package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lonely-worm/preflight/internal/scanner/secret"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	format := flags.String("format", "text", "output format: text, json, or sarif")
	includeHidden := flags.Bool("include-hidden", false, "include hidden files and directories")
	maxFileSize := flags.Int64("max-file-size", 2<<20, "maximum file size to scan in bytes")
	var excluded stringList
	flags.Var(&excluded, "exclude-dir", "directory name to exclude (repeatable)")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: preflight [options] [directory]")
		fmt.Fprintln(flags.Output(), "Scan a local directory for likely hard-coded secrets.")
		fmt.Fprintln(flags.Output(), "Options:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *format != "text" && *format != "json" && *format != "sarif" {
		fmt.Fprintln(os.Stderr, "preflight: -format must be text, json, or sarif")
		return 2
	}
	if *maxFileSize < 1 {
		fmt.Fprintln(os.Stderr, "preflight: -max-file-size must be greater than zero")
		return 2
	}
	root := "."
	if flags.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "preflight: expected at most one directory")
		flags.Usage()
		return 2
	}
	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}

	findings, err := secret.Scan(root, secret.Options{
		MaxFileSize:   *maxFileSize,
		IncludeHidden: *includeHidden,
		ExcludeDirs:   excluded,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "preflight: scan failed: %v\n", err)
		return 2
	}

	if *format == "sarif" {
		if err := writeSARIF(os.Stdout, findings); err != nil {
			fmt.Fprintf(os.Stderr, "preflight: encode SARIF: %v\\n", err)
			return 2
		}
	} else if *format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "preflight: encode output: %v\n", err)
			return 2
		}
	} else if len(findings) == 0 {
		fmt.Fprintln(os.Stdout, "Preflight: no matching secret patterns found.")
	} else {
		for _, finding := range findings {
			fmt.Printf("%s %s:%d:%d [%s] %s\n",
				strings.ToUpper(finding.Severity),
				finding.Path, finding.Line, finding.Column,
				finding.RuleID, finding.Message)
		}
		fmt.Fprintf(os.Stdout, "\n%d potential finding(s). Review results; this scanner may produce false positives or miss secrets.\n", len(findings))
	}

	if len(findings) > 0 {
		return 1
	}
	return 0
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string        `json:"ruleId"`
	Level     string        `json:"level"`
	Message   sarifMessage  `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func writeSARIF(w io.Writer, findings []secret.Finding) error {
	rulesByID := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		if _, ok := rulesByID[finding.RuleID]; !ok {
			rulesByID[finding.RuleID] = sarifRule{
				ID: finding.RuleID,
				ShortDescription: sarifMessage{Text: finding.Message},
			}
		}
		level := "warning"
		switch strings.ToLower(finding.Severity) {
		case "critical", "high":
			level = "error"
		case "low", "info", "informational":
			level = "note"
		}
		results = append(results, sarifResult{
			RuleID: finding.RuleID,
			Level: level,
			Message: sarifMessage{Text: finding.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: finding.Path},
					Region: sarifRegion{StartLine: finding.Line, StartColumn: finding.Column},
				},
			}},
		})
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, finding := range findings {
		if r, ok := rulesByID[finding.RuleID]; ok {
			rules = append(rules, r)
			delete(rulesByID, finding.RuleID)
		}
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Preflight",
				InformationURI: "https://github.com/lonely-worm/preflight",
				Rules: rules,
			}},
			Results: results,
		}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}
