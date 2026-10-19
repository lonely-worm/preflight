package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/lonely-worm/preflight/internal/scanner/secret"
	configscanner "github.com/lonely-worm/preflight/internal/scanner/config"
	depscanner "github.com/lonely-worm/preflight/internal/scanner/dependency"
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
	configPath := flags.String("config", "", "JSON rule configuration file")
	baselinePath := flags.String("baseline", "", "JSON baseline file for known findings")
	writeBaseline := flags.String("write-baseline", "", "write current findings to a baseline file and exit")
	checkDependencies := flags.Bool("deps", false, "run govulncheck for Go dependency vulnerabilities (requires govulncheck installed)")
	checkConfig := flags.Bool("config-scan", true, "scan common configuration files for risky security settings")
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

	config, err := secret.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preflight: config: %v\\n", err)
		return 2
	}
	baseline, err := secret.LoadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preflight: baseline: %v\\n", err)
		return 2
	}
	report, err := secret.ScanWithReport(root, secret.Options{
		MaxFileSize:   *maxFileSize,
		IncludeHidden: *includeHidden,
		ExcludeDirs:   excluded,
		RuleConfig: config,
		Baseline: baseline,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "preflight: scan failed: %v\n", err)
		return 2
	}
	if *checkConfig {
		configFindings, scanErr := configscanner.Scan(root)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "preflight: configuration scan incomplete: %v\\n", scanErr)
			report.Complete = false
			report.SkippedPaths = append(report.SkippedPaths, secret.ScanIssue{Path: root, Reason: "configuration_scan_error", Detail: scanErr.Error()})
		} else {
			report.Findings = append(report.Findings, applyPolicy(configFindings, config, baseline, &report.SuppressedFindings)...)
		}
	}
	if *checkDependencies {
		dependencyFindings, scanErr := depscanner.Scan(root)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "preflight: dependency scan incomplete: %v\\n", scanErr)
			report.Complete = false
			report.SkippedPaths = append(report.SkippedPaths, secret.ScanIssue{Path: "go.mod", Reason: "dependency_scan_error", Detail: scanErr.Error()})
		} else {
			report.Findings = append(report.Findings, applyPolicy(dependencyFindings, config, baseline, &report.SuppressedFindings)...)
		}
	}
	if *writeBaseline != "" {
		if err := secret.WriteBaseline(*writeBaseline, report.Findings); err != nil {
			fmt.Fprintf(os.Stderr, "preflight: write baseline: %v\\n", err)
			return 2
		}
		fmt.Fprintf(os.Stdout, "Wrote %d baseline entries to %s\\n", len(report.Findings), *writeBaseline)
		return 0
	}
	if report.Findings == nil {
		report.Findings = []secret.Finding{}
	}
	if report.SkippedPaths == nil {
		report.SkippedPaths = []secret.ScanIssue{}
	}

	switch *format {
	case "sarif":
		if err := writeSARIF(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "preflight: encode SARIF: %v\n", err)
			return 2
		}
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "preflight: encode output: %v\n", err)
			return 2
		}
	default:
		printTextReport(os.Stdout, report)
	}

	if !report.Complete {
		return 2
	}
	if len(report.Findings) > 0 {
		return 1
	}
	return 0
}

func printTextReport(w io.Writer, report secret.Report) {
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "%s %s:%d:%d [%s] %s\n",
			strings.ToUpper(finding.Severity), finding.Path, finding.Line, finding.Column,
			finding.RuleID, finding.Message)
	}
	status := "COMPLETE"
	if !report.Complete {
		status = "INCOMPLETE"
	}
	fmt.Fprintf(w, "\nScan status: %s | scanned files: %d | skipped paths: %d | findings: %d\n",
		status, report.ScannedFiles, len(report.SkippedPaths), len(report.Findings))
	for _, issue := range report.SkippedPaths {
		if issue.Detail == "" {
			fmt.Fprintf(w, "SKIPPED %s [%s]\n", issue.Path, issue.Reason)
		} else {
			fmt.Fprintf(w, "SKIPPED %s [%s]: %s\n", issue.Path, issue.Reason, issue.Detail)
		}
	}
	if !report.Complete {
		fmt.Fprintln(w, "WARNING: results are partial; do not treat this scan as clean.")
	} else if len(report.Findings) == 0 {
		fmt.Fprintln(w, "Preflight: no matching secret patterns found.")
	} else {
		fmt.Fprintln(w, "Review potential findings; this scanner may produce false positives or miss secrets.")
	}
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool               `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
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
	ID                    string                    `json:"id"`
	ShortDescription      sarifMessage              `json:"shortDescription"`
	FullDescription       *sarifMessage             `json:"fullDescription,omitempty"`
	HelpURI               string                    `json:"helpUri,omitempty"`
	DefaultConfiguration  sarifDefaultConfiguration `json:"defaultConfiguration"`
	Properties            sarifRuleProperties       `json:"properties,omitempty"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
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

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "low", "info", "informational":
		return "note"
	default:
		return "warning"
	}
}

func sarifRuleForFinding(finding secret.Finding) sarifRule {
	shortDescription := finding.Message
	var fullDescription *sarifMessage
	if short, remediation, ok := strings.Cut(finding.Message, " Remediation: "); ok {
		shortDescription = short
		fullDescription = &sarifMessage{Text: "Recommended action: " + remediation}
	}
	return sarifRule{
		ID: finding.RuleID,
		ShortDescription: sarifMessage{Text: shortDescription},
		FullDescription: fullDescription,
		HelpURI: "https://github.com/lonely-worm/preflight#detection-coverage",
		DefaultConfiguration: sarifDefaultConfiguration{Level: sarifLevel(finding.Severity)},
		Properties: sarifRuleProperties{Tags: []string{"security", "preflight"}},
	}
}

func writeSARIF(w io.Writer, report secret.Report) error {
	rulesByID := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if _, ok := rulesByID[finding.RuleID]; !ok {
			rulesByID[finding.RuleID] = sarifRuleForFinding(finding)
		}
		level := sarifLevel(finding.Severity)
		artifactURI := (&url.URL{Path: finding.Path}).EscapedPath()
		results = append(results, sarifResult{
			RuleID: finding.RuleID, Level: level, Message: sarifMessage{Text: finding.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
				Region: sarifRegion{StartLine: finding.Line, StartColumn: finding.Column},
			}}},
		})
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, finding := range report.Findings {
		if r, ok := rulesByID[finding.RuleID]; ok {
			rules = append(rules, r)
			delete(rulesByID, finding.RuleID)
		}
	}
	invocation := sarifInvocation{ExecutionSuccessful: report.Complete}
	for _, issue := range report.SkippedPaths {
		level := "note"
		switch issue.Reason {
		case "walk_error", "stat_error", "file_too_large", "binary_file", "read_error":
			level = "warning"
		}
		message := fmt.Sprintf("Skipped path %q (%s)", issue.Path, issue.Reason)
		if issue.Detail != "" {
			message += ": " + issue.Detail
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level: level, Message: sarifMessage{Text: message},
		})
	}
	if !report.Complete && len(invocation.ToolExecutionNotifications) == 0 {
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level: "warning",
			Message: sarifMessage{Text: fmt.Sprintf(
				"Scan incomplete: inspected %d files and skipped %d paths. Review scan diagnostics; an empty result is not a clean bill of health.",
				report.ScannedFiles, len(report.SkippedPaths))},
		})
	}
	log := sarifLog{
		Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{
			Name: "Preflight", InformationURI: "https://github.com/lonely-worm/preflight", Rules: rules,
		}}, Results: results, Invocations: []sarifInvocation{invocation}}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}


func applyPolicy(findings []secret.Finding, config secret.Config, baseline secret.Baseline, suppressed *int) []secret.Finding {
	baselineSet := make(map[string]bool, len(baseline.Findings))
	for _, entry := range baseline.Findings { baselineSet[entry.Fingerprint] = true }
	out := make([]secret.Finding, 0, len(findings))
	for _, finding := range findings {
		if cfg, ok := config.Rules[finding.RuleID]; ok {
			if cfg.Enabled != nil && !*cfg.Enabled { continue }
			if cfg.Severity != "" { finding.Severity = strings.ToLower(cfg.Severity) }
		}
		if baselineSet[secret.Fingerprint(finding)] { *suppressed++; continue }
		out = append(out, finding)
	}
	return out
}
