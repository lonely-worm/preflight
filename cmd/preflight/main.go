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
	format := flags.String("format", "text", "output format: text or json")
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
	if *format != "text" && *format != "json" {
		fmt.Fprintln(os.Stderr, "preflight: -format must be text or json")
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

	if *format == "json" {
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
