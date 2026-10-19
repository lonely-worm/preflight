// Package dependency integrates govulncheck for Go vulnerability analysis.
package dependency

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lonely-worm/preflight/internal/scanner/secret"
)

type sourcePosition struct {
	Filename string `json:"filename,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

type traceFrame struct {
	Module   string         `json:"module"`
	Version  string         `json:"version,omitempty"`
	Package  string         `json:"package,omitempty"`
	Function string         `json:"function,omitempty"`
	Receiver string         `json:"receiver,omitempty"`
	Position *sourcePosition `json:"position,omitempty"`
}

type findingEvent struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version,omitempty"`
	Trace        []traceFrame `json:"trace,omitempty"`
}

type osvEvent struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type event struct {
	OSV     *osvEvent     `json:"osv,omitempty"`
	Finding *findingEvent `json:"finding,omitempty"`
}

type vulnerabilityInfo struct {
	ID      string
	Summary string
}

// Scan invokes govulncheck's official Go vulnerability analysis. The tool must be installed.
// JSON mode is used so that vulnerabilities can be included in the report without making a
// vulnerability finding look like an execution failure.
func Scan(root string) ([]secret.Finding, error) {
	if _, err := filepath.Abs(root); err != nil {
		return nil, err
	}
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	findings, parseErr := parseJSON(&stdout)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("govulncheck failed: %w; JSON output: %v; stderr: %s", runErr, parseErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("decode govulncheck JSON: %w", parseErr)
	}
	// In JSON mode govulncheck returns success even when it reports vulnerabilities. A non-zero
	// process exit means the analysis did not finish successfully, so do not return partial
	// findings as if the scan were complete.
	if runErr != nil {
		return nil, fmt.Errorf("govulncheck failed: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return findings, nil
}

// parseJSON buffers the event stream before mapping findings. govulncheck explicitly does not
// guarantee event ordering, so an OSV description can arrive after its finding event.
func parseJSON(reader io.Reader) ([]secret.Finding, error) {
	decoder := json.NewDecoder(reader)
	vulnerabilities := make(map[string]vulnerabilityInfo)
	var vulnerabilityEvents []findingEvent

	for {
		var e event
		if err := decoder.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch {
		case e.OSV != nil:
			vulnerabilities[e.OSV.ID] = vulnerabilityInfo{ID: e.OSV.ID, Summary: e.OSV.Summary}
		case e.Finding != nil:
			vulnerabilityEvents = append(vulnerabilityEvents, *e.Finding)
		}
	}

	findings := make([]secret.Finding, 0, len(vulnerabilityEvents))
	seen := make(map[string]bool)
	for _, finding := range vulnerabilityEvents {
		if finding.OSV == "" {
			return nil, fmt.Errorf("govulncheck finding is missing its OSV ID")
		}
		info := vulnerabilities[finding.OSV]
		traces := finding.Trace
		if len(traces) == 0 {
			traces = []traceFrame{{}}
		}

		for _, trace := range traces {
			vulnerableSymbol := trace.Package
			if trace.Function != "" {
				if vulnerableSymbol != "" {
					vulnerableSymbol += "."
				}
				vulnerableSymbol += trace.Function
			}
			if trace.Receiver != "" {
				vulnerableSymbol = trace.Package + "." + trace.Receiver + "." + trace.Function
			}
			key := strings.Join([]string{
				finding.OSV, trace.Module, trace.Version, vulnerableSymbol,
				positionFilename(trace.Position), positionLine(trace.Position), positionColumn(trace.Position),
			}, "|")
			if seen[key] {
				continue
			}
			seen[key] = true

			message := finding.OSV
			if trace.Module != "" {
				message += fmt.Sprintf(" affects %s %s", trace.Module, trace.Version)
			}
			if info.Summary != "" {
				message += ": " + info.Summary
			}
			if finding.FixedVersion != "" {
				message += ". Remediation: upgrade to " + finding.FixedVersion + " or a later patched version, then rerun govulncheck."
			} else {
				message += ". Remediation: review the advisory and update to a supported patched release; govulncheck did not report a fixed version."
			}
			if vulnerableSymbol != "" {
				message += ". Vulnerable symbol: " + vulnerableSymbol
			}

			path, line, column := "go.mod", 1, 1
			// govulncheck traces run from the vulnerable symbol toward the entry point. The
			// final frame is the most useful source location for the developer to inspect.
			if len(finding.Trace) > 0 {
				entryPoint := finding.Trace[len(finding.Trace)-1]
				if entryPoint.Position != nil && entryPoint.Position.Filename != "" && entryPoint.Position.Line > 0 {
					path = filepath.ToSlash(filepath.Clean(entryPoint.Position.Filename))
					line = entryPoint.Position.Line
					if entryPoint.Position.Column > 0 {
						column = entryPoint.Position.Column
					}
				}
			}
			findings = append(findings, secret.Finding{
				RuleID: "go-vulnerability", Severity: "high", Path: path,
				Line: line, Column: column, Message: message,
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Message < findings[j].Message
	})
	return findings, nil
}

func positionFilename(position *sourcePosition) string {
	if position == nil { return "" }
	return position.Filename
}

func positionLine(position *sourcePosition) string {
	if position == nil { return "" }
	return fmt.Sprint(position.Line)
}

func positionColumn(position *sourcePosition) string {
	if position == nil { return "" }
	return fmt.Sprint(position.Column)
}
