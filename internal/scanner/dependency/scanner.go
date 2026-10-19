// Package dependency integrates govulncheck for Go vulnerability analysis.
package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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

type configEvent struct {
	ProtocolVersion string `json:"protocol_version"`
}

type event struct {
	Config   *configEvent  `json:"config,omitempty"`
	Progress *struct{}     `json:"progress,omitempty"`
	OSV      *osvEvent     `json:"osv,omitempty"`
	Finding  *findingEvent `json:"finding,omitempty"`
}

type vulnerabilityInfo struct {
	ID      string
	Summary string
}

const govulncheckTimeout = 10 * time.Minute

// Scan invokes govulncheck's official Go vulnerability analysis. The tool must be installed.
// JSON mode is used so that vulnerabilities can be included in the report without making a
// vulnerability finding look like an execution failure. A timeout prevents a stuck subprocess
// from holding a Preflight invocation open indefinitely.
func Scan(root string) ([]secret.Finding, error) {
	if _, err := filepath.Abs(root); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), govulncheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("govulncheck timed out after %s", govulncheckTimeout)
	}

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
	configSeen := false
	messageCount := 0

	for {
		var e event
		if err := decoder.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		messageCount++
		eventFields := 0
		if e.Config != nil { eventFields++ }
		if e.Progress != nil { eventFields++ }
		if e.OSV != nil { eventFields++ }
		if e.Finding != nil { eventFields++ }
		if eventFields != 1 {
			return nil, fmt.Errorf("govulncheck JSON event %d must contain exactly one event type", messageCount)
		}
		if messageCount == 1 && e.Config == nil {
			return nil, fmt.Errorf("govulncheck config event must be first")
		}
		if e.Config != nil && messageCount != 1 {
			return nil, fmt.Errorf("govulncheck config event must be first")
		}
		switch {
		case e.Config != nil:
			if configSeen {
				return nil, fmt.Errorf("govulncheck JSON stream contains multiple config events")
			}
			if e.Config.ProtocolVersion != "v1.0.0" {
				return nil, fmt.Errorf("unsupported govulncheck JSON protocol version %q (expected v1.0.0)", e.Config.ProtocolVersion)
			}
			configSeen = true
		case e.OSV != nil:
			if e.OSV.ID == "" {
				return nil, fmt.Errorf("govulncheck OSV event is missing its ID")
			}
			vulnerabilities[e.OSV.ID] = vulnerabilityInfo{ID: e.OSV.ID, Summary: e.OSV.Summary}
		case e.Finding != nil:
			vulnerabilityEvents = append(vulnerabilityEvents, *e.Finding)
		}
	}

	if messageCount == 0 || !configSeen {
		return nil, fmt.Errorf("govulncheck JSON stream is empty or missing its config event")
	}

	findings := make([]secret.Finding, 0, len(vulnerabilityEvents))
	seen := make(map[string]bool)
	for _, finding := range vulnerabilityEvents {
		if finding.OSV == "" {
			return nil, fmt.Errorf("govulncheck finding is missing its OSV ID")
		}
		info, foundOSV := vulnerabilities[finding.OSV]
		if !foundOSV {
			return nil, fmt.Errorf("govulncheck finding references unknown OSV ID %q", finding.OSV)
		}

		var vulnerableSymbolFrame traceFrame
		var entryPoint traceFrame
		if len(finding.Trace) > 0 {
			vulnerableSymbolFrame = finding.Trace[0]
			entryPoint = finding.Trace[len(finding.Trace)-1]
		}
		vulnerableSymbol := vulnerableSymbolFrame.Package
		if vulnerableSymbolFrame.Function != "" {
			if vulnerableSymbol != "" {
				vulnerableSymbol += "."
			}
			vulnerableSymbol += vulnerableSymbolFrame.Function
		}
		if vulnerableSymbolFrame.Receiver != "" {
			vulnerableSymbol = vulnerableSymbolFrame.Package + "." + vulnerableSymbolFrame.Receiver + "." + vulnerableSymbolFrame.Function
		}

		key := strings.Join([]string{
			finding.OSV, vulnerableSymbolFrame.Module, vulnerableSymbolFrame.Version, vulnerableSymbol,
			positionFilename(entryPoint.Position), positionLine(entryPoint.Position), positionColumn(entryPoint.Position),
		}, "|")
		if seen[key] {
			continue
		}
		seen[key] = true

		message := finding.OSV
		if vulnerableSymbolFrame.Module != "" {
			message += fmt.Sprintf(" affects %s %s", vulnerableSymbolFrame.Module, vulnerableSymbolFrame.Version)
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
		if entryPoint.Position != nil && entryPoint.Position.Filename != "" && entryPoint.Position.Line > 0 {
			path = filepath.ToSlash(filepath.Clean(entryPoint.Position.Filename))
			line = entryPoint.Position.Line
			if entryPoint.Position.Column > 0 {
				column = entryPoint.Position.Column
			}
		}
		findings = append(findings, secret.Finding{
			RuleID: "go-vulnerability", Severity: "high", Path: path,
			Line: line, Column: column, Message: message,
		})
	}
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
