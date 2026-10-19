// Package dependency integrates govulncheck for Go vulnerability analysis.
package dependency

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lonely-worm/preflight/internal/scanner/secret"
)

type event struct {
	Config *struct {
		GoVersion string `json:"go_version"`
		ScanLevel string `json:"scan_level"`
	} `json:"config,omitempty"`
	OSV *struct {
		ID string `json:"id"`
		Summary string `json:"summary"`
		Details string `json:"details"`
		Aliases []string `json:"aliases"`
	} `json:"osv,omitempty"`
	Finding *struct {
		OSV string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace []struct {
			Module string `json:"module"`
			Version string `json:"version"`
			Package string `json:"package"`
			Function string `json:"function"`
		} `json:"trace"`
	} `json:"finding,omitempty"`
}

// Scan invokes govulncheck's official Go vulnerability analysis. The tool must be installed.
// It uses the Go vulnerability database and returns actionable upgrade guidance.
func Scan(root string) ([]secret.Finding, error) {
	if _, err := filepath.Abs(root); err != nil { return nil, err }
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil { return nil, fmt.Errorf("govulncheck failed: %w: %s", runErr, strings.TrimSpace(stderr.String())) }
		return []secret.Finding{}, nil
	}
	var findings []secret.Finding
	decoder := json.NewDecoder(bufio.NewReader(&stdout))
	seen := map[string]bool{}
	var currentOSV = map[string]struct{ ID, Summary string }{}
	for decoder.More() {
		var e event
		if err := decoder.Decode(&e); err != nil { return nil, fmt.Errorf("decode govulncheck JSON: %w", err) }
		if e.OSV != nil {
			currentOSV[e.OSV.ID] = struct{ ID, Summary string }{e.OSV.ID, e.OSV.Summary}
		}
		if e.Finding == nil { continue }
		id := e.Finding.OSV
		info := currentOSV[id]
		for _, trace := range e.Finding.Trace {
			key := id + "|" + trace.Module + "|" + trace.Package + "|" + trace.Function
			if seen[key] { continue }
			seen[key] = true
			severity := "high"
			message := fmt.Sprintf("%s affects %s %s", id, trace.Module, trace.Version)
			if info.Summary != "" { message += ": " + info.Summary }
			if e.Finding.FixedVersion != "" {
				message += ". Remediation: upgrade to " + e.Finding.FixedVersion + " or a later patched version, then rerun govulncheck."
			} else {
				message += ". Remediation: review the advisory and update to a supported patched release; no fixed version was reported by govulncheck."
			}
			message += fmt.Sprintf(" Reachable symbol: %s.%s", trace.Package, trace.Function)
			findings = append(findings, secret.Finding{RuleID: "go-vulnerability-" + strings.ToLower(strings.ReplaceAll(id, "/", "-")), Severity: severity, Path: "go.mod", Line: 1, Column: 1, Message: message})
		}
	}
	if runErr != nil && len(findings) == 0 {
		return nil, fmt.Errorf("govulncheck failed: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	sort.Slice(findings, func(i,j int) bool {
		if findings[i].RuleID != findings[j].RuleID { return findings[i].RuleID < findings[j].RuleID }
		return findings[i].Message < findings[j].Message
	})
	return findings, nil
}
