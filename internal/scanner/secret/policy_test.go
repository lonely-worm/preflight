package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleConfigCanDisableAndOverrideSeverity(t *testing.T) {
	root := t.TempDir()
	token := "ghp_" + strings.Repeat("a", 50)
	if err := os.WriteFile(filepath.Join(root, "sample.env"), []byte("GITHUB_TOKEN="+token+"\npassword=super-secret-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	disabled := false
	report, err := ScanWithReport(root, Options{RuleConfig: Config{Rules: map[string]RuleConfig{
		"github-token": {Enabled: &disabled},
		"generic-secret-assignment": {Severity: "low"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected only generic assignment finding, got %#v", report.Findings)
	}
	if report.Findings[0].RuleID != "generic-secret-assignment" || report.Findings[0].Severity != "low" {
		t.Fatalf("rule override not applied: %#v", report.Findings[0])
	}
}

func TestBaselineSuppressesOnlyMatchingFinding(t *testing.T) {
	root := t.TempDir()
	token := "ghp_" + strings.Repeat("a", 50)
	if err := os.WriteFile(filepath.Join(root, "sample.env"), []byte("GITHUB_TOKEN="+token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := ScanWithReport(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) == 0 {
		t.Fatal("expected initial finding")
	}
	baselinePath := filepath.Join(root, "baseline.json")
	if err := WriteBaseline(baselinePath, first.Findings); err != nil {
		t.Fatal(err)
	}
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ScanWithReport(root, Options{Baseline: baseline})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Findings) != 0 || second.SuppressedFindings != len(first.Findings) {
		t.Fatalf("expected baseline suppression, got findings=%d suppressed=%d", len(second.Findings), second.SuppressedFindings)
	}
	if strings.Contains(string(mustRead(t, baselinePath)), token) {
		t.Fatal("baseline must not store credential values")
	}
}

func TestLoadConfigRejectsUnknownRuleAndSeverity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"rules":{"not-a-rule":{"severity":"critical"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected unknown rule to be rejected")
	}
	if err := os.WriteFile(path, []byte(`{"rules":{"github-token":{"severity":"urgent"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected invalid severity to be rejected")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"rules":{"github-token":{"enabeld":false}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected a misspelled rule option to be rejected")
	}

	if err := os.WriteFile(path, []byte(`{"rules":{},"overrides":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected an unknown top-level field to be rejected")
	}
}
