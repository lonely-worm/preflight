package secret

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// RuleConfig can disable a rule or override its severity.
type RuleConfig struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Config is an optional JSON policy file. Unspecified rules keep built-in defaults.
type Config struct {
	Rules map[string]RuleConfig `json:"rules,omitempty"`
}

// Baseline stores fingerprints for findings explicitly accepted by a maintainer.
type Baseline struct {
	Version  int             `json:"version"`
	Findings []BaselineEntry `json:"findings"`
}

// BaselineEntry contains no matched credential value.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
}

// Fingerprint identifies a finding by rule, repository-relative path, line, and column.
func Fingerprint(f Finding) string {
	raw := fmt.Sprintf("%s\x00%s\x00%d\x00%d", f.RuleID, filepathSlash(f.Path), f.Line, f.Column)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func filepathSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

// LoadConfig reads and validates a JSON rule configuration.
func LoadConfig(path string) (Config, error) {
	var config Config
	if path == "" {
		return config, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	if err := decodeStrictJSON(data, &config); err != nil {
		return config, fmt.Errorf("parse config: %w", err)
	}
	validSeverity := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	knownRules := make(map[string]bool, len(rules))
	for _, r := range rules {
		knownRules[r.id] = true
	}
	for _, id := range []string{"aws-secret-access-key", "aws-session-token", "docker-user-root", "docker-privileged", "docker-host-network", "terraform-public-ingress", "github-actions-write-permissions", "github-actions-unpinned", "kubernetes-privileged", "kubernetes-root-user", "go-vulnerability"} { knownRules[id] = true }
	for id, ruleConfig := range config.Rules {
		if !knownRules[id] {
			return config, fmt.Errorf("unknown rule ID %q in config", id)
		}
		if ruleConfig.Severity != "" && !validSeverity[strings.ToLower(ruleConfig.Severity)] {
			return config, fmt.Errorf("invalid severity %q for rule %q", ruleConfig.Severity, id)
		}
	}
	return config, nil
}

// LoadBaseline reads a JSON baseline. An absent path means no baseline.
func LoadBaseline(path string) (Baseline, error) {
	var baseline Baseline
	if path == "" {
		return baseline, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return baseline, err
	}
	if err := decodeStrictJSON(data, &baseline); err != nil {
		return baseline, fmt.Errorf("parse baseline: %w", err)
	}
	if baseline.Version != 1 {
		return baseline, fmt.Errorf("unsupported baseline version %d", baseline.Version)
	}
	seen := make(map[string]bool)
	for _, entry := range baseline.Findings {
		if entry.Fingerprint == "" {
			return baseline, fmt.Errorf("baseline entry is missing fingerprint")
		}
		if seen[entry.Fingerprint] {
			return baseline, fmt.Errorf("duplicate baseline fingerprint %q", entry.Fingerprint)
		}
		seen[entry.Fingerprint] = true
	}
	return baseline, nil
}

// WriteBaseline writes a stable, sorted baseline without secret values.
func WriteBaseline(path string, findings []Finding) error {
	entries := make([]BaselineEntry, 0, len(findings))
	seen := make(map[string]bool)
	for _, finding := range findings {
		fp := Fingerprint(finding)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		entries = append(entries, BaselineEntry{Fingerprint: fp, RuleID: finding.RuleID, Path: finding.Path, Line: finding.Line})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Fingerprint < entries[j].Fingerprint })
	data, err := json.MarshalIndent(Baseline{Version: 1, Findings: entries}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}


// decodeStrictJSON rejects unknown fields and trailing JSON values so a typo in a security
// policy cannot silently fall back to a scanner default.
func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
