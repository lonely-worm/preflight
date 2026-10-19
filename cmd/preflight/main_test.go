package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	code := fn()
	_ = writer.Close()
	os.Stdout = old
	var output bytes.Buffer
	_, _ = io.Copy(&output, reader)
	_ = reader.Close()
	return code, output.String()
}

func TestRunCleanDirectory(t *testing.T) {
	root := t.TempDir()
	code, output := captureStdout(t, func() int { return run([]string{root}) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; output: %s", code, output)
	}
	if !strings.Contains(output, "no matching secret patterns") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunJSONCleanDirectoryReturnsReport(t *testing.T) {
	root := t.TempDir()
	code, output := captureStdout(t, func() int { return run([]string{"-format", "json", root}) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; output: %s", code, output)
	}
	var report struct {
		Findings []map[string]any `json:"findings"`
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid JSON scan report, got %q: %v", output, err)
	}
	if report.Findings == nil || len(report.Findings) != 0 {
		t.Fatalf("expected an empty findings array, got %#v", report.Findings)
	}
	if !report.Complete {
		t.Fatal("expected complete scan report")
	}
}

func TestRunReportsFindingWithoutLeakingSecret(t *testing.T) {
	root := t.TempDir()
	secretValue := "ghp_" + strings.Repeat("a", 50)
	if err := os.WriteFile(filepath.Join(root, "sample.env"), []byte("GITHUB_TOKEN="+secretValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, output := captureStdout(t, func() int { return run([]string{"-format", "json", root}) })
	if code != 1 {
		t.Fatalf("expected exit 1 when findings exist, got %d; output: %s", code, output)
	}
	if !strings.Contains(output, "github-token") {
		t.Fatalf("expected rule ID in JSON output: %s", output)
	}
	if strings.Contains(output, secretValue) {
		t.Fatal("CLI output leaked the matched secret")
	}
}

func TestRunRejectsUnsupportedFormat(t *testing.T) {
	code, _ := captureStdout(t, func() int { return run([]string{"-format", "xml"}) })
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid format, got %d", code)
	}
}

func TestRunWritesSARIFWithoutLeakingSecret(t *testing.T) {
	root := t.TempDir()
	secretValue := "ghp_" + strings.Repeat("a", 50)
	if err := os.WriteFile(filepath.Join(root, "sample.env"), []byte("GITHUB_TOKEN="+secretValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte("FROM alpine:latest\nUSER root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, output := captureStdout(t, func() int { return run([]string{"-format", "sarif", root}) })
	if code != 1 {
		t.Fatalf("expected exit 1 when findings exist, got %d; output: %s", code, output)
	}
	if !strings.Contains(output, "\"version\": \"2.1.0\"") {
		t.Fatalf("expected SARIF 2.1.0 output: %s", output)
	}
	if !strings.Contains(output, "\"ruleId\": \"github-token\"") {
		t.Fatalf("expected github-token rule in SARIF: %s", output)
	}
	if strings.Contains(output, secretValue) {
		t.Fatal("SARIF output leaked the matched secret")
	}

	var document struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
						ShortDescription struct { Text string `json:"text"` } `json:"shortDescription"`
						FullDescription struct { Text string `json:"text"` } `json:"fullDescription"`
						DefaultConfiguration struct { Level string `json:"level"` } `json:"defaultConfiguration"`
						Properties struct { Tags []string `json:"tags"` } `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(output), &document); err != nil {
		t.Fatalf("expected parseable SARIF metadata: %v", err)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("expected one SARIF run, got %d", len(document.Runs))
	}
	var foundConfigRule bool
	for _, rule := range document.Runs[0].Tool.Driver.Rules {
		if rule.ID != "docker-user-root" { continue }
		foundConfigRule = true
		if strings.Contains(rule.ShortDescription.Text, "Remediation:") {
			t.Fatalf("short description should not contain remediation text: %q", rule.ShortDescription.Text)
		}
		if !strings.Contains(rule.FullDescription.Text, "non-root user") {
			t.Fatalf("expected actionable full description, got %q", rule.FullDescription.Text)
		}
		if rule.DefaultConfiguration.Level != "error" {
			t.Fatalf("expected high severity to map to SARIF error, got %q", rule.DefaultConfiguration.Level)
		}
		if !containsString(rule.Properties.Tags, "security") {
			t.Fatalf("expected security tag in SARIF metadata, got %#v", rule.Properties.Tags)
		}
	}
	if !foundConfigRule {
		t.Fatal("expected docker-user-root rule metadata in SARIF output")
	}
}

func TestSARIFEscapesArtifactPathAsURI(t *testing.T) {
	root := t.TempDir()
	secretValue := "ghp_" + strings.Repeat("a", 50)
	fileName := "secret file.env"
	if err := os.WriteFile(filepath.Join(root, fileName), []byte("GITHUB_TOKEN="+secretValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, output := captureStdout(t, func() int { return run([]string{"-format", "sarif", root}) })
	if code != 1 {
		t.Fatalf("expected exit 1 when findings exist, got %d; output: %s", code, output)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid SARIF JSON: %v", err)
	}
	runs, ok := report["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one SARIF run, got %#v", report["runs"])
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected SARIF run shape: %#v", runs[0])
	}
	results, ok := run["results"].([]any)
	if !ok || len(results) == 0 {
		t.Fatalf("expected SARIF results, got %#v", run["results"])
	}
	result, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected SARIF result shape: %#v", results[0])
	}
	locations, ok := result["locations"].([]any)
	if !ok || len(locations) == 0 {
		t.Fatalf("expected SARIF locations, got %#v", result["locations"])
	}
	location, ok := locations[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected SARIF location shape: %#v", locations[0])
	}
	physical, ok := location["physicalLocation"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected physical location shape: %#v", location["physicalLocation"])
	}
	artifact, ok := physical["artifactLocation"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected artifact location shape: %#v", physical["artifactLocation"])
	}
	if artifact["uri"] != "secret%20file.env" {
		t.Fatalf("expected URI-escaped artifact path, got %#v", artifact["uri"])
	}
}


func TestRunReportsOversizedFileAsIncompleteInJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte(strings.Repeat("x", 128)), 0600); err != nil {
		t.Fatal(err)
	}
	code, output := captureStdout(t, func() int {
		return run([]string{"-format", "json", "-max-file-size", "64", root})
	})
	if code != 2 {
		t.Fatalf("expected exit 2 for incomplete scan, got %d; output: %s", code, output)
	}
	var report struct {
		Complete bool `json:"complete"`
		SkippedPaths []struct {
			Reason string `json:"reason"`
		} `json:"skipped_paths"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid JSON scan report: %v", err)
	}
	if report.Complete {
		t.Fatal("incomplete scan must not be marked complete")
	}
	if len(report.SkippedPaths) != 1 || report.SkippedPaths[0].Reason != "file_too_large" {
		t.Fatalf("expected oversized-file diagnostic, got %#v", report.SkippedPaths)
	}
}

func TestRunMarksIncompleteSARIFExecution(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte(strings.Repeat("x", 128)), 0600); err != nil {
		t.Fatal(err)
	}
	code, output := captureStdout(t, func() int {
		return run([]string{"-format", "sarif", "-max-file-size", "64", root})
	})
	if code != 2 {
		t.Fatalf("expected exit 2 for incomplete scan, got %d; output: %s", code, output)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("expected valid SARIF JSON: %v", err)
	}
	runs, ok := report["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one SARIF run, got %#v", report["runs"])
	}
	runObject := runs[0].(map[string]any)
	invocations, ok := runObject["invocations"].([]any)
	if !ok || len(invocations) != 1 {
		t.Fatalf("expected one SARIF invocation, got %#v", runObject["invocations"])
	}
	invocation := invocations[0].(map[string]any)
	if invocation["executionSuccessful"] != false {
		t.Fatalf("expected unsuccessful SARIF invocation, got %#v", invocation["executionSuccessful"])
	}
	notifications, ok := invocation["toolExecutionNotifications"].([]any)
	if !ok || len(notifications) == 0 {
		t.Fatal("expected warning notification for incomplete scan")
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target { return true }
	}
	return false
}
