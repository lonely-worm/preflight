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

func TestRunJSONCleanDirectoryReturnsEmptyArray(t *testing.T) {
	root := t.TempDir()
	code, output := captureStdout(t, func() int { return run([]string{"-format", "json", root}) })
	if code != 0 {
		t.Fatalf("expected exit 0, got %d; output: %s", code, output)
	}

	var findings []map[string]any
	if err := json.Unmarshal([]byte(output), &findings); err != nil {
		t.Fatalf("expected valid JSON array, got %q: %v", output, err)
	}
	if findings == nil {
		t.Fatal("expected an empty array, got null")
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
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
