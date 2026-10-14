package main

import (
	"bytes"
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

func TestRunReportsFindingWithoutLeakingSecret(t *testing.T) {
	root := t.TempDir()
	secretValue := "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
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
	secretValue := "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
	if err := os.WriteFile(filepath.Join(root, "sample.env"), []byte("GITHUB_TOKEN="+secretValue+"\\n"), 0600); err != nil {
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
