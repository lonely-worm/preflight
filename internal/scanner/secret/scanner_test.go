package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFindsLikelySecretsWithoutLeakingValues(t *testing.T) {
	root := t.TempDir()
	secret := "ghp_" + strings.Repeat("a", 50)
	awsKey := "AKIA" + strings.Repeat("A", 16)
	content := "GITHUB_TOKEN=" + secret + "\nAWS_ACCESS_KEY_ID=" + awsKey + "\n"
	if err := os.WriteFile(filepath.Join(root, "config.env"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Redacted != "[REDACTED]" {
			t.Fatalf("match was not redacted: %#v", f)
		}
		if strings.Contains(f.Message, secret) {
			t.Fatal("finding leaked secret in message")
		}
	}
}

func TestScanSupportsConfiguredFileSizeForLongLines(t *testing.T) {
	root := t.TempDir()
	secret := "ghp_" + strings.Repeat("a", 50)
	content := strings.Repeat("x", (2<<20)+1) + " " + secret + "\n"
	if err := os.WriteFile(filepath.Join(root, "large-line.txt"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(root, Options{MaxFileSize: 3 << 20})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range findings {
		if finding.RuleID == "github-token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected token on a line larger than the default scanner buffer to be detected")
	}
}

func TestScanSkipsGitAndNodeModules(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{".git", "node_modules"} {
		p := filepath.Join(root, dir)
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "secret.txt"), []byte("TOKEN=abcdefghijklmnopqrstuvwxyz1234567890"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected ignored directories, got %d findings", len(findings))
	}
}

func TestScanRejectsFileRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(root, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(root, Options{}); err == nil {
		t.Fatal("expected error for non-directory root")
	}
}
