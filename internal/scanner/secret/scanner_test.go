package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFindsLikelySecretsWithoutLeakingValues(t *testing.T) {
	root := t.TempDir()
	secret := "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
	content := "GITHUB_TOKEN=" + secret + "\nAWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
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
