package secret

import (
	"encoding/json"
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


func TestScanDetectsAdditionalCredentialFormats(t *testing.T) {
	root := t.TempDir()
	fixtures := []struct {
		name  string
		value string
		rule  string
	}{
		{name: "github_pat", value: "github_pat_" + strings.Repeat("A", 35), rule: "github-fine-grained-token"},
		{name: "google_api_key", value: "AIza" + strings.Repeat("A", 35), rule: "google-api-key"},
		{name: "slack_token", value: "xoxb-" + strings.Repeat("A", 20), rule: "slack-token"},
		{name: "stripe_live_key", value: "sk_live_" + strings.Repeat("A", 24), rule: "stripe-live-secret-key"},
		{name: "npm_token", value: "npm_" + strings.Repeat("A", 36), rule: "npm-access-token"},
	}
	var content strings.Builder
	for _, fixture := range fixtures {
		content.WriteString(fixture.name)
		content.WriteString("=")
		content.WriteString(fixture.value)
		content.WriteString("\\n")
	}
	if err := os.WriteFile(filepath.Join(root, "credentials.env"), []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	foundRules := make(map[string]bool)
	for _, finding := range findings {
		foundRules[finding.RuleID] = true
		if finding.Redacted != "[REDACTED]" {
			t.Errorf("finding %q was not redacted: %#v", finding.RuleID, finding)
		}
	}
	for _, fixture := range fixtures {
		if !foundRules[fixture.rule] {
			t.Errorf("expected rule %q to detect fixture %q", fixture.rule, fixture.name)
		}
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		if strings.Contains(string(encoded), fixture.value) {
			t.Errorf("serialized findings leaked value for fixture %q", fixture.name)
		}
	}
}
