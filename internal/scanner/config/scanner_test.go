package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanReportsActionableRiskyConfigurations(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"Dockerfile": "FROM alpine:latest\nUSER root\n",
		"docker-compose.yml": "services:\n  app:\n    privileged: true\n    network_mode: host\n",
		".github/workflows/deploy.yml": "name: deploy\npermissions: write-all\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
		"infra/main.tf": "resource \"aws_security_group_rule\" \"public\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n",
	}
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { t.Fatal(err) }
		if err := os.WriteFile(path, []byte(body), 0600); err != nil { t.Fatal(err) }
	}
	findings, err := Scan(root)
	if err != nil { t.Fatal(err) }
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.RuleID] = true
		if !strings.Contains(finding.Message, "Remediation:") { t.Errorf("finding lacks remediation: %#v", finding) }
	}
	for _, id := range []string{"docker-user-root", "docker-privileged", "docker-host-network", "github-actions-write-permissions", "github-actions-unpinned", "terraform-public-ingress"} {
		if !found[id] { t.Errorf("expected %s finding; got %#v", id, findings) }
	}
}

func TestScanDoesNotFlagSafeWorkflowPermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"), 0600); err != nil { t.Fatal(err) }
	findings, err := Scan(root)
	if err != nil { t.Fatal(err) }
	if len(findings) != 0 { t.Fatalf("expected no findings for safe workflow, got %#v", findings) }
}
