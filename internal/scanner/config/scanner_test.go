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


func TestScanFlagsMutableVersionTagsButAcceptsFullSHA(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "deploy.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	body := "jobs:\n  deploy:\n    steps:\n      - uses: actions/checkout@v4.1.2\n      - uses: actions/setup-go@0123456789abcdef0123456789abcdef01234567\n      - uses: ./.github/actions/local-action\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range findings {
		if finding.RuleID == "github-actions-unpinned" {
			count++
			if finding.Line != 4 {
				t.Errorf("expected mutable tag on line 4, got line %d", finding.Line)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one unpinned action finding, got %#v", findings)
	}
}

func TestScanDoesNotFlagCommentedTerraformIngress(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "infra", "main.tf")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# cidr_blocks = [\"0.0.0.0/0\"]\n// cidr_blocks = [\"0.0.0.0/0\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected comments not to trigger a finding, got %#v", findings)
	}
}

func TestScanWithReportHonorsExclusionsAndSizeLimit(t *testing.T) {
	root := t.TempDir()
	dockerPath := filepath.Join(root, "Dockerfile")
	if err := os.WriteFile(dockerPath, []byte("FROM alpine\nUSER root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	excludedPath := filepath.Join(root, "infra", "main.tf")
	if err := os.MkdirAll(filepath.Dir(excludedPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excludedPath, []byte("cidr_blocks = [\"0.0.0.0/0\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	largePath := filepath.Join(root, "docker-compose.yml")
	if err := os.WriteFile(largePath, []byte("services:\n  app:\n    privileged: true\n# "+strings.Repeat("x", 80)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanWithReport(root, Options{MaxFileSize: 64, ExcludeDirs: []string{"infra"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Complete {
		t.Fatal("expected oversized configuration file to mark scan incomplete")
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "docker-user-root" {
		t.Fatalf("expected Docker root finding only; got %#v", report.Findings)
	}
	if len(report.SkippedPaths) != 1 || report.SkippedPaths[0].Path != "docker-compose.yml" || report.SkippedPaths[0].Reason != "config_file_too_large" {
		t.Fatalf("expected one size-limit diagnostic, got %#v", report.SkippedPaths)
	}
}
