// Package config scans common project configuration files for risky security settings.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/lonely-worm/preflight/internal/scanner/secret"
)

type rule struct {
	id, severity, message, remediation string
	filePattern *regexp.Regexp
	linePattern *regexp.Regexp
}

var rules = []rule{
	{"docker-user-root", "high", "Docker image explicitly selects root as its runtime user", "Create a dedicated non-root user and set USER to that account.", regexp.MustCompile(`(^|/)Dockerfile([^/]*)$`), regexp.MustCompile(`(?i)^\s*USER\s+(root|0)\s*$`)},
	{"docker-privileged", "critical", "Container is configured as privileged", "Remove privileged mode and grant only the specific capabilities the container needs.", regexp.MustCompile(`(?i)(docker-compose|compose).*\.ya?ml$`), regexp.MustCompile(`(?i)privileged\s*:\s*true\b`)},
	{"docker-host-network", "high", "Container uses host networking", "Prefer an isolated bridge network and publish only required ports.", regexp.MustCompile(`(?i)(docker-compose|compose).*\.ya?ml$`), regexp.MustCompile(`(?i)network_mode\s*:\s*["']?host\b`)},
	{"terraform-public-ingress", "high", "Terraform ingress rule allows traffic from all IPv4 addresses", "Restrict cidr_blocks to trusted ranges and required ports.", regexp.MustCompile(`\.tf$`), regexp.MustCompile(`(?i)0\.0\.0\.0/0`)},
	{"github-actions-write-permissions", "high", "GitHub Actions workflow grants write-all permissions", "Use least-privilege permissions at workflow or job level; grant write access only where required.", regexp.MustCompile(`\.github/workflows/.*\.ya?ml$`), regexp.MustCompile(`(?i)^\s*permissions\s*:\s*write-all\s*$`)},
	{"github-actions-unpinned", "medium", "GitHub Action reference is not pinned to a full commit SHA", "Pin third-party actions to a reviewed full-length commit SHA, or use a verified dependency lockfile.", regexp.MustCompile(`\.github/workflows/.*\.ya?ml$`), regexp.MustCompile(`(?i)^\s*uses\s*:\s*[^#\s]+@(v[0-9]+|main|master|latest)\s*(#.*)?$`)},
	{"kubernetes-privileged", "critical", "Kubernetes container is configured as privileged", "Set securityContext.privileged to false and use least-privilege capabilities.", regexp.MustCompile(`(?i)(deployment|pod|statefulset|daemonset).*\.ya?ml$`), regexp.MustCompile(`(?i)^\s*privileged\s*:\s*true\b`)},
	{"kubernetes-root-user", "high", "Kubernetes workload explicitly runs as root", "Set runAsNonRoot: true and configure a non-zero runAsUser where possible.", regexp.MustCompile(`(?i)(deployment|pod|statefulset|daemonset).*\.ya?ml$`), regexp.MustCompile(`(?i)^\s*runAsUser\s*:\s*0\s*$`)},
}

var ignoredDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".next": true}

func Scan(root string) ([]secret.Finding, error) {
	var findings []secret.Finding
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && ignoredDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		var matchingRules []rule
		for _, r := range rules {
			if r.filePattern.MatchString(rel) {
				matchingRules = append(matchingRules, r)
			}
		}
		if len(matchingRules) == 0 {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open configuration %s: %w", rel, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			for _, r := range matchingRules {
				if !r.linePattern.MatchString(line) {
					continue
				}
				message := r.message + " Remediation: " + r.remediation
				findings = append(findings, secret.Finding{
					RuleID: r.id, Severity: r.severity, Path: rel,
					Line: lineNo, Column: 1, Message: message,
				})
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read configuration %s: %w", rel, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return strings.Compare(findings[i].RuleID, findings[j].RuleID) < 0
	})
	return findings, nil
}
