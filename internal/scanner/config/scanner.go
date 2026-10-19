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

// Options controls which configuration files are inspected.
type Options struct {
	// MaxFileSize is the maximum number of bytes read from one configuration file.
	// Values <= 0 use the secret scanner's 2 MiB default.
	MaxFileSize int64
	// ExcludeDirs contains directory names to omit from configuration scanning.
	ExcludeDirs []string
}

// Report describes configuration findings and files that were not fully inspected.
type Report struct {
	Findings     []secret.Finding
	ScannedFiles int
	SkippedPaths []secret.ScanIssue
	Complete     bool
}

type rule struct {
	id, severity, message, remediation string
	filePattern                       *regexp.Regexp
	linePattern                       *regexp.Regexp
}

var rules = []rule{
	{"docker-user-root", "high", "Docker image explicitly selects root as its runtime user", "Create a dedicated non-root user and set USER to that account.", regexp.MustCompile(`(^|/)Dockerfile([^/]*)$`), regexp.MustCompile(`(?i)^\s*USER\s+(root|0)(?::(root|0))?(?:\s+#.*)?$`)},
	{"docker-privileged", "critical", "Container is configured as privileged", "Remove privileged mode and grant only the specific capabilities the container needs.", regexp.MustCompile(`(?i)(docker-compose|compose).*\.ya?ml$`), regexp.MustCompile(`(?i)privileged\s*:\s*true\b(?:\s+#.*)?$`)},
	{"docker-host-network", "high", "Container uses host networking", "Prefer an isolated bridge network and publish only required ports.", regexp.MustCompile(`(?i)(docker-compose|compose).*\.ya?ml$`), regexp.MustCompile(`(?i)network_mode\s*:\s*["']?host\b(?:["']?\s+#.*)?$`)},
	{"terraform-public-ingress", "high", "Terraform ingress rule allows traffic from all IPv4 addresses", "Restrict cidr_blocks to trusted ranges and required ports.", regexp.MustCompile(`\.tf$`), regexp.MustCompile(`(?i)0\.0\.0\.0/0`)},
	{"github-actions-write-permissions", "high", "GitHub Actions workflow grants write-all permissions", "Use least-privilege permissions at workflow or job level; grant write access only where required.", regexp.MustCompile(`\.github/workflows/.*\.ya?ml$`), regexp.MustCompile(`(?i)^\s*permissions\s*:\s*write-all\b(?:\s+#.*)?$`)},
	{"github-actions-unpinned", "medium", "GitHub Action reference is not pinned to a full commit SHA", "Pin third-party actions to a reviewed full-length commit SHA or an immutable image digest.", regexp.MustCompile(`\.github/workflows/.*\.ya?ml$`), regexp.MustCompile(`(?i)^\s*(?:-\s*)?uses\s*:`)},
	{"kubernetes-privileged", "critical", "Kubernetes container is configured as privileged", "Set securityContext.privileged to false and use least-privilege capabilities.", regexp.MustCompile(`(?i)\.ya?ml$`), regexp.MustCompile(`(?i)^\s*privileged\s*:\s*true\b(?:\s+#.*)?$`)},
	{"kubernetes-root-user", "high", "Kubernetes workload explicitly runs as root", "Set runAsNonRoot: true and configure a non-zero runAsUser where possible.", regexp.MustCompile(`(?i)\.ya?ml$`), regexp.MustCompile(`(?i)^\s*runAsUser\s*:\s*0\s*(?:#.*)?$`)},
}

var fullCommitSHA = regexp.MustCompile(`(?i)^[0-9a-f]{40}$`)
var sha256Digest = regexp.MustCompile(`(?i)^sha256:[0-9a-f]{64}$`)
var usesLine = regexp.MustCompile(`(?i)^\s*(?:-\s*)?uses\s*:\s*([^#\s]+)\s*(?:#.*)?$`)

var ignoredDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".next": true,
}

// Scan preserves the original findings-only API. Use ScanWithReport when completeness matters.
func Scan(root string) ([]secret.Finding, error) {
	report, err := ScanWithReport(root, Options{})
	if err != nil {
		return nil, err
	}
	if !report.Complete {
		return nil, fmt.Errorf("configuration scan incomplete: %d path(s) could not be inspected", len(report.SkippedPaths))
	}
	return report.Findings, nil
}

// ScanWithReport checks common risky settings without executing project code. It intentionally
// inspects .github/workflows even though that directory is hidden, because those workflows are
// security-sensitive. Explicit -exclude-dir values are still honored.
func ScanWithReport(root string, opts Options) (Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Report{}, err
	}
	if !info.IsDir() {
		return Report{}, fmt.Errorf("configuration scan root must be a directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Report{}, fmt.Errorf("resolve configuration scan root: %w", err)
	}
	root = resolvedRoot

	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = 2 << 20
	}
	excluded := make(map[string]struct{}, len(opts.ExcludeDirs))
	for _, dir := range opts.ExcludeDirs {
		excluded[filepath.Clean(dir)] = struct{}{}
	}

	report := Report{Findings: []secret.Finding{}, SkippedPaths: []secret.ScanIssue{}, Complete: true}
	addIssue := func(path, reason, detail string, incomplete bool) {
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil {
			path = filepath.ToSlash(rel)
		} else {
			path = filepath.ToSlash(path)
		}
		report.SkippedPaths = append(report.SkippedPaths, secret.ScanIssue{Path: path, Reason: reason, Detail: detail})
		if incomplete {
			report.Complete = false
		}
	}

	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			addIssue(path, "config_walk_error", walkErr.Error(), true)
			return nil
		}
		if entry.IsDir() {
			if path != root {
				if ignoredDirs[entry.Name()] {
					return filepath.SkipDir
				}
				if _, ok := excluded[filepath.Clean(entry.Name())]; ok {
					return filepath.SkipDir
				}
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

		fileInfo, err := entry.Info()
		if err != nil {
			addIssue(path, "config_stat_error", err.Error(), true)
			return nil
		}
		if fileInfo.Size() > maxFileSize {
			addIssue(path, "config_file_too_large", fmt.Sprintf("size %d bytes exceeds limit %d bytes", fileInfo.Size(), maxFileSize), true)
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			addIssue(path, "config_read_error", err.Error(), true)
			return nil
		}

		initialBufferSize := 4096
		if maxFileSize < int64(initialBufferSize) {
			initialBufferSize = int(maxFileSize)
		}
		maxInt := int64(int(^uint(0) >> 1))
		maxTokenSize := maxFileSize
		if maxTokenSize > maxInt {
			maxTokenSize = maxInt
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, initialBufferSize), int(maxTokenSize))
		lines := make([]string, 0, 32)
		hasAPIVersion, hasKind := false, false
		for scanner.Scan() {
			line := scanner.Text()
			lines = append(lines, line)
			trimmed := strings.TrimSpace(line)
			if isCommentLine(trimmed) {
				continue
			}
			if strings.HasPrefix(trimmed, "apiVersion:") {
				hasAPIVersion = true
			}
			if strings.HasPrefix(trimmed, "kind:") {
				hasKind = true
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			addIssue(path, "config_read_error", scanErr.Error(), true)
			return nil
		}
		if closeErr != nil {
			addIssue(path, "config_read_error", closeErr.Error(), true)
			return nil
		}

		// Kubernetes manifests commonly have arbitrary filenames such as app.yaml, not
		// only deployment.yaml or pod.yaml. Require Kubernetes document markers before
		// applying pod/container-specific rules so Compose and generic YAML are not misread.
		isKubernetesManifest := hasAPIVersion && hasKind
		for index, line := range lines {
			if isCommentLine(strings.TrimSpace(line)) {
				continue
			}
			for _, r := range matchingRules {
				if strings.HasPrefix(r.id, "kubernetes-") && !isKubernetesManifest {
					continue
				}
				if !matchesRule(r, line) {
					continue
				}
				message := r.message + " Remediation: " + r.remediation
				report.Findings = append(report.Findings, secret.Finding{
					RuleID: r.id, Severity: r.severity, Path: rel,
					Line: index + 1, Column: 1, Message: message,
				})
			}
		}
		report.ScannedFiles++
		return nil
	})
	if err != nil {
		return Report{}, err
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Path != report.Findings[j].Path {
			return report.Findings[i].Path < report.Findings[j].Path
		}
		if report.Findings[i].Line != report.Findings[j].Line {
			return report.Findings[i].Line < report.Findings[j].Line
		}
		return strings.Compare(report.Findings[i].RuleID, report.Findings[j].RuleID) < 0
	})
	sort.Slice(report.SkippedPaths, func(i, j int) bool {
		if report.SkippedPaths[i].Path != report.SkippedPaths[j].Path {
			return report.SkippedPaths[i].Path < report.SkippedPaths[j].Path
		}
		return report.SkippedPaths[i].Reason < report.SkippedPaths[j].Reason
	})
	return report, nil
}

func isCommentLine(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
}

func matchesRule(r rule, line string) bool {
	if !r.linePattern.MatchString(line) {
		return false
	}
	if r.id != "github-actions-unpinned" {
		return true
	}

	match := usesLine.FindStringSubmatch(line)
	if len(match) != 2 {
		return false
	}
	reference := match[1]
	// Local actions are part of the same repository. Remote action references must use a
	// full commit SHA; tags and branch names are mutable. Docker actions may use an immutable
	// sha256 image digest instead.
	if strings.HasPrefix(reference, "./") {
		return false
	}
	at := strings.LastIndex(reference, "@")
	if at < 0 || at == len(reference)-1 {
		return true
	}
	ref := reference[at+1:]
	return !fullCommitSHA.MatchString(ref) && !sha256Digest.MatchString(ref)
}
