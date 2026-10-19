// Package secret implements a local, read-only scanner for likely hard-coded secrets.
// Findings intentionally never include the matched secret value.
package secret

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const defaultMaxFileSize int64 = 2 << 20 // 2 MiB

// Finding describes a suspected secret without disclosing its value.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
	Redacted string `json:"redacted_match,omitempty"`
}

// ScanIssue explains why a path was not fully inspected. Detail never contains file contents.
type ScanIssue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Report describes findings and the scope actually inspected.
type Report struct {
	Findings                 []Finding   `json:"findings"`
	ScannedFiles             int         `json:"scanned_files"`
	ConfigurationFilesScanned int        `json:"configuration_files_scanned"`
	SkippedPaths             []ScanIssue `json:"skipped_paths"`
	SuppressedFindings       int         `json:"suppressed_findings"`
	Complete                 bool        `json:"complete"`
}

// Options controls a scan. MaxFileSize <= 0 uses the 2 MiB default.
type Options struct {
	MaxFileSize   int64
	IncludeHidden bool
	ExcludeDirs   []string
	RuleConfig Config
	Baseline Baseline
}

type rule struct {
	id, severity, message string
	pattern               *regexp.Regexp
}

var rules = []rule{
	{"aws-access-key-id", "high", "Possible AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"aws-secret-access-key", "critical", "Possible AWS secret access key assignment", regexp.MustCompile(`(?i)\baws_secret_access_key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,128})`)},
	{"aws-session-token", "critical", "Possible AWS session token assignment", regexp.MustCompile(`(?i)\baws_session_token\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{32,8192})`)},
	{"github-token", "critical", "Possible GitHub access token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,255}\b`)},
	{"github-fine-grained-token", "critical", "Possible GitHub fine-grained personal access token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,255}\b`)},
	{"google-api-key", "high", "Possible Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"slack-token", "critical", "Possible Slack access token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"stripe-live-secret-key", "critical", "Possible Stripe live secret key", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{20,}\b`)},
	{"npm-access-token", "high", "Possible npm access token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"private-key-header", "critical", "Private key material header found", regexp.MustCompile(`-----BEGIN (?:(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----`)},
	{"generic-secret-assignment", "medium", "Possible hard-coded credential assignment", regexp.MustCompile(`(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})`)},
}

var ignoredDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "dist": {}, "build": {}, ".next": {},
}

// Scan preserves the original findings-only API. Use ScanWithReport when completeness matters.
func Scan(root string, opts Options) ([]Finding, error) {
	report, err := ScanWithReport(root, opts)
	if err != nil {
		return nil, err
	}
	return report.Findings, nil
}

// ScanWithReport recursively inspects regular text-like files under root. It is read-only.
// Complete is false when a path that should be inspected cannot be fully read.
func ScanWithReport(root string, opts Options) (Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Report{}, err
	}
	if !info.IsDir() {
		return Report{}, errors.New("scan root must be a directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Report{}, fmt.Errorf("resolve scan root: %w", err)
	}
	root = resolvedRoot
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = defaultMaxFileSize
	}
	excluded := make(map[string]struct{}, len(opts.ExcludeDirs))
	for _, d := range opts.ExcludeDirs {
		excluded[filepath.Clean(d)] = struct{}{}
	}

	report := Report{Findings: []Finding{}, SkippedPaths: []ScanIssue{}, Complete: true}
	addIssue := func(path, reason, detail string, makesIncomplete bool) {
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil {
			path = filepath.ToSlash(rel)
		} else {
			path = filepath.ToSlash(path)
		}
		report.SkippedPaths = append(report.SkippedPaths, ScanIssue{Path: path, Reason: reason, Detail: detail})
		if makesIncomplete {
			report.Complete = false
		}
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			addIssue(path, "walk_error", walkErr.Error(), true)
			return nil
		}
		if path == root {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if _, ok := ignoredDirs[name]; ok {
				addIssue(path, "ignored_directory", "directory is excluded by Preflight defaults", false)
				return filepath.SkipDir
			}
			if _, ok := excluded[filepath.Clean(name)]; ok {
				addIssue(path, "excluded_directory", "directory matched -exclude-dir", false)
				return filepath.SkipDir
			}
			if !opts.IncludeHidden && strings.HasPrefix(name, ".") {
				addIssue(path, "hidden_directory", "hidden paths are excluded from the secret-content scan; use -include-hidden to include them", false)
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			addIssue(path, "non_regular_file", "only regular files are scanned", false)
			return nil
		}
		if !opts.IncludeHidden && strings.HasPrefix(name, ".") {
			addIssue(path, "hidden_file", "use -include-hidden to scan hidden files", false)
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			addIssue(path, "stat_error", err.Error(), true)
			return nil
		}
		if fi.Size() > maxSize {
			addIssue(path, "file_too_large", fmt.Sprintf("size %d bytes exceeds limit %d bytes", fi.Size(), maxSize), true)
			return nil
		}
		if fi.Size() == 0 {
			addIssue(path, "empty_file", "empty file contains no content to inspect", false)
			return nil
		}
		fileFindings, err := scanFile(root, path, maxSize, opts.RuleConfig)
		if err != nil {
			reason := "read_error"
			if errors.Is(err, errBinaryFile) {
				reason = "binary_file"
			}
			addIssue(path, reason, err.Error(), true)
			return nil
		}
		report.ScannedFiles++
		report.Findings = append(report.Findings, fileFindings...)
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	baselineSet := make(map[string]struct{}, len(opts.Baseline.Findings))
	for _, entry := range opts.Baseline.Findings {
		baselineSet[entry.Fingerprint] = struct{}{}
	}
	active := report.Findings[:0]
	for _, finding := range report.Findings {
		if _, ok := baselineSet[Fingerprint(finding)]; ok {
			report.SuppressedFindings++
			continue
		}
		active = append(active, finding)
	}
	report.Findings = active
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
	sort.Slice(report.SkippedPaths, func(i, j int) bool {
		if report.SkippedPaths[i].Path != report.SkippedPaths[j].Path {
			return report.SkippedPaths[i].Path < report.SkippedPaths[j].Path
		}
		return report.SkippedPaths[i].Reason < report.SkippedPaths[j].Reason
	})
	return report, nil
}

var errBinaryFile = errors.New("binary file")

func scanFile(root, path string, maxFileSize int64, config Config) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	maxInt := int64(int(^uint(0) >> 1))
	maxTokenSize := maxInt
	if maxFileSize < maxInt {
		maxTokenSize = maxFileSize
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), int(maxTokenSize))
	var out []Finding
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := s.Text()
		if strings.IndexByte(line, 0) >= 0 {
			return nil, errBinaryFile
		}
		for _, r := range rules {
			ruleConfig, configured := config.Rules[r.id]
			if configured && ruleConfig.Enabled != nil && !*ruleConfig.Enabled {
				continue
			}
			severity := r.severity
			if configured && ruleConfig.Severity != "" {
				severity = strings.ToLower(ruleConfig.Severity)
			}
			for _, loc := range r.pattern.FindAllStringIndex(line, -1) {
				out = append(out, Finding{RuleID: r.id, Severity: severity, Path: filepath.ToSlash(rel), Line: lineNo, Column: loc[0] + 1, Message: r.message, Redacted: "[REDACTED]"})
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return out, nil
}
