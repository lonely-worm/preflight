// Package secret implements a local, read-only scanner for likely hard-coded secrets.
// Findings intentionally never include the matched secret value.
package secret

import (
	"bufio"
	"errors"
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

// Options controls a scan. MaxFileSize <= 0 uses the 2 MiB default.
type Options struct {
	MaxFileSize   int64
	IncludeHidden bool
	ExcludeDirs   []string
}

type rule struct {
	id, severity, message string
	pattern               *regexp.Regexp
}

var rules = []rule{
	{"aws-access-key-id", "high", "Possible AWS access key ID", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"github-token", "critical", "Possible GitHub access token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,255}\b`)},
	{"private-key-header", "critical", "Private key material header found", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"generic-secret-assignment", "medium", "Possible hard-coded credential assignment", regexp.MustCompile(`(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})`)},
}

var ignoredDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "dist": {}, "build": {}, ".next": {},
}

// Scan recursively inspects regular text-like files under root. It is read-only.
func Scan(root string, opts Options) ([]Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("scan root must be a directory")
	}
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = defaultMaxFileSize
	}
	excluded := make(map[string]struct{}, len(opts.ExcludeDirs))
	for _, d := range opts.ExcludeDirs {
		excluded[filepath.Clean(d)] = struct{}{}
	}

	var findings []Finding
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if _, ok := ignoredDirs[name]; ok {
				return filepath.SkipDir
			}
			if _, ok := excluded[filepath.Clean(name)]; ok {
				return filepath.SkipDir
			}
			if !opts.IncludeHidden && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if !opts.IncludeHidden && strings.HasPrefix(name, ".") {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Size() > maxSize || fi.Size() == 0 {
			return nil
		}
		fileFindings, err := scanFile(root, path)
		if err != nil {
			return nil
		} // unreadable/binary files are skipped, not fatal to the whole scan
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
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
	return findings, nil
}

func scanFile(root, path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), int(defaultMaxFileSize))
	var out []Finding
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := s.Text()
		if strings.IndexByte(line, 0) >= 0 {
			return nil, errors.New("binary file")
		}
		for _, r := range rules {
			for _, loc := range r.pattern.FindAllStringIndex(line, -1) {
				out = append(out, Finding{RuleID: r.id, Severity: r.severity, Path: filepath.ToSlash(rel), Line: lineNo, Column: loc[0] + 1, Message: r.message, Redacted: "[REDACTED]"})
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
