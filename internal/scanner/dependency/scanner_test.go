package dependency

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lonely-worm/preflight/internal/scanner/secret"
)

func TestParseJSONHandlesOutOfOrderEventsAndMapsSourceLocation(t *testing.T) {
	stream := strings.Join([]string{
		`{"config":{"protocol_version":"v1.0.0"}}`,
		`{"finding":{"osv":"GO-2026-1234","fixed_version":"v1.4.2","trace":[{"module":"example.com/vulnerable","version":"v1.4.0","package":"example.com/vulnerable/parser","function":"Parse","position":{"filename":"parser/parse.go","line":7,"column":3}},{"module":"example.com/app","package":"example.com/app","function":"main","position":{"filename":"cmd/server/main.go","line":42,"column":9}}]}}`,
		`{"osv":{"id":"GO-2026-1234","summary":"Malformed input may panic"}}`,
		`{"finding":{"osv":"GO-2026-1234","fixed_version":"v1.4.2","trace":[{"module":"example.com/vulnerable","version":"v1.4.0","package":"example.com/vulnerable/parser","function":"Parse","position":{"filename":"parser/parse.go","line":7,"column":3}},{"module":"example.com/app","package":"example.com/app","function":"main","position":{"filename":"cmd/server/main.go","line":42,"column":9}}]}}`,
	}, "\n")

	findings, err := parseJSON(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected duplicate trace to be deduplicated; got %#v", findings)
	}
	finding := findings[0]
	if finding.RuleID != "go-vulnerability" || finding.Severity != "high" {
		t.Fatalf("unexpected rule or severity: %#v", finding)
	}
	if finding.Path != "cmd/server/main.go" || finding.Line != 42 || finding.Column != 9 {
		t.Fatalf("expected actionable entry-point location, got %#v", finding)
	}
	for _, want := range []string{"GO-2026-1234", "Malformed input may panic", "v1.4.2", "Vulnerable symbol: example.com/vulnerable/parser.Parse"} {
		if !strings.Contains(finding.Message, want) {
			t.Errorf("expected message to contain %q, got %q", want, finding.Message)
		}
	}
}

func TestParseJSONReportsModuleLevelFindingWithoutSourceLocation(t *testing.T) {
	stream := `{"config":{"protocol_version":"v1.0.0"}}` + "\n" + `{"finding":{"osv":"GO-2026-4321","fixed_version":"v2.0.1","trace":[{"module":"example.com/dependency","version":"v2.0.0"}]}}` + "\n" + `{"osv":{"id":"GO-2026-4321","summary":"A vulnerable dependency"}}`
	findings, err := parseJSON(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one module-level finding, got %#v", findings)
	}
	if findings[0].Path != "go.mod" || findings[0].Line != 1 {
		t.Fatalf("module-level finding should point to go.mod, got %#v", findings[0])
	}
	if !strings.Contains(findings[0].Message, "example.com/dependency v2.0.0") {
		t.Fatalf("expected affected module in finding, got %q", findings[0].Message)
	}
}

func TestParseJSONRejectsMalformedOrUnidentifiableFinding(t *testing.T) {
	for _, stream := range []string{
		`{"finding":`,
		"{\"config\":{\"protocol_version\":\"v1.0.0\"}}\n" + `{"finding":{"fixed_version":"v1.2.3","trace":[]}}`,
		"",
	} {
		if _, err := parseJSON(strings.NewReader(stream)); err == nil {
			t.Errorf("expected parse error for %q", stream)
		}
	}
}

func TestParseJSONRejectsUnsupportedProtocolAndUnknownOSV(t *testing.T) {
	for _, stream := range []string{
		`{"config":{"protocol_version":"v9.0.0"}}`,
		`{"config":{"protocol_version":"v1.0.0"}}\n{"finding":{"osv":"GO-2026-9999","trace":[]}}`,
	} {
		if _, err := parseJSON(strings.NewReader(stream)); err == nil {
			t.Errorf("expected protocol or unknown-OSV validation error for %q", stream)
		}
	}
}

func TestParseJSONAcceptsCompleteNoFindingStream(t *testing.T) {
	stream := `{"config":{"protocol_version":"v1.0.0"}}` + "\n" + `{"progress":{"message":"scan complete"}}`
	findings, err := parseJSON(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("expected valid no-finding stream, got %v", err)
	}
	if findings == nil || len(findings) != 0 {
		t.Fatalf("expected an empty findings slice, got %#v", findings)
	}
}

func TestParseJSONRequiresConfigFirstAndSingleEventType(t *testing.T) {
	for _, stream := range []string{
		`{"progress":{"message":"started"}}\n{"config":{"protocol_version":"v1.0.0"}}`,
		`{"config":{"protocol_version":"v1.0.0"},"progress":{}}`,
		`{"config":{"protocol_version":"v1.0.0"}}\n{"unknownEvent":{}}`,
	} {
		if _, err := parseJSON(strings.NewReader(stream)); err == nil {
			t.Errorf("expected invalid event stream to be rejected: %s", stream)
		}
	}
}

func TestNormalizeFindingPathsKeepsLocationsRelativeAndRedactsOutsidePaths(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "internal", "worker.go")
	outside := filepath.Join(filepath.Dir(root), "outside.go")
	original := []secret.Finding{
		{RuleID: "go-vulnerability", Path: inside, Line: 12, Column: 4, Message: "test finding"},
		{RuleID: "go-vulnerability", Path: outside, Line: 3, Column: 2, Message: "external finding"},
		{RuleID: "go-vulnerability", Path: "../outside.go", Line: 1, Column: 1, Message: "relative escape"},
	}

	got := normalizeFindingPaths(root, original)
	if got[0].Path != "internal/worker.go" {
		t.Fatalf("expected repository-relative path, got %q", got[0].Path)
	}
	for _, finding := range got[1:] {
		if finding.Path != "go.mod" {
			t.Errorf("outside path should fall back to go.mod, got %q", finding.Path)
		}
		if strings.Contains(finding.Message, root) || strings.Contains(finding.Message, filepath.Dir(root)) {
			t.Errorf("finding message leaked an absolute path: %q", finding.Message)
		}
		if !strings.Contains(finding.Message, "outside the scanned project") {
			t.Errorf("expected fallback explanation, got %q", finding.Message)
		}
	}
}
