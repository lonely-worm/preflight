package dependency

import (
	"strings"
	"testing"
)

func TestParseJSONHandlesOutOfOrderEventsAndMapsSourceLocation(t *testing.T) {
	stream := strings.Join([]string{
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

func TestParseJSONReportsModuleLevelFindingsWithoutTrace(t *testing.T) {
	stream := `{"finding":{"osv":"GO-2026-4321","fixed_version":"v2.0.1","trace":[{"module":"example.com/dependency","version":"v2.0.0"}]}}`
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
		`{"finding":{"fixed_version":"v1.2.3","trace":[]}}`,
	} {
		if _, err := parseJSON(strings.NewReader(stream)); err == nil {
			t.Errorf("expected parse error for %q", stream)
		}
	}
}
