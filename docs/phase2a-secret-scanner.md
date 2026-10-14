# Preflight — Phase 2A: Secret Scanner Package

A small, read-only Go scanner foundation for detecting likely hard-coded secrets in a local project directory. This package is intended to be integrated into the existing Preflight scanner interface after that interface is reviewed; it does not assume or overwrite the existing Phase 1 architecture.

## Current capabilities

- Detects common AWS access key IDs, GitHub token formats, private-key headers, and high-confidence generic credential assignments.
- Returns stable, sorted findings with rule ID, severity, relative path, line, and column.
- Redacts matched content in all findings; the secret value is never returned.
- Skips common generated/dependency directories and hidden files by default.
- Read-only; does not make network requests or modify scanned files.
- Includes unit tests.

## Run tests

```bash
go test ./...
```

## Minimal usage

```go
findings, err := secret.Scan(".", secret.Options{})
if err != nil {
    log.Fatal(err)
}
for _, finding := range findings {
    fmt.Printf("%s %s:%d:%d %s\n", finding.Severity, finding.Path, finding.Line, finding.Column, finding.Message)
}
```

## Limitations

This is a first-pass scanner, not a guarantee that a repository is secret-free. It can produce false positives and miss encoded, split, dynamically generated, or unsupported credentials. It intentionally does not validate discovered credentials against live services. Review findings manually and rotate any real credential that was committed.

## Integration note

Before wiring this package into Preflight's orchestrator, map `secret.Finding` to the project's existing `internal/finding` model and implement the existing scanner interface. Keep scanner registration explicit and preserve current CLI/reporting contracts.
