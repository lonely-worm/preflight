# Preflight

**A developer-focused security toolkit written in Go.**

Preflight helps developers identify common security risks before code ships. This repository currently contains the Phase 2A secret-scanning package; CLI and orchestrator integration are planned next.

## Current status

- [x] Read-only filesystem scanning
- [x] Detection rules for common credential patterns
- [x] Redacted findings (secret values are not returned)
- [x] Stable finding order
- [x] Unit tests for detection, ignored directories, and invalid scan roots
- [ ] CLI integration
- [ ] SARIF reporter
- [ ] GitHub Actions CI workflow
- [ ] Baseline and configurable policy support

## Quick start

Requires Go 1.22 or newer.

```powershell
go test ./...
go vet ./...
```

The scanner package is located at `internal/scanner/secret`. It is currently a library package, not yet a standalone CLI.

## Safety and limitations

Preflight is a first-pass detector, not a guarantee that a repository contains no secrets. False positives and missed detections are possible. It does not validate credentials against external services and does not modify scanned files. Only scan directories you own or are authorized to inspect.

If a real credential is found in source control, revoke or rotate it; deleting the line alone does not remove it from Git history.

## Project roadmap

1. Integrate the scanner with a stable finding model and CLI.
2. Add SARIF output and CI gating.
3. Improve rules, test fixtures, false-positive handling, and benchmarks.
4. Publish versioned cross-platform releases.

## License

License selection is pending. Do not assume reuse terms until a license file is added.
