# Preflight

**A developer-focused security toolkit written in Go.**

Preflight helps developers identify common security risks before code ships. It currently includes a read-only secret-scanning package and a command-line interface.

## Current status

- [x] Read-only filesystem scanning
- [x] Detection rules for common credential patterns
- [x] Redacted findings (secret values are not returned)
- [x] Stable finding order
- [x] Unit tests for scanner and CLI behavior
- [x] CLI integration (text and JSON output)
- [x] SARIF 2.1.0 reporter (local output; GitHub Code Scanning upload workflow not configured yet)
- [x] GitHub Actions CI workflow (runs unit tests and go vet on push and pull request)
- [ ] Baseline and configurable policy support

## Quick start

Requires Go 1.22 or newer.

Run tests and static checks:

```powershell
go test ./...
go vet ./...
```

Scan the current directory:

```powershell
go run ./cmd/preflight .
```

Output machine-readable JSON:

```powershell
go run ./cmd/preflight -format json .
```

Include hidden files and directories:

```powershell
go run ./cmd/preflight -include-hidden .
```

Exclude a directory by name (repeat the flag to add more):

```powershell
go run ./cmd/preflight -exclude-dir testdata -exclude-dir fixtures .
```

Set a custom file-size limit in bytes:

```powershell
go run ./cmd/preflight -max-file-size 1048576 .
```

### Exit codes

- `0`: scan completed with no matching patterns.
- `1`: one or more potential findings were detected.
- `2`: invalid options or a scan/output error.

## Safety and limitations

Preflight is a first-pass detector, not a guarantee that a repository contains no secrets. False positives and missed detections are possible. It does not validate credentials against external services and does not modify scanned files. Only scan directories you own or are authorized to inspect.

If a real credential is found in source control, revoke or rotate it; deleting the line alone does not remove it from Git history.

## Project roadmap

1. Add SARIF output and GitHub Code Scanning integration.
2. Add baseline support and configurable severity policy.
3. Improve rules, test fixtures, false-positive handling, and benchmarks.
4. Publish versioned cross-platform releases.

## License

License selection is pending. Do not assume reuse terms until a license file is added.
