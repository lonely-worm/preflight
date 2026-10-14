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
- [x] SARIF 2.1.0 reporter
- [x] GitHub Actions workflow configured to upload SARIF to GitHub Code Scanning
- [x] GitHub Actions CI workflow (unit tests, go vet, build, and smoke tests)
- [ ] Baseline and configurable policy support

## Quick start

Requires Go 1.22 or newer.

Run tests and static checks:

```sh
go test ./...
go vet ./...
```

Scan the current directory:

```sh
go run ./cmd/preflight .
```

Output machine-readable JSON:

```sh
go run ./cmd/preflight -format json .
```

Output SARIF for GitHub Code Scanning:

```sh
go run ./cmd/preflight -format sarif . > preflight.sarif
```

Include hidden files and directories:

```sh
go run ./cmd/preflight -include-hidden .
```

Exclude a directory by name (repeat the flag to add more):

```sh
go run ./cmd/preflight -exclude-dir testdata -exclude-dir fixtures .
```

Set a custom file-size limit in bytes:

```sh
go run ./cmd/preflight -max-file-size 1048576 .
```

### Exit codes

- `0`: scan completed with no matching patterns.
- `1`: one or more potential findings were detected.
- `2`: invalid options or a scan/output error.

## Safety and limitations

Preflight is a first-pass detector, not a guarantee that a repository contains no secrets. False positives and missed detections are possible. It does not validate credentials against external services and does not modify scanned files. Only scan directories you own or are authorized to inspect.

If a real credential is found in source control, revoke or rotate it; deleting the line alone does not remove it from Git history.

## Roadmap

1. Add baseline support and configurable severity policy.
2. Improve rules, test fixtures, false-positive handling, and benchmarks.
3. Publish versioned cross-platform releases.

## License

No license file is present yet. Until a license is selected and added, do not assume the repository is licensed for reuse.
