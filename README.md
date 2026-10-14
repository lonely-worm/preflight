# Preflight

**A developer-focused, read-only secret scanner written in Go.**

Preflight scans a local project directory for common hard-coded credential patterns and reports findings without printing the matched secret value. It is designed as a lightweight first line of defense—not a replacement for secret-management controls or a full security audit.

[![Go CI](https://github.com/lonely-worm/preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/lonely-worm/preflight/actions/workflows/ci.yml)
[![Code Scanning](https://github.com/lonely-worm/preflight/actions/workflows/code-scanning.yml/badge.svg)](https://github.com/lonely-worm/preflight/actions/workflows/code-scanning.yml)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)

## Features

- Read-only recursive filesystem scanning; no credential validation or network requests.
- Detection patterns for AWS access key IDs, GitHub access tokens, private-key headers, and generic credential assignments.
- Redacted findings with rule ID, severity, relative file path, line, and column.
- Text, JSON, and SARIF 2.1.0 output.
- Stable finding order for predictable output.
- Hidden-file control, directory exclusions, and configurable maximum file size.
- GitHub Actions workflows for tests/build checks and SARIF upload to GitHub Code Scanning.

## Quick start

Requires Go 1.22 or newer.

Clone and enter the repository:

```sh
git clone https://github.com/lonely-worm/preflight.git
cd preflight
```

Run tests and static checks:

```sh
go test ./...
go vet ./...
```

Scan a directory:

```sh
go run ./cmd/preflight .
```

Choose an output format:

```sh
# JSON
go run ./cmd/preflight -format json .

# SARIF 2.1.0
go run ./cmd/preflight -format sarif . > preflight.sarif
```

Useful options:

```sh
# Include hidden files and directories
go run ./cmd/preflight -include-hidden .

# Exclude directories by name; repeat the flag as needed
go run ./cmd/preflight -exclude-dir testdata -exclude-dir fixtures .

# Change the maximum scanned file size (bytes)
go run ./cmd/preflight -max-file-size 1048576 .
```

## Detection coverage

| Rule ID | What it looks for | Default severity |
| --- | --- | --- |
| `aws-access-key-id` | AWS access key ID-shaped strings | High |
| `github-token` | GitHub token-shaped strings | Critical |
| `private-key-header` | Private-key PEM header markers | Critical |
| `generic-secret-assignment` | Credential-like assignments such as `api_key`, `password`, or `client_secret` | Medium |

These are pattern-based heuristics. A match is a **potential finding**, not proof that a credential is valid or exploitable.

## Exit codes

- `0` — scan completed with no matching patterns.
- `1` — one or more potential findings were detected.
- `2` — invalid options or a scan/output error.

## Safety and limitations

- Preflight does not modify scanned files or send their contents to a remote service.
- Matched secret values are not included in text, JSON, or SARIF findings.
- False positives and missed detections are possible. Encoded, split, dynamically generated, or unsupported credentials may not be detected.
- Some unreadable or binary files may be skipped; review scan scope when completeness matters.
- Only scan directories you own or are authorized to inspect.
- If a real credential was committed, revoke or rotate it. Removing the current line alone does not remove it from Git history.

## Roadmap

1. Add baseline support and configurable severity policy.
2. Expand test fixtures and regression coverage for detection edge cases.
3. Add benchmarks and document detection trade-offs.
4. Publish versioned cross-platform releases.

## License

No license file is present yet. Until a license is selected and added, do not assume the repository is licensed for reuse.
