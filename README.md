# Preflight

**A developer-focused, read-only secret scanner written in Go.**

Preflight scans a local project directory for common hard-coded credential patterns and reports findings without printing the matched secret value. It is designed as a lightweight first line of defense—not a replacement for secret-management controls or a full security audit.

[![Go CI](https://github.com/lonely-worm/preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/lonely-worm/preflight/actions/workflows/ci.yml)
[![Code Scanning](https://github.com/lonely-worm/preflight/actions/workflows/code-scanning.yml/badge.svg)](https://github.com/lonely-worm/preflight/actions/workflows/code-scanning.yml)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)

## Features

- Read-only recursive filesystem scanning; no credential validation or network requests.
- Detection patterns for AWS access key IDs, GitHub classic and fine-grained tokens, Google API keys, Slack tokens, Stripe live secret keys, npm tokens, private-key headers, and generic credential assignments.
- Redacted findings with rule ID, severity, relative file path, line, and column.
- Text, JSON, and SARIF 2.1.0 output.
- Stable finding order for predictable output.
- Scan report includes inspected-file counts, skipped paths with reasons, and an explicit completeness status.
- Scan report includes inspected-file counts, skipped paths with reasons, and an explicit completeness status.
- JSON rule configuration with per-rule enable/disable and severity overrides.
- Baseline support for suppressing known findings without storing credential values.
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

# JSON now includes findings, scan counts, skipped-path diagnostics, and completeness status.

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
| `github-token` | GitHub classic token-shaped strings | Critical |
| `github-fine-grained-token` | GitHub fine-grained personal access token-shaped strings | Critical |
| `google-api-key` | Google API key-shaped strings | High |
| `slack-token` | Slack access token-shaped strings | Critical |
| `stripe-live-secret-key` | Stripe live secret key-shaped strings | Critical |
| `npm-access-token` | npm access token-shaped strings | High |
| `private-key-header` | Private-key PEM header markers | Critical |
| `generic-secret-assignment` | Credential-like assignments such as `api_key`, `password`, or `client_secret` | Medium |

These are pattern-based heuristics. A match is a **potential finding**, not proof that a credential is valid or exploitable.

## Dependency and configuration scanning

The default scan checks common risky settings in Dockerfiles, Compose files, Terraform files, Kubernetes manifests, and GitHub Actions workflows. Findings include a rule ID, severity, source location, and concrete remediation guidance.

```sh
# Scan secrets and security-sensitive configuration
go run ./cmd/preflight .

# Also check Go dependencies against the official Go vulnerability database
go install golang.org/x/vuln/cmd/govulncheck@latest
go run ./cmd/preflight -deps .
```

The dependency scan requires `govulncheck` on `PATH` and network access to the Go vulnerability database. It reports known vulnerabilities found by govulncheck's code-aware analysis, including reachable vulnerable symbols and a fixed version when available. If the tool is missing or the scan fails, Preflight marks the overall report incomplete instead of presenting a clean result. See the [official Go vulnerability management documentation](https://go.dev/doc/security/vuln/).

Configuration rules currently include:
- Docker containers explicitly configured to run as root, privileged Compose services, and host networking.
- Terraform ingress rules containing `0.0.0.0/0`.
- GitHub Actions workflows granting `write-all` permissions or using mutable version tags instead of full commit SHAs.
- Kubernetes manifests enabling privileged containers or explicitly setting `runAsUser: 0`.

These checks are heuristic and should be reviewed in context. For GitHub Actions, pinning to a reviewed full commit SHA is the recommended security practice; see [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Rule configuration and baseline

Create a `preflight.json` file to disable a rule or override its severity. Unspecified rules keep their built-in defaults.

```json
{
  "rules": {
    "generic-secret-assignment": {
      "enabled": true,
      "severity": "low"
    },
    "google-api-key": {
      "enabled": false
    }
  }
}
```

Supported severities are `critical`, `high`, `medium`, `low`, and `info`. Unknown rule IDs and invalid severities are rejected instead of silently ignored.

```sh
# Scan using custom rules
go run ./cmd/preflight -config preflight.json .

# Create/update a baseline from current findings
go run ./cmd/preflight -write-baseline .preflight-baseline.json .

# Suppress findings already represented in a baseline
go run ./cmd/preflight -baseline .preflight-baseline.json .
```

The baseline stores a fingerprint plus rule ID, relative path, line, and column—not the matched secret. Fingerprints are location-based; moving a finding or editing nearby lines can cause it to reappear and require baseline regeneration. Review findings before accepting them into a baseline. New findings remain visible, and the text report shows how many were suppressed.

## Scan completeness and exit codes

CI regression tests also verify that incomplete JSON and SARIF runs fail closed.

Every output format reports scan completeness. Text output lists skipped paths and reasons; JSON returns an object containing `findings`, `scanned_files`, `skipped_paths`, and `complete`. SARIF marks incomplete execution as unsuccessful and includes a warning notification.

- `0` — scan completed without findings; paths intentionally excluded by policy may still be listed.
- `1` — scan completed and one or more potential findings were detected.
- `2` — invalid options, a fatal scan/output error, or an incomplete scan (for example, an unreadable, binary, or oversized file). Review the report before treating the result as clean.

Preflight reports intentional scope exclusions such as hidden paths, default-ignored directories, and `-exclude-dir` entries. These are disclosed in `skipped_paths` but do not by themselves mark the scan incomplete. Files that could not be inspected due to read errors, binary content, or the size limit do mark it incomplete.

## Safety and limitations

- Preflight does not modify scanned files or send their contents to a remote service.
- Matched secret values are not included in text, JSON, or SARIF findings.
- False positives and missed detections are possible. Encoded, split, dynamically generated, or unsupported credentials may not be detected.
- Unreadable, binary, and oversized files are reported explicitly and make the scan incomplete; an empty findings list does not override that status.
- Only scan directories you own or are authorized to inspect.
- If a real credential was committed, revoke or rotate it. Removing the current line alone does not remove it from Git history.

## Roadmap

1. Expand regression coverage for detection edge cases and false positives.
2. Add dependency and configuration-file scanners.
3. Add benchmarks and publish versioned cross-platform releases.


## License

No license file is present yet. Until a license is selected and added, do not assume the repository is licensed for reuse.
