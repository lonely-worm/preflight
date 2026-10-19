# Security Policy

## Supported Versions

Preflight is currently pre-1.0. Security fixes are made against the latest code on `main`; there are no versioned releases yet.

## Reporting a Vulnerability

Please do not publish live credentials, private keys, or exploitable vulnerability details in a public issue.

If GitHub Private Vulnerability Reporting is enabled for this repository, use the repository's **Security → Report a vulnerability** flow. Otherwise, contact the repository owner privately through GitHub before public disclosure. Include a concise impact description and safe reproduction steps; redact real credentials and private customer data.

The maintainers will acknowledge reports on a best-effort basis. No response-time SLA is currently offered.

## Scope and Limitations

Preflight uses pattern-based secret detection and heuristic configuration checks. A clean report does not prove that a repository is secure. It currently scans the working tree rather than Git history, and the optional Go dependency scan requires `govulncheck` plus network access to the Go vulnerability database.

For an actual leaked credential, revoke or rotate it immediately and remove it from affected systems and history as appropriate; do not rely on scanner output alone.
