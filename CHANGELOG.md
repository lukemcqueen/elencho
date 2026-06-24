# Changelog

## v0.2.0 — 2026-06-24

- **36 detection rules** (up from 30) — 6 new rules
- **3 new CRITICAL rules**: trojan-source, known-malicious-npm, known-malicious-pypi, known-malicious-go
- **3 new MEDIUM rules**: dockerfile-suspect, actions-suspect
- **Inline suppression** — `elencho:ignore rule-id` comments in source files
- **Remediation suggestions** — every finding includes a fix + optional command
- **Threat intel blocklist** — 20 known-malicious packages, auto-updatable via signed manifests
- **Auto-update default-on** — Ed25519-signed, opt out with `--no-auto-update`
- **Noise reduction** — `.next`, `dist`, `build`, `target`, `tmp/cache` excluded by default
- **Compact output** — grouped findings, severity summary, LOW hidden unless `-v`
- **Ecosystem comparison** in README — Trivy, Semgrep, Gitleaks, TruffleHog, etc.
- **Better naming** — `dockerfile-suspect` not `dockerfile-dangerous` (MEDIUM)

## v0.1.0 — Initial release

- **30 detection rules** across 7 categories — shell, npm, Python, git, generic, gitignore abuse, secrets
- **Multiple output formats** — text (human), JSON (machines), SARIF 2.1 (CI tools)
- **Ed25519-signed updates** — rule definitions verified by embedded public key
- **Zero false positives** — proven against clean directories
- **Exclusion system** — built-in (`.git`, `node_modules`, etc.), `.elencho-ignore` file, CLI `-e` flags, strict mode
- **Self-contained binary** — all rules embedded via `//go:embed`, no runtime dependencies
- **Cross-platform builds** — Linux amd64/arm64, macOS amd64/arm64, Windows amd64
- **CI/CD pipeline** — GitHub Actions: test → lint → cross-compile → release
- **Homebrew tap** — `brew install lukemcqueen/elencho/elencho`
