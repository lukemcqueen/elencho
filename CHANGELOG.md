# Changelog

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
