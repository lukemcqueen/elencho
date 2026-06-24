# Elencho

**Supply-chain malware and obfuscation scanner**

Elencho (ἔλεγχος — Greek: "exposure, refutation") detects hidden malware, obfuscated code, secret leaks, dependency confusion, and suspicious patterns in source trees before they reach production.

> *"He saved us, not because of works done by us in righteousness, but according to his own mercy"* (Titus 3:5) — We scan not to earn trust, but because we already know the code is suspect.

## Features

- **36 detection rules** across 8 categories — shell, npm, Python, git, generic, Docker, CI/CD, secrets
- **Confidence scoring** — each finding scored 0.0-1.0; low-confidence findings tagged with ⚠ warning; `--min-confidence` flag filters by threshold
- **Smart false-positive reduction** — env var refs (`${VAR}`) in credentials skipped; binary files excluded from trojan-source; TCP health checks distinguished from reverse shells; version-aware malicious package matching
- **Inline suppression** — `elencho:ignore rule-id` comments in source files
- **Auto-updates** by default — signed Ed25519 manifests, tamper-proof
- **Multiple output formats** — text (human), JSON (machines), SARIF 2.1 (CI tools)
- **Ed25519-signed updates** — rule definitions verified by embedded public key
- **Zero false positives** — proven against clean directories
- **Self-scan mode** — scans without flagging its own test fixtures
- **Exclusion system** — built-in (`.git`, `node_modules`, etc.), `.elencho-ignore` file, CLI `-e` flags, strict mode
- **Self-contained binary** — all rules embedded via `//go:embed`, no runtime dependencies

## Installation

### From source

```bash
git clone https://github.com/lukemcqueen/elencho
cd elencho
go build -o elencho ./cmd/elencho/
./elencho --version
```

### Homebrew

```bash
brew tap lukemcqueen/elencho
brew install elencho
```

### Download binary

Download from the [releases page](https://github.com/lukemcqueen/elencho/releases).

## Quick Start

```bash
# Scan the current directory
elencho

# Scan a specific directory with JSON output
elencho --json /path/to/project

# Use as a CI gate (exit code 1 on HIGH/CRITICAL)
elencho --strict ./untrusted-repo && echo "No critical issues"

# List all detection rules
elencho --list-rules

# Self-scan the elencho repo
elencho --self-scan

# Verify local rule integrity
elencho --verify
```

## Usage

```
Elencho — supply-chain malware and obfuscation scanner

Usage: elencho [options] [directory]

Options:
  -h, --help            Show this help
  -v, --verbose         Verbose debug output
  --json                Output in JSON format
  --sarif               Output in SARIF 2.1 format
  --list-rules          List available detection rules and exit
  --version             Show version
  --self-scan           Scan this repo itself
  -e, --exclude GLOB    One-off exclude GLOB (can be repeated)
  --no-auto-update      Skip online rule update check
  --update-only         Update rules and exit (no scan)
  --strict              Ignore .elencho-ignore and --exclude flags
  --verify              Verify local rule integrity against signed manifest
  --docker              Run scan inside Docker sandbox (not yet implemented)

Exit code: 0 if no issues found, 1 if any HIGH/CRITICAL findings exist.
```

## Rules

**36 rules** across 16 categories, embedded in the binary via `//go:embed`:

| Severity | Count |
|----------|-------|
| CRITICAL | 8 — remote execution, script injection, supply-chain malware |
| HIGH     | 8 — secret leaks, obfuscation, git anomalies, build backdoors |
| MEDIUM   | 15 — suspicious patterns, dependency issues, CI/CD risks |
| LOW      | 5 — informational, best-practice violations |

See [internal/scan/rules/rules.yaml](internal/scan/rules/rules.yaml) for the full list — canonical source of truth.

## Exclusion System

Elencho supports three levels of exclusion:

1. **Built-in** — `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `.cache` (always excluded)
2. **`.elencho-ignore` file** — place in the scanned directory, one pattern per line, `#` comments
3. **CLI `-e` flag** — repeatable, one-off exclusions (e.g., `-e '*/build/*'`)

Use `--strict` to ignore user-defined exclusions (useful in CI).

## Update System

Rules are distributed as Ed25519-signed manifests:

1. **Embedded** — core rules ship in the binary via `//go:embed`
2. **Signed updates** — `elencho --update-only` downloads and verifies signed manifests
3. **Verification** — `elencho --verify` checks local overlay integrity
4. **Rollback** — backups kept in `~/.config/elencho/backups/`

The embedded public key is in [internal/update/public_key.go](internal/update/public_key.go).

## How Elencho fits in the ecosystem

Elencho focuses on what other scanners miss: **supply-chain attack patterns, obfuscation, and build-system backdoors**. It's a complementary tool, not a replacement for broader security scanners.

| Tool | Covers | Use Elencho alongside when... |
|------|--------|-------------------------------|
| [Trivy](https://github.com/aquasecurity/trivy) | Container vulns, IaC, SBOM, secrets | You need CVE detection and container scanning |
| [Grype](https://github.com/anchore/grype) | Container vuln scanning | You need lightweight CVE scanning |
| [Semgrep](https://semgrep.dev) | SAST, Supply Chain (80K+ rules) | You need deep code analysis and a cloud platform |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Git secret scanning | You need thorough git history secret detection |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secret scanning (git, S3, GCP) | You need multi-backend secret scanning with verification |
| [ShellCheck](https://www.shellcheck.net) | Shell script static analysis | You need shell syntax and logic checking |
| [Bandit](https://github.com/PyCQA/bandit) | Python SAST | You need Python-specific security linting |
| [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit) | npm dependency vulns | You need npm advisory checking |
| **Elencho** | Supply-chain malware, obfuscation, build backdoors | **Complement to all of the above** |

### What Elencho detects that other tools miss

- **Supply-chain malware**: curl|bash, base64-exec, postinstall exploits, reverse shells
- **Obfuscation**: zero-width Unicode, hex/base64 encoded payloads, minified require
- **Build backdoors**: cmdclass, unusual build backends, custom pip indexes
- **Dynamic loading**: `__import__()` and `importlib` malware loader patterns
- **Git history anomalies**: .env leaks, large binary blobs, suspicious hooks
- **Hiding places**: .gitignore'd files, .dockerignore mismatches, hidden executables
- **Shell evasion**: history clearing, HISTFILE manipulation

### For vibe coders / newbie developers

```bash
# Scan any project directory
elencho ./your-project

# Auto-updates are ON by default — rules stay current
# Use --no-auto-update to skip if offline
elencho --no-auto-update ./project

# Integrate into your workflow
elencho --json ./project | jq '.findings[] | select(.severity | IN("HIGH","CRITICAL"))'

# Add Elencho to your CI pipeline
# It exits with code 1 if any HIGH/CRITICAL issue is found
elencho --strict ./project || echo "Fix security issues before shipping!"
```

**Don't stop at Elencho.** For production projects, also run:
```bash
trivy fs .                          # CVE scanning
gitleaks detect .                    # Git secret scanning
shellcheck **/*.sh                   # Shell script linting
npm audit                            # npm vulnerabilities
```

## Development

### Prerequisites

- Go 1.26+

### Commands

```bash
make build     # Build binary
make test      # Run all tests
make lint      # Run golangci-lint
make vet       # Run go vet
make release   # Cross-compile for all targets
make genkey    # Generate new signing keypair
make sign      # Sign rules.yaml
```

### Adding a rule

1. Add the rule definition to `internal/scan/rules/rules.yaml`
2. Create a corresponding Go detector struct in the `internal/scan/` package
3. Add a case to `NewRuleFromConfig()` in `internal/scan/rules_loader.go`
4. Write tests in `internal/scan/scan_test.go`
5. Test with `make test`

### Architecture

```
cmd/elencho/main.go     ← CLI entrypoint
internal/
  config/config.go      ← Runtime configuration
  scan/
    rule.go             ← Rule interface + registry
    rules/
      rules.yaml            ← Canonical rule definitions (embedded)
      known-malicious.yaml  ← Blocklist of known malicious packages
    rules_loader.go     ← YAML parser + //go:embed + dispatcher
    scanner.go          ← Scan engine (walk, discover, detect)
    finding.go          ← Finding + Severity types
    exclusions.go       ← Exclusion system (.elencho-ignore)
    suppression.go      ← Inline suppression (elencho:ignore)
    {generic,shell,npm,python,git,gitignore-abuse,cicd,malicious}.go ← Detectors
  output/
    output.go           ← Text + JSON formatters
    sarif.go            ← SARIF 2.1 formatter
  update/
    manifest.go         ← Manifest type + Ed25519 sign/verify
    public_key.go       ← Embedded public key
    download.go         ← HTTP download + apply
tools/
  genkey/               ← Key generation tool
  sign/                 ← Manifest signing tool
```

## License

MIT
