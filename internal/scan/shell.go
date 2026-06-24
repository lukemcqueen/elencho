package scan

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
)

// ── curl | bash ───────────────────────────────────────────────────────────────

type ShellCurlPipeBashRule struct {
	BaseRule
	Config RuleConfig
}

var curlPipePat = regexp.MustCompile(`(?i)(curl|wget|http)\s+[^|]+\|\s*(bash|sh)\b`)
var pipeExts = []string{".sh", ".bash", ".zsh"}
var pipeFiles = []string{"Makefile", "Dockerfile"}

func (r *ShellCurlPipeBashRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, pipeExts) && !FilenameMatch(f, pipeFiles) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if curlPipePat.MatchString(line) {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Downloads and pipes to shell: " + strings.TrimSpace(line),
				})
			}
		}
	}
	return findings, nil
}

// Verify implements the Verifier interface for shell-curl-pipe-bash.
// Lowers confidence when the pattern is part of an intentional installer:
// version-pinned releases, or files named install/setup/bootstrap.
func (r *ShellCurlPipeBashRule) Verify(_ context.Context, _ string, finding *Finding, _ []Finding) error {
	// Version-pinned URLs from known distribution channels are likely intentional installers.
	// Matches github.com/org/repo/releases, /v1.2.3/, /releases/tag/ patterns.
	if strings.Contains(finding.Message, "releases/") ||
		strings.Contains(finding.Message, "releases/download/") ||
		versionTagPat.MatchString(finding.Message) {
		finding.Confidence = 0.5
		return nil
	}
	// Installer/setup/bootstrap scripts wrapping curl|bash are almost always intentional.
	if strings.Contains(finding.File, "install") ||
		strings.Contains(finding.File, "setup") ||
		strings.Contains(finding.File, "bootstrap") {
		finding.Confidence = 0.4
		return nil
	}
	return nil
}

// versionTagPat matches pinned version tags like /v1.2.3/ or /v1.2.3-alpha/ or /1.2.3/
var versionTagPat = regexp.MustCompile(`/v?\d+\.\d+\.\d+[^/]*/`)

// ── Base64 decode → pipe to shell ──────────────────────────────────────────────

type ShellBase64ExecRule struct {
	BaseRule
	Config RuleConfig
}

var base64ExecPats = []string{
	`base64\s*-d\s*<<<`,
	`base64\s*-d\s*\|\s*(bash|sh)\b`,
	`base64\s*-d\s*.+\|\s*(bash|sh)\b`,
	`base64\s*--decode\s*\|\s*(bash|sh)\b`,
	`python\s+-c\s*["']import\s+base64`,
	`perl\s+-e\s*["'].*decode_base64`,
}

var base64ExecCompiled = func() []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, p := range base64ExecPats {
		res = append(res, regexp.MustCompile(p))
	}
	return res
}()

func (r *ShellBase64ExecRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, pipeExts) && !FilenameMatch(f, pipeFiles) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			for _, pat := range base64ExecCompiled {
				if pat.MatchString(line) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Base64 decode piped to shell — likely staged payload: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── Shell history evasion ─────────────────────────────────────────────────────

type ShellHistoryEvasionRule struct {
	BaseRule
	Config RuleConfig
}

var historyEvasionPats = []string{
	"history -c",
	"history -w",
	"unset HISTFILE",
	"HISTFILE=/dev/null",
	"HISTSIZE=0",
	"HISTFILESIZE=0",
	"rm .*bash_history",
	"> ~/.bash_history",
	"cat /dev/null >.*bash_history",
}

func (r *ShellHistoryEvasionRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, pipeExts) && !FilenameMatch(f, pipeFiles) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			for _, pat := range historyEvasionPats {
				if strings.Contains(line, pat) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Shell history evasion: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── Reverse shell ─────────────────────────────────────────────────────────────

type ShellReverseShellRule struct {
	BaseRule
	Config RuleConfig
}

var reverseShellPats = []string{
	"/dev/tcp/",
	"bash -i >& /dev/tcp/",
	"bash -i >& /dev/udp/",
	"nc -e /bin/bash",
	"nc -e /bin/sh",
	"mkfifo",
	"exec .*<>/dev/tcp/",
}

func (r *ShellReverseShellRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, pipeExts) && !FilenameMatch(f, pipeFiles) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			for _, pat := range reverseShellPats {
				if !(strings.Contains(line, pat) || regexp.MustCompile(pat).MatchString(line)) {
					continue
				}
				// Context check: if the line is a TCP health check probe
				// (echo > /dev/tcp/... in a until/while/sleep/wait context),
				// it's not a reverse shell.
				if pat == "/dev/tcp/" && isHealthCheckProbe(lines, i) {
					continue
				}
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Possible reverse shell: " + strings.TrimSpace(line),
				})
				break
			}
		}
	}
	return findings, nil
}

// isHealthCheckProbe checks if a line containing /dev/tcp/ is a legitimate
// TCP connectivity probe rather than a reverse shell.
// Looks for tell-tale signs: echo/<> redirection, until/while loops,
// sleep/wait, timeout, 2>/dev/null, || true, health-check function context.
func isHealthCheckProbe(lines []string, lineIdx int) bool {
	line := lines[lineIdx]
	trimmed := strings.TrimSpace(line)

	// Must be a /dev/tcp line
	if !strings.Contains(trimmed, "/dev/tcp/") {
		return false
	}

	// If it's a full reverse shell (bash -i, exec), it's not a health check
	if strings.Contains(trimmed, "bash -i") || strings.Contains(trimmed, "exec ") {
		return false
	}

	// Pattern 1: echo > /dev/tcp/host/port
	if strings.HasPrefix(trimmed, "echo ") && strings.Contains(trimmed, "/dev/tcp/") {
		return true
	}

	// Pattern 2: /dev/tcp/ piped to || true (suppress errors — health check idiom)
	if strings.Contains(trimmed, "|| true") || strings.Contains(trimmed, "||:") {
		return true
	}

	// Pattern 3: cat < /dev/null > /dev/tcp/... or <>/dev/tcp/ (bash TCP connection probe)
	if strings.Contains(trimmed, "<> /dev/tcp/") || strings.Contains(trimmed, "<>/dev/tcp/") ||
		(strings.Contains(trimmed, "< /dev/null") && strings.Contains(trimmed, "/dev/tcp/")) {
		return true
	}

	// Check surrounding context (10 lines before for loop/function/timeout indicators)
	start := lineIdx - 10
	if start < 0 {
		start = 0
	}
	for _, ctxLine := range lines[start:lineIdx] {
		ctxTrimmed := strings.TrimSpace(ctxLine)
		if strings.HasPrefix(ctxTrimmed, "until ") ||
			strings.HasPrefix(ctxTrimmed, "while ") ||
			strings.Contains(ctxTrimmed, "sleep ") ||
			strings.Contains(ctxTrimmed, "wait ") ||
			strings.HasPrefix(ctxTrimmed, "timeout ") ||
			strings.Contains(ctxTrimmed, "function ") && (strings.Contains(ctxTrimmed, "wait_") || strings.Contains(ctxTrimmed, "health")) ||
			strings.Contains(ctxTrimmed, "=()") && (strings.Contains(ctxTrimmed, "wait_") || strings.Contains(ctxTrimmed, "health")) {
			// Verify the line is a probe, not a shell
			if strings.Contains(trimmed, "2>/dev/null") || strings.Contains(trimmed, "&>/dev/null") {
				return true
			}
		}
	}

	return false
}
