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
				if strings.Contains(line, pat) || regexp.MustCompile(pat).MatchString(line) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Possible reverse shell: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}
