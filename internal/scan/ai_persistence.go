package scan

import (
	"context"
	"path/filepath"
	"strings"
)

// AiConfigPersistenceRule detects AI coding tool config files planted in
// source trees. The Miasma worm campaign (May-Jun 2026) planted files like
// .claude/settings.json, .cursor/rules/*.mdc, .gemini/settings.json, and
// .vscode/tasks.json to achieve persistence when developers open projects
// in AI coding assistants or editors.
//
// To minimize false positives, this rule is very specific about what it flags:
// - .vscode/tasks.json: only when "runOn" + "folderOpen" present (auto-run)
// - .claude/settings.json: only when "onSessionStart" or "shell:" present
// - .gemini/settings.json: only when "onSessionStart" or "command" present
// - .cursor/rules/: only when shell execution primitives present
type AiConfigPersistenceRule struct {
	BaseRule
	Config RuleConfig
}

type aiConfigPattern struct {
	fileSuffix string
	desc       string
}

var aiConfigPatterns = []aiConfigPattern{
	{".claude/settings.json", "Claude Code settings — can auto-execute on session start"},
	{".gemini/settings.json", "Gemini CLI settings — can auto-execute on session start"},
	{".cursor/rules/", "Cursor AI rules — auto-applied; can execute code"},
	{".vscode/tasks.json", "VS Code tasks — auto-run on folder open"},
	{".vscode/launch.json", "VS Code launch config — can execute programs"},
}

func (r *AiConfigPersistenceRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding

	for _, f := range files {
		var matched bool
		var patternDesc string
		for _, pat := range aiConfigPatterns {
			if strings.Contains(f, pat.fileSuffix) {
				matched = true
				patternDesc = pat.desc
				break
			}
		}
		if !matched {
			continue
		}

		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}

		if !hasDangerousContent(f, data) {
			continue
		}

		findings = append(findings, Finding{
			Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
			File: f, Line: 0,
			Message: "AI tool config file with auto-execution capability: " + filepath.Base(f) + " — " + patternDesc,
		})
	}

	return findings, nil
}

// hasDangerousContent checks for file-specific dangerous patterns.
// Each AI config type has its own criteria to minimize false positives.
func hasDangerousContent(filePath, content string) bool {
	lower := strings.ToLower(content)

	switch {
	case strings.Contains(filePath, ".vscode/tasks.json"):
		// VS Code tasks: flag only if "runOn" + "folderOpen" (auto-run on open)
		// OR type:"shell" with a download/exfiltration command
		hasRunOn := strings.Contains(lower, "runon") || strings.Contains(lower, "\"run\"")
		hasFolderOpen := strings.Contains(lower, "folderopen")
		hasDownload := strings.Contains(lower, "curl") || strings.Contains(lower, "wget") ||
			strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
		return (hasRunOn && hasFolderOpen) || (hasDownload && strings.Contains(lower, "\"shell\""))

	case strings.Contains(filePath, ".claude/settings.json"):
		// Claude Code: flag only if onSessionStart hooks or shell: prefixed commands
		return strings.Contains(lower, "onsessionstart") || strings.Contains(lower, "\"shell\":")

	case strings.Contains(filePath, ".gemini/settings.json"):
		// Gemini CLI: flag only if onSessionStart or explicit command with download
		return strings.Contains(lower, "onsessionstart") ||
			(strings.Contains(lower, "\"command\"") && strings.Contains(lower, "curl"))

	case strings.Contains(filePath, ".cursor/rules/"):
		// Cursor rules: flag only if explicit shell execution or download command
		return strings.Contains(lower, "exec") || strings.Contains(lower, "--command") ||
			strings.Contains(lower, "curl") || strings.Contains(lower, "bash")

	case strings.Contains(filePath, ".vscode/launch.json"):
		// VS Code launch: flag only if program points to a download or script
		return strings.Contains(lower, "curl") || strings.Contains(lower, "wget") ||
			strings.Contains(lower, "/tmp/") || strings.Contains(lower, ".pyz")

	default:
		return false
	}
}
