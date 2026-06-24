package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ── Binary in source tree ─────────────────────────────────────────────────────

type GitBinaryInSourceRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GitBinaryInSourceRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	// Check if we're in a git repo
	gitRoot, err := gitRevParse(scanRoot)
	if err != nil {
		return nil, nil // Not a git repo
	}

	// Get tracked files
	cmd := exec.Command("git", "-C", gitRoot, "ls-files")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	trackedFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
	binaryExts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".bmp": true, ".pdf": true, ".zip": true,
		".tgz": true, ".7z": true, ".rar": true,
	}

	sourceDirs := []string{"/src/", "/lib/", "/app/", "/bin/", "/scripts/"}

	for _, tf := range trackedFiles {
		if tf == "" {
			continue
		}
		ext := strings.ToLower(filepath.Ext(tf))
		if !binaryExts[ext] {
			continue
		}
		// Skip if it's in a known asset directory
		if strings.Contains(tf, "public/") || strings.Contains(tf, "static/") ||
			strings.Contains(tf, "images/") || strings.Contains(tf, "img/") ||
			strings.Contains(tf, "icon") || strings.Contains(tf, "logo") ||
			strings.Contains(tf, "favicon") || strings.Contains(tf, "screenshot") {
			continue
		}
		// Only flag if in source directories
		inSource := false
		for _, sd := range sourceDirs {
			if strings.Contains(tf, sd) {
				inSource = true
				break
			}
		}
		if !inSource {
			continue
		}

		fullPath := filepath.Join(gitRoot, tf)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		size := info.Size()
		findings = append(findings, Finding{
			Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
			File: tf, Line: 0,
			Message: "Binary file in source tree (" + humanSize(size) + ") — verify intent",
		})
	}
	return findings, nil
}

// ── .env in git history ───────────────────────────────────────────────────────

type GitEnvInHistoryRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GitEnvInHistoryRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	gitRoot, err := gitRevParse(scanRoot)
	if err != nil {
		return nil, nil
	}

	cmd := exec.Command("git", "-C", gitRoot, "log", "--diff-filter=A", "--name-only", "--pretty=format:")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	lines := strings.Split(string(output), "\n")
	seen := false
	for _, line := range lines {
		if strings.HasPrefix(line, ".env") && line != ".env.example" {
			seen = true
		}
	}
	if seen {
		return []Finding{{
			Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
			File: ".git", Line: 0,
			Message: "Files matching .env* have been committed in git history — secrets may be exposed",
		}}, nil
	}
	return nil, nil
}

// ── Large recent additions ────────────────────────────────────────────────────

type GitLargeRecentAddRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GitLargeRecentAddRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	gitRoot, err := gitRevParse(scanRoot)
	if err != nil {
		return nil, nil
	}

	// Get files added in the last 5 commits
	cmd := exec.Command("git", "-C", gitRoot, "diff", "--name-only", "--diff-filter=A", "HEAD~5..HEAD")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var findings []Finding
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fullPath := filepath.Join(gitRoot, line)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		if info.Size() > 1048576 { // 1MB
			findings = append(findings, Finding{
				Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
				File: line, Line: 0,
				Message: "Large file added in recent commits: " + humanSize(info.Size()),
			})
		}
	}
	return findings, nil
}

// ── Suspicious git hooks ─────────────────────────────────────────────────────

type GitHookSuspiciousRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GitHookSuspiciousRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	gitRoot, err := gitRevParse(scanRoot)
	if err != nil {
		return nil, nil
	}

	hooksDir := filepath.Join(gitRoot, ".git", "hooks")
	hookEntries, err := os.ReadDir(hooksDir)
	if err != nil {
		return nil, nil
	}

	var findings []Finding
	for _, entry := range hookEntries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".sample") {
			continue
		}
		hookPath := filepath.Join(hooksDir, entry.Name())

		// Check if executable
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&0111 == 0 {
			continue // Not executable
		}

		// Read first 50 lines for suspicious content
		data, err := ReadFile(hookPath)
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		checkLen := len(lines)
		if checkLen > 50 {
			checkLen = 50
		}
		for _, line := range lines[:checkLen] {
			if strings.Contains(line, "curl") || strings.Contains(line, "wget") ||
				strings.Contains(line, "/dev/tcp") || strings.Contains(line, "bash -i") {
				relPath, _ := filepath.Rel(scanRoot, hookPath)
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: relPath, Line: 0,
					Message: "Git hook contains network or shell execution: " + relPath,
				})
				break
			}
		}
	}
	return findings, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func gitRevParse(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func humanSize(bytes int64) string {
	if bytes >= 1048576 {
		return fmt.Sprintf("%dMB", bytes/1048576)
	} else if bytes >= 1024 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}
