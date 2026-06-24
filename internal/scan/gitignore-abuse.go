package scan

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

// ── Ignored files present on disk ─────────────────────────────────────────────

type GitIgnoredFilePresentRule struct {
	BaseRule
	Config RuleConfig
}

var safeIgnored = []string{
	".DS_Store", "Thumbs.db", "*.log", "*.tmp", "*.swp", "*.swo",
	"*.pyc", "__pycache__/", "*.egg-info/",
	".terraform/", "*.tfstate", "terraform.tfvars",
	"node_modules/", "vendor/bundle/",
	".next/", "dist/", "build/", "target/", "*.tsbuildinfo",
}

func (r *GitIgnoredFilePresentRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	gitRoot, err := gitRevParse(scanRoot)
	if err != nil {
		return nil, nil
	}

	cmd := exec.Command("git", "-C", gitRoot, "ls-files", "--others", "--ignored", "--exclude-standard")
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
		// Skip common safe artifacts
		skip := false
		for _, safe := range safeIgnored {
			if strings.HasPrefix(safe, "*") {
				if strings.HasSuffix(line, strings.TrimPrefix(safe, "*")) {
					skip = true
					break
				}
			} else if strings.HasSuffix(safe, "/") {
				if strings.HasPrefix(line, safe) {
					skip = true
					break
				}
			} else if line == safe {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Only report files within the target scan directory
		fullPath := filepath.Join(gitRoot, line)
		rel, err := filepath.Rel(scanRoot, fullPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}

		findings = append(findings, Finding{
			Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
			File: line, Line: 0,
			Message: "File present on disk but .gitignore'd — potential hiding place for malware",
		})
	}
	return findings, nil
}

// ── Dockerignore mismatch ────────────────────────────────────────────────────

type DockerignoreMismatchRule struct {
	BaseRule
	Config RuleConfig
}

func (r *DockerignoreMismatchRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	gitRoot, err := gitRevParse(scanRoot)
	if err != nil {
		return nil, nil
	}

	gitIgnorePath := filepath.Join(gitRoot, ".gitignore")
	dockerIgnorePath := filepath.Join(gitRoot, ".dockerignore")

	if !FileExists(gitIgnorePath) || !FileExists(dockerIgnorePath) {
		return nil, nil
	}

	// Read both files
	gitData, _ := ReadFile(gitIgnorePath)
	dockerData, _ := ReadFile(dockerIgnorePath)

	gitPatterns := parseIgnorePatterns(gitData)
	dockerPatterns := parseIgnorePatterns(dockerData)

	// Find patterns in .dockerignore but not in .gitignore
	dockerOnly := make(map[string]bool)
	for _, dp := range dockerPatterns {
		if !patternExists(dp, gitPatterns) {
			dockerOnly[dp] = true
		}
	}

	var findings []Finding
	for pat := range dockerOnly {
		findings = append(findings, Finding{
			Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
			File: ".dockerignore", Line: 0,
			Message: "Pattern in .dockerignore but not in .gitignore: " + pat,
		})
	}
	return findings, nil
}

func parseIgnorePatterns(content string) []string {
	var patterns []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

func patternExists(pat string, patterns []string) bool {
	for _, p := range patterns {
		if p == pat {
			return true
		}
	}
	return false
}
