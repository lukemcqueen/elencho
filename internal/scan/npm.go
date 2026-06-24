package scan

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
)

// npmPostinstallDangerPatterns checks if a postinstall script contains dangerous commands.
var npmDownloadPats = []string{"curl", "wget", "fetch", "https://", "http://"}
var npmEvalPats = []string{"node -e", "node -r", "require(", "eval("}
var npmSuspiciousPats = []string{"curl", "wget", "chmod +x", "/dev/tcp", "bash -i", "nc -e", "stratum"}

// ── Postinstall downloads ──────────────────────────────────────────────────────

type NPMPostinstallDownloadRule struct {
	BaseRule
	Config RuleConfig
}

func (r *NPMPostinstallDownloadRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "package.json" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		// Parse package.json to find scripts
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal([]byte(data), &pkg); err != nil {
			continue
		}
		for scriptName, scriptCmd := range pkg.Scripts {
			if scriptName != "postinstall" && scriptName != "preinstall" && scriptName != "prepublish" {
				continue
			}
			for _, pat := range npmDownloadPats {
				if strings.Contains(scriptCmd, pat) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: 0,
						Message: "Dangerous postinstall script downloads or contacts remote: " + scriptCmd,
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── Postinstall eval ──────────────────────────────────────────────────────────

type NPMPostinstallEvalRule struct {
	BaseRule
	Config RuleConfig
}

func (r *NPMPostinstallEvalRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "package.json" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal([]byte(data), &pkg); err != nil {
			continue
		}
		for scriptName, scriptCmd := range pkg.Scripts {
			if scriptName != "postinstall" && scriptName != "preinstall" {
				continue
			}
			for _, pat := range npmEvalPats {
				if strings.Contains(scriptCmd, pat) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: 0,
						Message: "Postinstall runs inline code via node -e or require: " + scriptCmd,
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── Suspicious scripts ───────────────────────────────────────────────────────

type NpmSuspiciousScriptRule struct {
	BaseRule
	Config RuleConfig
}

func (r *NpmSuspiciousScriptRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "package.json" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal([]byte(data), &pkg); err != nil {
			continue
		}
		knownSafe := map[string]bool{"test": true, "start": true, "build": true, "dev": true,
			"lint": true, "format": true, "typecheck": true, "prettier": true, "eslint": true}
		for scriptName, scriptCmd := range pkg.Scripts {
			if knownSafe[scriptName] {
				continue
			}
			for _, pat := range npmSuspiciousPats {
				if strings.Contains(scriptCmd, pat) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: 0,
						Message: "Suspicious command in scripts: " + scriptCmd,
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── .npmrc hooks ──────────────────────────────────────────────────────────────

type NpmrcHookRule struct {
	BaseRule
	Config RuleConfig
}

func (r *NpmrcHookRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != ".npmrc" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		hookPats := []string{"postinstall", "preinstall", "scripts-prepend-node-path"}
		for i, line := range lines {
			for _, pat := range hookPats {
				if strings.HasPrefix(line, pat) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: ".npmrc contains script hook: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── Unpinned dependency versions ──────────────────────────────────────────────

type NpmUnpinnedDepRule struct {
	BaseRule
	Config RuleConfig
}

func (r *NpmUnpinnedDepRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "package.json" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal([]byte(data), &pkg); err != nil {
			continue
		}
		check := func(name, version string) {
			if version == "*" || version == "latest" || version == "" {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: 0,
					Message: "Unpinned dependency version (" + version + "): " + name,
				})
			}
		}
		for name, ver := range pkg.Dependencies {
			check(name, ver)
		}
		for name, ver := range pkg.DevDependencies {
			check(name, ver)
		}
	}
	return findings, nil
}

// ── Git dependencies ─────────────────────────────────────────────────────────

type NpmGitDependencyRule struct {
	BaseRule
	Config RuleConfig
}

func (r *NpmGitDependencyRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "package.json" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		gitDepsPat := []string{"git+https", "git+ssh", "github:"}
		for i, line := range lines {
			for _, pat := range gitDepsPat {
				if strings.Contains(line, pat) && strings.Contains(line, "\"") {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Unpinned git dependency: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}
