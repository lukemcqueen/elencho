package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed rules/known-malicious.yaml
var knownMaliciousData []byte

// MaliciousPackage describes a known-malicious package entry.
type MaliciousPackage struct {
	Name       string `yaml:"name" json:"name"`
	Ecosystem  string `yaml:"ecosystem" json:"ecosystem"`
	Versions   []string `yaml:"versions" json:"versions,omitempty"`
	AliasOf    string `yaml:"alias_of" json:"alias_of,omitempty"`
	Notes      string `yaml:"notes" json:"notes"`
	Discovered string `yaml:"discovered" json:"discovered,omitempty"`
}

// maliciousFile wraps the YAML structure.
type maliciousFile struct {
	Version  int               `yaml:"version"`
	Packages []MaliciousPackage `yaml:"packages"`
}

// knownMaliciousPackages is the parsed blocklist, populated at init.
var npmMalicious, pypiMalicious, goMalicious map[string]MaliciousPackage

func init() {
	loadMalicious(knownMaliciousData)

	// Try to load updated blocklist from update directory
	if updateDir, err := updateDir(); err == nil {
		overlayPath := filepath.Join(updateDir, "rules", "known-malicious.yaml")
		if data, err := os.ReadFile(overlayPath); err == nil {
			loadMalicious(data)
		}
	}
}

// loadMalicious populates the malicious package maps from YAML data.
func loadMalicious(data []byte) {
	if npmMalicious == nil {
		npmMalicious = make(map[string]MaliciousPackage)
		pypiMalicious = make(map[string]MaliciousPackage)
		goMalicious = make(map[string]MaliciousPackage)
	}
	var file maliciousFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return
	}
	for _, p := range file.Packages {
		switch p.Ecosystem {
		case "npm":
			npmMalicious[p.Name] = p
		case "pypi":
			pypiMalicious[p.Name] = p
		case "go":
			goMalicious[p.Name] = p
		}
	}
}

// updateDir returns the path to the update overlay directory.
func updateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "elencho", "rules"), nil
}

// KnownMaliciousNpmRule checks package.json dependencies against npm blocklist.
type KnownMaliciousNpmRule struct {
	BaseRule
	Config RuleConfig
}

// KnownMaliciousPyPiRule checks requirements.txt / pyproject.toml against PyPI blocklist.
type KnownMaliciousPyPiRule struct {
	BaseRule
	Config RuleConfig
}

// KnownMaliciousGoRule checks go.mod against Go module blocklist.
type KnownMaliciousGoRule struct {
	BaseRule
	Config RuleConfig
}

// KnownMaliciousNpmRule — checks package.json dependencies against npm blocklist.
func (r *KnownMaliciousNpmRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
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
		for name := range pkg.Dependencies {
			if mp, ok := npmMalicious[name]; ok {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: 0,
					Message: "Known malicious npm package: " + name + " — " + mp.Notes,
				})
			}
		}
		for name := range pkg.DevDependencies {
			if mp, ok := npmMalicious[name]; ok {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: 0,
					Message: "Known malicious npm package (dev): " + name + " — " + mp.Notes,
				})
			}
		}
	}
	return findings, nil
}

// KnownMaliciousPyPiRule — checks requirements.txt / pyproject.toml against PyPI blocklist.
func (r *KnownMaliciousPyPiRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		base := filepath.Base(f)
		if base != "requirements.txt" && base != "pyproject.toml" && !strings.HasPrefix(base, "requirements") {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "[") {
				continue
			}
			// Extract package name before any version specifier
			name := line
			for _, sep := range []string{"==", ">=", "<=", ">", "<", "~=", "!="} {
				if idx := strings.Index(name, sep); idx >= 0 {
					name = strings.TrimSpace(name[:idx])
					break
				}
			}
			// Handle extras like package[extra]
			if idx := strings.Index(name, "["); idx >= 0 {
				name = name[:idx]
			}
			name = strings.ToLower(name)
			if mp, ok := pypiMalicious[name]; ok {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Known malicious PyPI package: " + name + " — " + mp.Notes,
				})
			}
		}
	}
	return findings, nil
}

// KnownMaliciousGoRule — checks go.mod against Go module blocklist.
func (r *KnownMaliciousGoRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "go.mod" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require ") {
				continue
			}
			// Match lines with module paths like "github.com/some/module v1.0.0"
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasPrefix(fields[0], "github.com/") {
				mod := fields[0]
				if mp, ok := goMalicious[mod]; ok {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Known malicious Go module: " + mod + " — " + mp.Notes,
					})
				}
			}
		}
	}
	return findings, nil
}
