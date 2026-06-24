package scan

import (
	"context"
	"path/filepath"
	"strings"
)

// ── Trojan Source (bidirectional Unicode) ────────────────────────────────────

type GenericTrojanSourceRule struct {
	BaseRule
	Config RuleConfig
}

// bidiOverrideBytes are Unicode control characters used in trojan-source attacks.
// These override text directionality, making code appear different from reality.
var bidiOverrideBytes = [][]byte{
	{0xE2, 0x80, 0xAE}, // U+202E RIGHT-TO-LEFT OVERRIDE
	{0xE2, 0x80, 0xAD}, // U+202D LEFT-TO-RIGHT OVERRIDE
	{0xE2, 0x81, 0xA6}, // U+2066 LEFT-TO-RIGHT ISOLATE
	{0xE2, 0x81, 0xA7}, // U+2067 RIGHT-TO-LEFT ISOLATE
	{0xE2, 0x81, 0xA8}, // U+2068 FIRST STRONG ISOLATE
	{0xE2, 0x81, 0xA9}, // U+2069 POP DIRECTIONAL ISOLATE
	{0xE2, 0x80, 0xAC}, // U+202C POP DIRECTIONAL FORMATTING
}

func (r *GenericTrojanSourceRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		// Scan all text files
		if ext == ".png" || ext == ".jpg" || ext == ".gif" || ext == ".ico" || ext == ".zip" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		for _, bidi := range bidiOverrideBytes {
			if !containsBytes([]byte(data), bidi) {
				continue
			}
			lines := strings.Split(data, "\n")
			for i, line := range lines {
				if containsBytes([]byte(line), bidi) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Bidirectional Unicode override character detected — trojan-source attack possible (CVE-2021-42574)",
					})
					break // one finding per file is enough
				}
			}
			break
		}
	}
	return findings, nil
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ── Dockerfile dangerous patterns ─────────────────────────────────────────────

type DockerfileDangerousRule struct {
	BaseRule
	Config RuleConfig
}

var dockerfileDangerPats = []struct {
	pattern string
	desc    string
}{
	{"ADD --chmod", "ADD with chmod can introduce executable malware"},
	{"ADD http", "ADD from URL downloads unverified content into image"},
	{"USER root", "Container runs as root — privilege escalation risk"},
	{"curl | bash", "Downloads and pipes to shell during build"},
	{"curl | sh", "Downloads and pipes to shell during build"},
	{"pip install", "pip install in Dockerfile — version pinning recommended"},
	{"npm install", "npm install in Dockerfile — versions not pinned"},
	{"wget -O- | bash", "Downloads and pipes to shell during build"},
}

func (r *DockerfileDangerousRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "Dockerfile" && !strings.HasSuffix(f, ".dockerfile") {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			for _, p := range dockerfileDangerPats {
				matched := strings.Contains(line, p.pattern)
				// Special handling: "curl | bash" also matches "curl <url> | bash"
				if !matched && (p.pattern == "curl | bash" || p.pattern == "curl | sh") {
					matched = matchesCurlPipe(line, p.pattern)
				}
				if !matched {
					continue
				}
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: p.desc + ": " + strings.TrimSpace(line),
				})
				break
			}
		}
	}
	return findings, nil
}

func matchesCurlPipe(line, target string) bool {
	// Match "curl <anything> | bash" or "curl <anything> | sh"
	// where target is "curl | bash" or "curl | sh"
	pipePart := strings.TrimPrefix(target, "curl ")
	return strings.Contains(line, "curl") && strings.Contains(line, pipePart)
}

// ── GitHub Actions abuse ─────────────────────────────────────────────────────

type ActionsDangerousRule struct {
	BaseRule
	Config RuleConfig
}

var actionsDangerPats = []struct {
	pattern string
	desc    string
}{
	{"curl | bash", "Workflow downloads and executes remote code"},
	{"curl | sh", "Workflow downloads and executes remote code"},
	{"wget -O- | bash", "Workflow downloads and executes remote code"},
	{"run: |", "Multi-line shell execution — verify content"},
	{"GITHUB_TOKEN", "Workflow leaks GITHUB_TOKEN via script"},
	{"actions-ecosystem/", "Third-party action from ecosystem org — verify"},
	{"peaceiris/", "Third-party action — verify publisher"},
	{"docker://", "Action uses Docker container — verify image source"},
	{"uses: docker://", "Action uses Docker container — verify image source"},
}

func (r *ActionsDangerousRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !strings.Contains(f, ".github/workflows/") {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			for _, p := range actionsDangerPats {
				if strings.Contains(line, p.pattern) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: p.desc + ": " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}
