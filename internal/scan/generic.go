package scan

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ── Zero-width Unicode characters ──────────────────────────────────────────────

type GenericZeroWidthUnicodeRule struct {
	BaseRule
	Config RuleConfig
}

var zeroWidthBytes = [][]byte{
	{0xE2, 0x80, 0x8B}, // U+200B ZERO WIDTH SPACE
	{0xE2, 0x80, 0x8C}, // U+200C ZERO WIDTH NON-JOINER
	{0xE2, 0x80, 0x8D}, // U+200D ZERO WIDTH JOINER
	{0xE2, 0x80, 0x8E}, // U+200E LEFT-TO-RIGHT MARK
	{0xE2, 0x80, 0x8F}, // U+200F RIGHT-TO-LEFT MARK
	{0xEF, 0xBB, 0xBF}, // U+FEFF BOM
}

var zeroWidthExts = []string{".js", ".ts", ".py", ".rb", ".go", ".rs", ".sh", ".bash", ".php", ".java", ".swift"}

func (r *GenericZeroWidthUnicodeRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, zeroWidthExts) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		for _, zwb := range zeroWidthBytes {
			if bytes.Contains([]byte(data), zwb) {
				// Find which line
				lines := strings.Split(data, "\n")
				for i, line := range lines {
					if bytes.Contains([]byte(line), zwb) {
						findings = append(findings, Finding{
							Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
							File: f, Line: i + 1,
							Message: "Zero-width Unicode character detected — possible obfuscation",
						})
					}
				}
			}
		}
	}
	return findings, nil
}

// ── Long base64 strings ───────────────────────────────────────────────────────

type GenericLongBase64Rule struct {
	BaseRule
	Config RuleConfig
}

var base64LongPat = regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,2}`)

func (r *GenericLongBase64Rule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	extensions := []string{".js", ".ts", ".py", ".sh", ".rb"}
	for _, f := range files {
		if !HasExtension(f, extensions) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if strings.Contains(line, "data:image") || strings.Contains(line, "base64,") ||
				strings.Contains(line, "font-awesome") || strings.Contains(line, "glyphicon") {
				continue
			}
			if base64LongPat.MatchString(line) {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Unusually long base64 string — verify it's not encoded payload",
				})
			}
		}
	}
	return findings, nil
}

// ── Obfuscated eval/exec ──────────────────────────────────────────────────────

type GenericObfuscatedEvalRule struct {
	BaseRule
	Config RuleConfig
}

var obfuscatedEvalPat = regexp.MustCompile(`(eval|exec)\s*\(\s*(atob|btoa|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode|require\("child_process"\)\.exec)`)

func (r *GenericObfuscatedEvalRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, []string{".js", ".ts"}) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if obfuscatedEvalPat.MatchString(line) {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Obfuscated eval/exec — likely hidden code execution",
				})
			}
		}
	}
	return findings, nil
}

// ── Minified require detection ────────────────────────────────────────────────

type GenericMinifiedRequireRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GenericMinifiedRequireRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, []string{".js"}) {
			continue
		}
		// Check if it's minified: few lines, many characters
		info, err := filepath.Glob(filepath.Join(scanRoot, f))
		if err != nil || len(info) == 0 {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		if len(lines) >= 5 {
			continue // Not minified
		}
		if len(data) <= 500 {
			continue // Not large enough
		}
		// Look for local requires
		for i, line := range lines {
			if strings.Contains(line, "require(") &&
				!strings.Contains(line, "react") && !strings.Contains(line, "lodash") &&
				!strings.Contains(line, "express") && !strings.Contains(line, "axios") &&
				!strings.Contains(line, "chalk") && !strings.Contains(line, "fs") &&
				!strings.Contains(line, "path") {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Minified file with local requires — verify it's legitimate",
				})
			}
		}
	}
	return findings, nil
}

// ── Hardcoded credentials ─────────────────────────────────────────────────────

type GenericHardcodedSecretRule struct {
	BaseRule
	Config RuleConfig
}

var credPat = regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|password|passwd|pwd|token)\s*[:=]\s*["']([^"']+)`)

var credSkipWords = []string{"placeholder", "your-", "<YOUR", "your-api", "example", "changeme", "test_", "xxxx", "fake", "dummy", "staging", "demo", "${", "$(", "todo", "fixme", "sample", "template", "default", "changethis", "change_me", "not_a_real", "not_real", "my_", "your_", "tbd", "TBD", "xxx", "REPLACE", "replace_", "replace-"}

var credExts = []string{".js", ".ts", ".py", ".rb", ".go", ".yml", ".yaml", ".json"}

func (r *GenericHardcodedSecretRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, credExts) {
			continue
		}
		// Skip lock files and test files
		base := filepath.Base(f)
		if base == "package-lock.json" || base == "yarn.lock" || base == "pnpm-lock.yaml" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if strings.Contains(line, "process.env") || strings.Contains(line, "os.getenv") ||
				strings.Contains(line, "environ.get") || strings.Contains(line, "config.get") ||
				strings.Contains(line, ".env.") || strings.Contains(line, "settings.") {
				continue
			}
			matches := credPat.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			// Check if value is a placeholder
			val := matches[2]
			skip := false
			for _, skipWord := range credSkipWords {
				if strings.Contains(strings.ToLower(val), skipWord) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			// Skip if value is short (likely a config key, not a secret)
			if len(val) < 8 {
				continue
			}
			finding := Finding{
				Severity:   r.Sev,
				Category:   r.Cat,
				RuleID:     r.RuleID,
				File:       f,
				Line:       i + 1,
				Message:    fmt.Sprintf("Possible hardcoded credential: %s", matches[1]),
				Confidence: 1.0,
			}
			// Apply verifier inline for efficiency
			verifyHardcodedSecret(&finding, lines, i, f)
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// verifyHardcodedSecret adjusts confidence for hardcoded secret findings.
// Lowers confidence when the value is an env var reference or the file is a fixture.
func verifyHardcodedSecret(f *Finding, allLines []string, lineIdx int, filePath string) {
	// Check if file is in test/fixture/spec/seed directories (both leading / and relative)
	testDir := func(dir string) bool {
		return strings.HasPrefix(filePath, dir+"/") || strings.Contains(filePath, "/"+dir+"/")
	}
	if testDir("test") || testDir("spec") || testDir("fixtures") ||
		testDir("mock") || testDir("example") || testDir("seed") || testDir("seeds") ||
		strings.Contains(filePath, "docker-compose") {
		f.Confidence = 0.2
		return
	}
	// Lower confidence for minified or built JS bundles, vendor/third-party, archive dirs
	if strings.HasSuffix(filePath, ".min.js") ||
		strings.Contains(filePath, "/assets/") ||
		strings.Contains(filePath, "/public/assets/") ||
		testDir("dist") || testDir("build") || testDir("vendor") ||
		strings.Contains(filePath, "/_archive") ||
		strings.Contains(filePath, "node_modules/") {
		f.Confidence = 0.3
		return
	}
	// Check surrounding lines for env var or config patterns
	start := lineIdx - 3
	if start < 0 {
		start = 0
	}
	for _, ctxLine := range allLines[start:lineIdx] {
		trimmed := strings.TrimSpace(ctxLine)
		if strings.Contains(trimmed, "${") || strings.Contains(trimmed, "$(") ||
			strings.Contains(trimmed, "process.env") || strings.Contains(trimmed, ".env.") {
			f.Confidence = 0.3
			return
		}
	}
}

// ── .gitattributes filter/smudge ──────────────────────────────────────────────

type GenericGitAttributesRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GenericGitAttributesRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	gaPath := filepath.Join(scanRoot, ".gitattributes")
	data, err := ReadFile(gaPath)
	if err != nil {
		return nil, nil // File doesn't exist — skip
	}
	lines := strings.Split(data, "\n")
	gaPat := regexp.MustCompile(`(?i)(filter|smudge|clean|diff=)`)

	// Known benign patterns — standard git attributes that are not security threats
	benignPatterns := []string{
		"* text=auto",
		"* text eol=lf",
		"* text eol=crlf",
		"*.png binary",
		"*.jpg binary",
		"*.jpeg binary",
		"*.gif binary",
		"*.ico binary",
		"*.pdf binary",
		"*.zip binary",
		"*.jar binary",
		"*.woff binary",
		"*.ttf binary",
		"*.eot binary",
		"*.svg binary",
		"*.webp binary",
		"linguist-generated",
		"linguist-vendored",
		"linguist-documentation",
		"export-ignore",
	}
	isBenign := func(line string) bool {
		trimmed := strings.TrimSpace(line)
		for _, bp := range benignPatterns {
			if strings.Contains(trimmed, bp) {
				return true
			}
		}
		return false
	}

	for i, line := range lines {
		if gaPat.MatchString(line) && !isBenign(line) {
			findings = append(findings, Finding{
				Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
				File: ".gitattributes", Line: i + 1,
				Message: "Git filter/smudge defined — can auto-transform files on checkout",
			})
		}
	}
	return findings, nil
}

// ── Long hex-encoded payloads ──────────────────────────────────────────────────

type GenericHexEncodedRule struct {
	BaseRule
	Config RuleConfig
}

var hexLongPat = regexp.MustCompile(`[0-9a-fA-F]{100,}`)

func (r *GenericHexEncodedRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	extensions := []string{".js", ".ts", ".py", ".sh", ".rb", ".php", ".pl"}
	for _, f := range files {
		if !HasExtension(f, extensions) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			// Skip data URIs, URLs, hex color codes, git SHAs
			if strings.Contains(line, "data:") || strings.Contains(line, "http://") ||
				strings.Contains(line, "https://") || strings.Contains(line, "sha256") ||
				strings.Contains(line, "md5") || strings.Contains(line, "color:") {
				continue
			}
			if hexLongPat.MatchString(line) {
				// Verify it's actually hex (majority of non-hex chars means it's not)
				hexCount := 0
				totalCount := 0
				for _, ch := range line {
					if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
						hexCount++
					}
					totalCount++
				}
				// Must be at least 60% hex characters to avoid flagging regular text
				if totalCount > 0 && float64(hexCount)/float64(totalCount) < 0.6 {
					continue
				}
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Unusually long hex-encoded string — possible encoded payload",
				})
			}
		}
	}
	return findings, nil
}

// ── Hidden executables ────────────────────────────────────────────────────────

type GenericHiddenExecutableRule struct {
	BaseRule
	Config RuleConfig
}

func (r *GenericHiddenExecutableRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		base := filepath.Base(f)
		if !strings.HasPrefix(base, ".") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f))
		if ext == ".exe" || ext == ".dll" || ext == ".bat" || ext == ".cmd" || ext == ".ps1" {
			findings = append(findings, Finding{
				Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
				File: f, Line: 0,
				Message: "Executable file in hidden directory",
			})
		}
	}
	return findings, nil
}
