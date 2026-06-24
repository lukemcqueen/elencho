package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Rule defines the interface that every detection rule must implement.
type Rule interface {
	// ID returns the unique identifier for this rule (e.g., "shell-curl-pipe-bash").
	ID() string

	// Severity returns the default severity for this rule.
	Severity() Severity

	// Category returns the category this rule belongs to (e.g., "remote-execution").
	Category() string

	// Description returns a human-readable description of what this rule detects.
	Description() string

	// Detect runs the rule against the scanned files and returns any findings.
	Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error)
}

// Verifier is an optional interface that rules can implement to re-evaluate
// their own findings with full file context and adjust confidence.
// Called after Detect() for each finding the rule produced.
// scanRoot is the absolute path of the scanned directory.
// finding points to the finding (can be modified in-place).
// allFindings is the complete findings list from all rules (read-only context).
type Verifier interface {
	Verify(ctx context.Context, scanRoot string, finding *Finding, allFindings []Finding) error
}

// BaseRule provides common fields and methods for rules.
type BaseRule struct {
	RuleID      string
	Sev         Severity
	Cat         string
	Desc        string
}

// ID returns the rule identifier.
func (r *BaseRule) ID() string { return r.RuleID }

// Severity returns the default severity.
func (r *BaseRule) Severity() Severity { return r.Sev }

// Category returns the category.
func (r *BaseRule) Category() string { return r.Cat }

// Description returns the description.
func (r *BaseRule) Description() string { return r.Desc }

// RuleRegistry holds all registered rules.
type RuleRegistry struct {
	rules []Rule
}

// NewRuleRegistry creates a new empty rule registry.
func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		rules: make([]Rule, 0),
	}
}

// Register adds a rule to the registry.
func (r *RuleRegistry) Register(rule Rule) {
	r.rules = append(r.rules, rule)
}

// Rules returns all registered rules.
func (r *RuleRegistry) Rules() []Rule {
	return r.rules
}

// RuleCount returns the number of registered rules.
func (r *RuleRegistry) RuleCount() int {
	return len(r.rules)
}

// RemediationByRuleID returns a map of rule ID → (remediation, fix_command)
// from the embedded rule configs.
func (r *RuleRegistry) RemediationByRuleID() map[string]struct{ Remediation, FixCommand string } {
	configs, err := LoadEmbeddedRules()
	if err != nil {
		return nil
	}
	m := make(map[string]struct{ Remediation, FixCommand string })
	for _, c := range configs {
		m[c.ID] = struct{ Remediation, FixCommand string }{c.Remediation, c.FixCommand}
	}
	return m
}

// DefaultRegistry creates a registry with all built-in rules loaded
// from the embedded rules.yaml. This is the canonical rule source.
func DefaultRegistry() *RuleRegistry {
	configs, err := LoadEmbeddedRules()
	if err != nil {
		// Fallback: hardcoded registry if embedded rules fail to load
		return fallbackRegistry()
	}

	reg := NewRuleRegistry()
	for _, cfg := range configs {
		rule := NewRuleFromConfig(cfg)
		reg.Register(rule)
	}
	return reg
}

// fallbackRegistry constructs rules from hardcoded definitions.
// Used when the embedded rules.yaml cannot be loaded.
func fallbackRegistry() *RuleRegistry {
	reg := NewRuleRegistry()

	reg.Register(&GenericZeroWidthUnicodeRule{BaseRule: BaseRule{RuleID: "generic-zero-width-unicode", Sev: SeverityMedium, Cat: "obfuscation", Desc: "Zero-width Unicode characters in source code — possible obfuscation"}})
	reg.Register(&GenericLongBase64Rule{BaseRule: BaseRule{RuleID: "generic-long-base64", Sev: SeverityLow, Cat: "obfuscation", Desc: "Unusually long base64 strings — verify it's not encoded payload"}})
	reg.Register(&GenericObfuscatedEvalRule{BaseRule: BaseRule{RuleID: "generic-obfuscated-eval", Sev: SeverityMedium, Cat: "obfuscation", Desc: "Obfuscated eval/exec — likely hidden code execution"}})
	reg.Register(&GenericMinifiedRequireRule{BaseRule: BaseRule{RuleID: "generic-minified-require", Sev: SeverityMedium, Cat: "obfuscation", Desc: "Minified file with local requires — verify it's legitimate"}})
	reg.Register(&GenericHardcodedSecretRule{BaseRule: BaseRule{RuleID: "generic-hardcoded-secret", Sev: SeverityHigh, Cat: "secret-leak", Desc: "Possible hardcoded credential — verify this isn't a real key"}})
	reg.Register(&GenericGitAttributesRule{BaseRule: BaseRule{RuleID: "generic-gitattributes-filter", Sev: SeverityHigh, Cat: "git-attributes", Desc: "Git filter/smudge defined — can auto-transform files on checkout"}})
	reg.Register(&GenericHiddenExecutableRule{BaseRule: BaseRule{RuleID: "generic-hidden-executable", Sev: SeverityMedium, Cat: "suspicious-file", Desc: "Executable file in hidden directory"}})
	reg.Register(&ShellCurlPipeBashRule{BaseRule: BaseRule{RuleID: "shell-curl-pipe-bash", Sev: SeverityCritical, Cat: "remote-execution", Desc: "Downloads and pipes to shell"}})
	reg.Register(&ShellReverseShellRule{BaseRule: BaseRule{RuleID: "shell-reverse-shell", Sev: SeverityCritical, Cat: "remote-execution", Desc: "Possible reverse shell"}})
	reg.Register(&NPMPostinstallDownloadRule{BaseRule: BaseRule{RuleID: "npm-postinstall-download", Sev: SeverityHigh, Cat: "script-execution", Desc: "Dangerous postinstall script downloads or contacts remote"}})
	reg.Register(&NPMPostinstallEvalRule{BaseRule: BaseRule{RuleID: "npm-postinstall-eval", Sev: SeverityHigh, Cat: "script-execution", Desc: "Postinstall runs inline code via node -e or require"}})
	reg.Register(&NpmSuspiciousScriptRule{BaseRule: BaseRule{RuleID: "npm-suspicious-script", Sev: SeverityCritical, Cat: "script-execution", Desc: "Suspicious command in scripts"}})
	reg.Register(&NpmrcHookRule{BaseRule: BaseRule{RuleID: "npmrc-hook", Sev: SeverityMedium, Cat: "script-execution", Desc: ".npmrc contains script hook"}})
	reg.Register(&NpmGitDependencyRule{BaseRule: BaseRule{RuleID: "npm-git-dependency", Sev: SeverityMedium, Cat: "dependency", Desc: "Unpinned git dependency"}})
	reg.Register(&PythonCmdclassRule{BaseRule: BaseRule{RuleID: "python-cmdclass", Sev: SeverityHigh, Cat: "script-execution", Desc: "setup.py defines cmdclass — can execute arbitrary build code"}})
	reg.Register(&PythonSetupDownloadRule{BaseRule: BaseRule{RuleID: "python-setup-download", Sev: SeverityHigh, Cat: "script-execution", Desc: "setup.py calls network or shell command"}})
	reg.Register(&PythonBuildBackendRule{BaseRule: BaseRule{RuleID: "python-build-backend", Sev: SeverityMedium, Cat: "script-execution", Desc: "Unusual build backend"}})
	reg.Register(&PythonCustomIndexRule{BaseRule: BaseRule{RuleID: "python-custom-index", Sev: SeverityMedium, Cat: "dependency", Desc: "Custom pip index (potential dependency confusion)"}})
	reg.Register(&PythonGitDependencyRule{BaseRule: BaseRule{RuleID: "python-git-dependency", Sev: SeverityMedium, Cat: "dependency", Desc: "Unpinned dependency from external source"}})
	reg.Register(&GitBinaryInSourceRule{BaseRule: BaseRule{RuleID: "git-binary-in-source", Sev: SeverityMedium, Cat: "binary-artifact", Desc: "Binary file in source tree — verify intent"}})
	reg.Register(&GitEnvInHistoryRule{BaseRule: BaseRule{RuleID: "git-env-in-history", Sev: SeverityHigh, Cat: "secret-leak", Desc: "Files matching .env* have been committed in git history"}})
	reg.Register(&GitLargeRecentAddRule{BaseRule: BaseRule{RuleID: "git-large-recent-add", Sev: SeverityLow, Cat: "data-exfiltration", Desc: "Large file added in recent commits"}})
	reg.Register(&GitHookSuspiciousRule{BaseRule: BaseRule{RuleID: "git-hook-suspicious", Sev: SeverityHigh, Cat: "git-hooks", Desc: "Git hook contains network or shell execution"}})
	reg.Register(&GitIgnoredFilePresentRule{BaseRule: BaseRule{RuleID: "git-ignored-file-present", Sev: SeverityLow, Cat: "ignored-artifact", Desc: "File present on disk but .gitignore'd — potential hiding place"}})
	reg.Register(&DockerignoreMismatchRule{BaseRule: BaseRule{RuleID: "dockerignore-mismatch", Sev: SeverityLow, Cat: "docker-supply-chain", Desc: "Pattern in .dockerignore but not in .gitignore"}})

	return reg
}


// GlobMatcher checks if a file path matches a glob pattern.
// Supports patterns like "*.sh", "**/*.py", etc.
func GlobMatcher(pattern string, path string) bool {
	matched, err := filepath.Match(pattern, filepath.Base(path))
	if err == nil && matched {
		return true
	}
	matched, err = filepath.Match(pattern, path)
	if err == nil && matched {
		return true
	}
	return false
}

// HasExtension checks if a file path has any of the given extensions.
func HasExtension(path string, extensions []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range extensions {
		if ext == e {
			return true
		}
	}
	return false
}

// FilenameMatch checks if a filename matches any of the given exact names.
func FilenameMatch(path string, names []string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, name := range names {
		if base == name {
			return true
		}
	}
	return false
}

// ContainsLine searches file content for a pattern and returns matching line numbers.
func ContainsLine(lines []string, pattern string) []int {
	var matches []int
	for i, line := range lines {
		if strings.Contains(line, pattern) {
			matches = append(matches, i+1) // 1-indexed line numbers
		}
	}
	return matches
}

// ContainsLineRegex searches file content for a regex pattern.
func ContainsLineRegex(lines []string, pattern string) []int {
	var matches []int
	for i, line := range lines {
		if matched, _ := filepath.Match(pattern, line); matched {
			matches = append(matches, i+1)
		}
	}
	return matches
}

// IsSymlink checks if a file is a symlink.
func IsSymlink(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}

// DirExists checks if a directory exists.
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// FileExists checks if a file exists and is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
