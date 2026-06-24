package scan

import (
	"context"
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed rules/rules.yaml
var embeddedRulesData []byte

// RuleConfig holds the declarative configuration for a detection rule.
// Embedded via rules/rules.yaml — the canonical source of truth.
type RuleConfig struct {
	ID          string   `yaml:"id"`
	Severity    string   `yaml:"severity"`
	Category    string   `yaml:"category"`
	Description string   `yaml:"description"`
	Detector    string   `yaml:"detector"`
	Extensions  []string `yaml:"file_extensions"`
	FileNames   []string `yaml:"file_names"`
	Message     string   `yaml:"message"`
	Remediation string   `yaml:"remediation"`
	FixCommand  string   `yaml:"fix_command"`
}

// ruleFile wraps the top-level YAML structure.
type ruleFile struct {
	Version int          `yaml:"version"`
	Rules   []RuleConfig `yaml:"rules"`
}

// LoadEmbeddedRules parses the embedded rules.yaml and returns all rule configs.
func LoadEmbeddedRules() ([]RuleConfig, error) {
	var file ruleFile
	if err := yaml.Unmarshal(embeddedRulesData, &file); err != nil {
		return nil, err
	}
	return file.Rules, nil
}

// NewRuleFromConfig creates a Rule from a RuleConfig by dispatching to the
// appropriate rule struct based on the detector field.
func NewRuleFromConfig(cfg RuleConfig) Rule {
	base := BaseRule{
		RuleID: cfg.ID,
		Sev:    Severity(cfg.Severity),
		Cat:    cfg.Category,
		Desc:   cfg.Description,
	}

	switch cfg.Detector {
	// Generic
	case "zero_width_bytes":
		return &GenericZeroWidthUnicodeRule{BaseRule: base, Config: cfg}
	case "long_base64":
		return &GenericLongBase64Rule{BaseRule: base, Config: cfg}
	case "obfuscated_eval":
		return &GenericObfuscatedEvalRule{BaseRule: base, Config: cfg}
	case "minified_require":
		return &GenericMinifiedRequireRule{BaseRule: base, Config: cfg}
	case "hex_encoded":
		return &GenericHexEncodedRule{BaseRule: base, Config: cfg}
	case "hardcoded_secret":
		return &GenericHardcodedSecretRule{BaseRule: base, Config: cfg}
	case "gitattributes_filter":
		return &GenericGitAttributesRule{BaseRule: base, Config: cfg}
	case "hidden_executable":
		return &GenericHiddenExecutableRule{BaseRule: base, Config: cfg}
	case "trojan_source":
		return &GenericTrojanSourceRule{BaseRule: base, Config: cfg}
	// Shell
	case "curl_pipe_bash":
		return &ShellCurlPipeBashRule{BaseRule: base, Config: cfg}
	case "reverse_shell":
		return &ShellReverseShellRule{BaseRule: base, Config: cfg}
	case "base64_exec":
		return &ShellBase64ExecRule{BaseRule: base, Config: cfg}
	case "history_evasion":
		return &ShellHistoryEvasionRule{BaseRule: base, Config: cfg}
	// npm
	case "npm_postinstall_download":
		return &NPMPostinstallDownloadRule{BaseRule: base, Config: cfg}
	case "npm_postinstall_eval":
		return &NPMPostinstallEvalRule{BaseRule: base, Config: cfg}
	case "npm_suspicious_script":
		return &NpmSuspiciousScriptRule{BaseRule: base, Config: cfg}
	case "npmrc_hook":
		return &NpmrcHookRule{BaseRule: base, Config: cfg}
	case "npm_git_dependency":
		return &NpmGitDependencyRule{BaseRule: base, Config: cfg}
	case "npm_unpinned_dep":
		return &NpmUnpinnedDepRule{BaseRule: base, Config: cfg}
	// Python
	case "python_cmdclass":
		return &PythonCmdclassRule{BaseRule: base, Config: cfg}
	case "python_setup_download":
		return &PythonSetupDownloadRule{BaseRule: base, Config: cfg}
	case "python_build_backend":
		return &PythonBuildBackendRule{BaseRule: base, Config: cfg}
	case "python_custom_index":
		return &PythonCustomIndexRule{BaseRule: base, Config: cfg}
	case "python_git_dependency":
		return &PythonGitDependencyRule{BaseRule: base, Config: cfg}
	case "python_dynamic_import":
		return &PythonDynamicImportRule{BaseRule: base, Config: cfg}
	// CI/CD
	case "dockerfile_dangerous":
		return &DockerfileDangerousRule{BaseRule: base, Config: cfg}
	case "actions_dangerous":
		return &ActionsDangerousRule{BaseRule: base, Config: cfg}
	// Git
	case "git_binary_in_source":
		return &GitBinaryInSourceRule{BaseRule: base, Config: cfg}
	case "git_env_in_history":
		return &GitEnvInHistoryRule{BaseRule: base, Config: cfg}
	case "git_large_recent_add":
		return &GitLargeRecentAddRule{BaseRule: base, Config: cfg}
	case "git_hook_suspicious":
		return &GitHookSuspiciousRule{BaseRule: base, Config: cfg}
	// Gitignore abuse
	case "git_ignored_file_present":
		return &GitIgnoredFilePresentRule{BaseRule: base, Config: cfg}
	case "dockerignore_mismatch":
		return &DockerignoreMismatchRule{BaseRule: base, Config: cfg}
	default:
		// Fallback: return a basic rule that logs the unknown detector
		return &genericFallbackRule{BaseRule: base, detector: cfg.Detector}
	}
}

// genericFallbackRule handles unknown detector types gracefully.
type genericFallbackRule struct {
	BaseRule
	detector string
}

func (r *genericFallbackRule) Detect(_ context.Context, _ string, _ []string) ([]Finding, error) {
	return nil, nil
}
