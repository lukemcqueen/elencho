package config

// Version is the current version of Elencho.
// Overridden at build time via -ldflags.
var Version = "0.3.2"

// Default constants
const (
	DefaultMaxFileSize = 10 * 1024 * 1024 // 10MB
	AppName            = "elencho"
	AppDescription     = "Supply-chain malware and obfuscation scanner"
	UpdateBaseURL      = "https://github.com/lukemcqueen/elencho/releases/latest/download"
)

// Config holds the runtime configuration for Elencho.
type Config struct {
	// Target directory to scan
	TargetDir string

	// Output format: text, json, sarif
	OutputFormat string

	// Verbose enables debug logging
	Verbose bool

	// ListRules prints all available rules and exits
	ListRules bool

	// SelfScan enables self-scan mode
	SelfScan bool

	// StrictMode ignores .elencho-ignore and --exclude flags
	StrictMode bool

	// AutoUpdate enables automatic rule updates (default: true)
	AutoUpdate bool

	// UpdateOnly updates rules and exits
	UpdateOnly bool

	// VerifyRules checks local rule integrity
	VerifyRules bool

	// Exclusions from CLI flags
	ExcludePatterns []string

	// MaxFileSize is the maximum file size to scan
	MaxFileSize int64

	// DockerMode runs scan in Docker sandbox
	DockerMode bool

	// DockerImage is the Docker image to use
	DockerImage string

	// ConfidenceThreshold hides findings below this confidence level (0.0-1.0)
	// Default 0.0 (show everything). Set to e.g. 0.5 to hide low-confidence findings.
	ConfidenceThreshold float64
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		TargetDir:           ".",
		OutputFormat:        "text",
		Verbose:             false,
		ListRules:           false,
		SelfScan:            false,
		StrictMode:          false,
		AutoUpdate:          true,
		UpdateOnly:          false,
		VerifyRules:         false,
		ExcludePatterns:     []string{},
		MaxFileSize:         DefaultMaxFileSize,
		DockerMode:          false,
		DockerImage:         "ubuntu:24.04",
		ConfidenceThreshold: 0.5,
	}
}
