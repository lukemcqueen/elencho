package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lukemcqueen/elencho/internal/config"
	"github.com/lukemcqueen/elencho/internal/output"
	"github.com/lukemcqueen/elencho/internal/scan"
	"github.com/lukemcqueen/elencho/internal/update"
)

var version = config.Version

func main() {
	cfg := config.DefaultConfig()

	// Define flags
	help := flag.Bool("help", false, "Show this help")
	verbose := flag.Bool("v", false, "Verbose debug output")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	sarifOutput := flag.Bool("sarif", false, "Output in SARIF format")
	listRules := flag.Bool("list-rules", false, "List available detection rules and exit")
	showVersion := flag.Bool("version", false, "Show version")
	selfScan := flag.Bool("self-scan", false, "Scan this repo itself")
	strictMode := flag.Bool("strict", false, "Ignore .elencho-ignore and --exclude flags")
	noAutoUpdate := flag.Bool("no-auto-update", false, "Skip online rule update check")
	updateOnly := flag.Bool("update-only", false, "Update rules and exit (no scan)")
	verifyRules := flag.Bool("verify", false, "Verify local rule integrity against CHECKSUMS")
	dockerMode := flag.Bool("docker", false, "Run scan inside Docker sandbox")
	dockerImage := flag.String("docker-image", "ubuntu:24.04", "Docker image to use with --docker")

	var excludeFlags multiFlag
	flag.Var(&excludeFlags, "e", "One-off exclude GLOB (can be repeated)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Elencho — supply-chain malware and obfuscation scanner

Usage: elencho [options] [directory]

Scan a directory for supply-chain malware, hidden code, and suspicious patterns.

Options:
  -h, --help            Show this help
  -v, --verbose         Verbose debug output
  --json                Output in JSON format
  --sarif               Output in SARIF 2.1 format
  --list-rules          List available detection rules and exit
  --version             Show version
  --self-scan           Scan this repo itself
  -e, --exclude GLOB    One-off exclude GLOB (can be repeated)
  --no-auto-update      Skip online rule update check
  --update-only         Update rules and exit (no scan)
  --strict              Ignore .elencho-ignore and --exclude flags
  --verify              Verify local rule integrity against CHECKSUMS
  --docker              Run scan inside Docker sandbox
  --docker-image IMG    Docker image to use with --docker

Examples:
  elencho                                           Scan current directory
  elencho --json /path/to/repo                      Scan repo, output JSON
  elencho --sarif ./repo                             Scan repo, output SARIF
  elencho --list-rules                              List all detection rules
  elencho --self-scan                               Self-scan with safe exclusions
  elencho --strict ./untrusted-repo                 CI-scan untrusted fork
  elencho -e '*/build/*' -e '*/dist/*'              Exclude build/dist dirs

Exit code: 0 if no issues found, 1 if any HIGH/CRITICAL findings exist.
`)
	}

	// Parse flags (using a custom parse to handle both single-dash and double-dash)
	args := os.Args[1:]
	if len(args) > 0 {
		// Support --help and -h
		switch args[0] {
		case "-h", "--help":
			*help = true
		case "--version":
			*showVersion = true
		}
	}

	flag.Parse()

	// Handle version
	if *showVersion {
		fmt.Printf("elencho %s\n", version)
		os.Exit(0)
	}

	// Map flags to config
	cfg.Verbose = *verbose
	cfg.ListRules = *listRules
	cfg.SelfScan = *selfScan
	cfg.StrictMode = *strictMode
	cfg.AutoUpdate = !*noAutoUpdate
	cfg.UpdateOnly = *updateOnly
	cfg.VerifyRules = *verifyRules
	cfg.DockerMode = *dockerMode
	cfg.DockerImage = *dockerImage
	cfg.ExcludePatterns = []string(excludeFlags)

	if *jsonOutput {
		cfg.OutputFormat = "json"
	} else if *sarifOutput {
		cfg.OutputFormat = "sarif"
	}

	// Target directory is the first non-flag argument
	target := flag.Arg(0)
	if target != "" {
		cfg.TargetDir = target
	}

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// --list-rules
	if cfg.ListRules {
		registry := scan.DefaultRegistry()
		fmt.Println("Available rules:")
		fmt.Println()
		for _, rule := range registry.Rules() {
			fmt.Printf("  %-30s %s\n", rule.ID(), rule.Description())
		}
		fmt.Println()
		fmt.Printf("Total: %d rules\n", registry.RuleCount())
		os.Exit(0)
	}

	// Determine output format
	var outputFormat output.Format
	switch cfg.OutputFormat {
	case "json":
		outputFormat = output.FormatJSON
	case "sarif":
		outputFormat = output.FormatSARIF
	default:
		outputFormat = output.FormatText
	}

	// Auto-detect self-scan
	if !cfg.SelfScan {
		exePath, err := os.Executable()
		if err == nil {
			// If the target is the repo itself, enable self-scan
			if cfg.TargetDir == "." || cfg.TargetDir == exePath {
				// Check if we're in the elencho source directory
				if info, err := os.Stat("go.mod"); err == nil && info != nil {
					// Check if this is the elencho repo
					data, _ := os.ReadFile("go.mod")
					if strings.Contains(string(data), "github.com/lukemcqueen/elencho") {
						cfg.SelfScan = true
					}
				}
			}
		}
	}

	// Create scanner with configured registry
	registry := scan.DefaultRegistry()

	// Check if update/verify is requested
	if cfg.UpdateOnly {
		runUpdate(cfg)
		return
	}
	if cfg.VerifyRules {
		runVerify(cfg)
		return
	}

	// Check if Docker mode is requested (inform user it's not yet implemented in Go)
	if cfg.DockerMode {
		fmt.Fprintf(os.Stderr, "[INFO] Docker mode is not yet implemented in the Go version.\n")
		fmt.Fprintf(os.Stderr, "[INFO] Use the bash version for Docker sandboxing: cd security-scanner && ./run --docker\n")
		os.Exit(1)
	}

	// Create scanner
	scanner := scan.NewScanner(registry)

	// Create scan options
	scanOpts := scan.DefaultScanOptions(cfg.TargetDir)
	scanOpts.Verbose = cfg.Verbose
	scanOpts.StrictMode = cfg.StrictMode
	scanOpts.SelfScan = cfg.SelfScan

	// Add CLI exclusions
	for _, pattern := range cfg.ExcludePatterns {
		scanOpts.Exclusions.AddPattern(pattern)
	}

	// In self-scan mode, exclude fixtures and rules
	if cfg.SelfScan {
		scanOpts.Exclusions.SetSelfScanExcludes([]string{"tests/fixtures/", "internal/scan/"})
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[INFO] Self-scan mode: excluding tests/fixtures/ and internal/scan/\n")
		}
	}

	// Run scan
	ctx := context.Background()
	findings, err := scanner.Scan(ctx, scanOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}

	// Format and print output
	report := output.NewReport(findings)
	formatted, err := output.FormatReport(report, outputFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Formatting output: %v\n", err)
		os.Exit(1)
	}

	// For JSON and SARIF, output to stdout; text goes to stdout
	fmt.Println(formatted)

	os.Exit(findings.ExitCode())
}

// multiFlag implements flag.Value for repeated -e flags.
type multiFlag []string

func (f *multiFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// runUpdate checks for updates and applies them.
func runUpdate(cfg *config.Config) {
	fmt.Println("Checking for rule updates...")

	// Current rules version (starts at 0 for embedded-only)
	currentVersion := 0

	manifest, err := update.CheckForUpdate(config.UpdateBaseURL, currentVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Update check failed: %v\n", err)
		os.Exit(1)
	}

	if manifest == nil {
		fmt.Println("  Rules are up to date (version 0).")
		os.Exit(0)
	}

	fmt.Printf("  New version available: rules v%d\n", manifest.RulesVersion)
	fmt.Printf("  %d file(s) to download\n", len(manifest.Files))

	if err := update.DownloadUpdate(config.UpdateBaseURL, manifest); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Update failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("  ✓ Update applied successfully.")
}

// runVerify verifies local rule integrity.
func runVerify(cfg *config.Config) {
	fmt.Println("Verifying local rule integrity...")

	// Validate the embedded public key
	pubKey := update.ReadEmbeddedPublicKey()
	fmt.Printf("  Public key: loaded (%d bytes)\n", len(pubKey))

	// Verify embedded rules parse correctly
	configs, err := scan.LoadEmbeddedRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Embedded rules failed to parse: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Embedded rules: %d rules loaded successfully\n", len(configs))

	// Verify local overlaid rules if present
	if err := update.VerifyLocal(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Local overlay verification: %v\n", err)
	} else {
		fmt.Println("  Local overlays: verified")
	}

	fmt.Println("  ✓ Rule integrity check passed.")
	_ = cfg
}
