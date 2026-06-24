package scan

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scanner is the core scanning engine.
type Scanner struct {
	registry *RuleRegistry
}

// NewScanner creates a new scanner with the given rule registry.
func NewScanner(registry *RuleRegistry) *Scanner {
	return &Scanner{
		registry: registry,
	}
}

// Scan runs the scanner against the target directory with the given options.
func (s *Scanner) Scan(ctx context.Context, opts *ScanOptions) (*Findings, error) {
	findings := NewFindings()

	// Resolve target to absolute path
	targetAbs, err := filepath.Abs(opts.TargetDir)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve target path: %w", err)
	}

	// Verify target exists
	targetInfo, err := os.Stat(targetAbs)
	if err != nil {
		return nil, fmt.Errorf("cannot access target: %w", err)
	}
	if !targetInfo.IsDir() {
		return nil, fmt.Errorf("target is not a directory: %s", targetAbs)
	}

	// Auto-load .elencho-ignore from the target directory (unless in strict mode)
	if !opts.StrictMode {
		if err := opts.Exclusions.LoadIgnoreFileFromDir(targetAbs); err != nil {
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "[WARN] Loading .elencho-ignore: %v\n", err)
			}
		}
	}

	// Discover files
	files, err := discoverFiles(targetAbs, opts)
	if err != nil {
		return nil, fmt.Errorf("file discovery failed: %w", err)
	}

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "[INFO] Scanning: %s\n", targetAbs)
		fmt.Fprintf(os.Stderr, "[INFO] Files scanned: %d\n", len(files))
	}

	// Run each rule against the discovered files
	rules := s.registry.Rules()
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Running rule: %s\n", rule.ID())
		}

		ruleFindings, err := rule.Detect(ctx, targetAbs, files)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "[WARN] Rule %s error: %v\n", rule.ID(), err)
			}
			continue
		}
		for _, f := range ruleFindings {
			findings.Add(f.Severity, f.Category, f.RuleID, f.File, f.Line, f.Message)
		}
	}

	// Apply inline suppression markers (elencho:ignore)
	allFindings := findings.All()
	filtered := FilterSuppressed(allFindings, targetAbs)
	if len(filtered) != len(allFindings) {
		findings = NewFindings()
		for _, f := range filtered {
			findings.Add(f.Severity, f.Category, f.RuleID, f.File, f.Line, f.Message)
		}
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "[INFO] Suppressed %d finding(s) via inline markers\n", len(allFindings)-len(filtered))
		}
	}

	return findings, nil
}

// discoverFiles walks the target directory and returns all scannable files.
func discoverFiles(root string, opts *ScanOptions) ([]string, error) {
	var files []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Permission denied — skip
			if os.IsPermission(err) {
				return nil
			}
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Check exclusion
			if opts.Exclusions.ShouldExclude(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file itself is excluded
		if opts.Exclusions.ShouldExclude(path) {
			return nil
		}

		// Check file size limit
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			return nil
		}

		// Normalize path
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			relPath = path
		}
		files = append(files, relPath)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// ListFiles lists all scannable files (for --list-files or verbose output).
func ListFiles(root string, opts *ScanOptions) ([]string, error) {
	return discoverFiles(root, opts)
}

// ReadFileLines reads a file and returns its lines.
// Used by rules to search file contents.
func ReadFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// ReadFile reads the entire file content as a string.
func ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// IsTextFile does a basic check if a file appears to be text.
func IsTextFile(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	// Check first 512 bytes for null bytes (binary indicator)
	checkLen := len(data)
	if checkLen > 512 {
		checkLen = 512
	}
	return !strings.ContainsRune(string(data[:checkLen]), '\x00')
}
