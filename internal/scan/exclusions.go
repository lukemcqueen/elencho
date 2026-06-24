package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Exclusions manages path exclusions for scans.
type Exclusions struct {
	patterns         []string
	builtInExcludes  []string
	selfScanExcludes []string
	strictMode       bool
}

// NewExclusions creates a new Exclusions instance.
func NewExclusions(strictMode bool) *Exclusions {
	return &Exclusions{
		patterns:         make([]string, 0),
		builtInExcludes:  []string{".git", "node_modules", "venv", ".venv", "__pycache__", ".cache", "security-scanner", ".next", "dist", "build", "target", ".serverless", ".terraform", "tmp/cache"},
		selfScanExcludes: []string{},
		strictMode:       strictMode,
	}
}

// AddPattern adds a glob pattern to exclude.
func (e *Exclusions) AddPattern(pattern string) {
	e.patterns = append(e.patterns, pattern)
}

// AddPatterns adds multiple glob patterns.
func (e *Exclusions) AddPatterns(patterns []string) {
	e.patterns = append(e.patterns, patterns...)
}

// SetSelfScanExcludes sets the exclusions for self-scan mode.
func (e *Exclusions) SetSelfScanExcludes(excludes []string) {
	e.selfScanExcludes = excludes
}

// LoadIgnoreFile reads a .elencho-ignore file and adds its patterns.
// Ignores blank lines and comments (#). Returns nil if the file doesn't exist.
func (e *Exclusions) LoadIgnoreFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File missing is not an error
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e.patterns = append(e.patterns, line)
	}
	return scanner.Err()
}

// LoadIgnoreFileFromDir looks for a .elencho-ignore file in the given directory
// and loads its patterns. Returns nil if no file exists.
func (e *Exclusions) LoadIgnoreFileFromDir(dir string) error {
	ignorePath := filepath.Join(dir, ".elencho-ignore")
	return e.LoadIgnoreFile(ignorePath)
}

// ShouldExclude checks if a path should be excluded from scanning.
func (e *Exclusions) ShouldExclude(path string) bool {
	// Normalize path separators
	path = filepath.ToSlash(path)

	// Check built-in excludes
	for _, exclude := range e.builtInExcludes {
		// Check if path starts with the excluded directory
		if strings.HasPrefix(path, exclude+"/") || path == exclude {
			return true
		}
		if strings.Contains(path, "/"+exclude+"/") || strings.Contains(path, string(filepath.Separator)+exclude+string(filepath.Separator)) {
			return true
		}
		// Also check if the path itself is the excluded dir
		if strings.HasSuffix(path, "/"+exclude) || path == exclude {
			return true
		}
	}

	// Check self-scan excludes (always apply, even in strict mode)
	for _, exclude := range e.selfScanExcludes {
		if strings.Contains(path, exclude) {
			return true
		}
	}

	// In strict mode, ignore user-added patterns
	if e.strictMode {
		return false
	}

	// Check user-added pattern exclusions
	for _, pattern := range e.patterns {
		// Directory pattern (ending with /) — check if path starts with it
		if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(path, pattern) {
				return true
			}
			continue
		}

		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
		matched, err = filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
		// Simple substring check for globs like */build/* or */dist/*
		if strings.Contains(pattern, "*") {
			// Check if the path contains any segment matching the pattern
			parts := strings.Split(path, "/")
			for _, part := range parts {
				if matched, _ := filepath.Match(pattern, part); matched {
					return true
				}
			}
		}
	}

	return false
}

// WalkFunc returns a filepath.WalkFunc that skips excluded directories and files.
func (e *Exclusions) WalkFunc() func(path string, info os.FileInfo, err error) error {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && e.ShouldExclude(path) {
			return filepath.SkipDir
		}
		return nil
	}
}

// ScanOptions holds options for a scan run.
type ScanOptions struct {
	TargetDir   string
	Exclusions  *Exclusions
	Verbose     bool
	StrictMode  bool
	SelfScan    bool
	MaxFileSize int64 // maximum file size to scan in bytes (0 = no limit)
}

// DefaultScanOptions returns scan options with sensible defaults.
func DefaultScanOptions(targetDir string) *ScanOptions {
	return &ScanOptions{
		TargetDir:   targetDir,
		Exclusions:  NewExclusions(false),
		Verbose:     false,
		StrictMode:  false,
		SelfScan:    false,
		MaxFileSize: 10 * 1024 * 1024, // 10MB default
	}
}
