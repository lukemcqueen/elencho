package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ignoreRe matches "elencho:ignore rule-id" or "elencho:ignore id1, id2"
// in any comment context — trims leading //, #, --, <!-- -->, etc.
var ignoreRe = regexp.MustCompile(`elencho:\s*ignore\s+(.+?)$`)

// maxSuppressionScanBytes is the max bytes read from a file when looking for
// suppression markers. Markers must appear within this window.
const maxSuppressionScanBytes = 8192

// SuppressionSet maps rule IDs to whether they are suppressed in a specific file.
type SuppressionSet map[string]bool

// ParseSuppressions reads up to maxSuppressionScanBytes from file and returns
// the set of rule IDs suppressed via "elencho:ignore <rule-id>" markers.
// Returns an empty set (nil) if no markers are found.
// Does not error on missing files or read errors — returns empty set.
func ParseSuppressions(path string) SuppressionSet {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, maxSuppressionScanBytes), maxSuppressionScanBytes)

	suppressed := make(SuppressionSet)
	for scanner.Scan() {
		line := scanner.Text()
		if !containsIgnoreMarker(line) {
			continue
		}
		// Squeeze comment prefixes so the regex can match
		clean := stripCommentPrefix(line)
		matches := ignoreRe.FindStringSubmatch(clean)
		if matches == nil {
			continue
		}
		// matches[1] is the comma/space separated list of rule IDs
		for _, id := range splitIgnoreTargets(matches[1]) {
			if id != "" {
				suppressed[id] = true
			}
		}
	}
	if len(suppressed) == 0 {
		return nil
	}
	return suppressed
}

// containsIgnoreMarker is a fast pre-check before running the regex.
func containsIgnoreMarker(line string) bool {
	idx := strings.Index(line, "elencho:")
	if idx == -1 {
		return false
	}
	// Must have "ignore" after "elencho:" (with optional whitespace)
	rest := line[idx+8:] // after "elencho:"
	rest = strings.TrimSpace(rest)
	return strings.HasPrefix(rest, "ignore") || strings.HasPrefix(rest, " ignore")
}

// stripCommentPrefix removes common comment markers from the start of a line
// so the regex can match "elencho:ignore" cleanly.
func stripCommentPrefix(line string) string {
	trimmed := strings.TrimSpace(line)
	// Try known comment prefixes
	for _, prefix := range []string{"//", "#", "--", "<!--", "/*"} {
		if strings.HasPrefix(trimmed, prefix) {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
			// Handle multi-char close like -->
			if idx := strings.Index(trimmed, "-->"); idx >= 0 {
				trimmed = strings.TrimSpace(trimmed[:idx])
			}
			// Handle */ close
			if idx := strings.Index(trimmed, "*/"); idx >= 0 {
				trimmed = strings.TrimSpace(trimmed[:idx])
			}
			break
		}
	}
	return trimmed
}

// splitIgnoreTargets splits a comma/space-separated list of rule IDs.
// Accepts "id1,id2,id3", "id1 id2", or mixed.
func splitIgnoreTargets(s string) []string {
	// Normalize: replace commas with spaces, then split on whitespace
	normalized := strings.ReplaceAll(s, ",", " ")
	return strings.Fields(normalized)
}

// FilterSuppressed removes findings that have been suppressed via inline
// elencho:ignore markers in their source file. Returns a new slice.
// scanRoot must be the absolute path to the scanned directory.
func FilterSuppressed(findings []Finding, scanRoot string) []Finding {
	if len(findings) == 0 {
		return findings
	}

	cache := make(map[string]SuppressionSet)

	var filtered []Finding
	for _, f := range findings {
		if f.File == "" || f.Line == 0 {
			// File-level rules or empty paths can't be suppressed inline
			filtered = append(filtered, f)
			continue
		}
		// Build full path: scanRoot + relative file path
		fullPath := f.File
		if scanRoot != "" && !strings.HasPrefix(fullPath, "/") {
			fullPath = filepath.Join(scanRoot, fullPath)
		}

		supp, ok := cache[fullPath]
		if !ok {
			supp = ParseSuppressions(fullPath)
			cache[fullPath] = supp
		}

		if supp != nil && supp[f.RuleID] {
			continue // suppressed
		}
		filtered = append(filtered, f)
	}
	return filtered
}
