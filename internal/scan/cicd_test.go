package scan

import (
	"path/filepath"
	"testing"
)

// ── Trojan Source ─────────────────────────────────────────────────────────────

func TestGenericTrojanSourceRule(t *testing.T) {
	rule := &GenericTrojanSourceRule{
		BaseRule: BaseRule{RuleID: "generic-trojan-source", Sev: SeverityCritical, Cat: "obfuscation", Desc: "test"},
	}
	ctx := t.Context()

	// Create a temp file with RTL override
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "trojan.js")
	// U+202E RIGHT-TO-LEFT OVERRIDE followed by "abc"
	content := "// \u202Eabc\nvar x = 1;\n"
	if err := writeFile(f, content); err != nil {
		t.Fatal(err)
	}

	files := []string{"trojan.js"}
	findings, err := rule.Detect(ctx, tmpDir, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected trojan source findings, got 0")
	}
}

func TestGenericTrojanSourceRule_Clean(t *testing.T) {
	rule := &GenericTrojanSourceRule{
		BaseRule: BaseRule{RuleID: "generic-trojan-source", Sev: SeverityCritical, Cat: "obfuscation", Desc: "test"},
	}
	ctx := t.Context()

	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "clean.js")
	content := "// normal comment\nvar x = 1;\n"
	if err := writeFile(f, content); err != nil {
		t.Fatal(err)
	}

	files := []string{"clean.js"}
	findings, err := rule.Detect(ctx, tmpDir, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) > 0 {
		t.Errorf("expected 0 findings on clean file, got %d", len(findings))
	}
}

// ── Dockerfile ────────────────────────────────────────────────────────────────

func TestDockerfileDangerousRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := t.Context()
	target := testdataDir(t, "docker-dangerous")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "dockerfile-dangerous")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Dockerfile findings, got 0")
	}

	// Should flag USER root, ADD http, and curl | bash
	hasRoot := false
	hasADD := false
	hasCurl := false
	for _, f := range findings {
		if f.Line == 2 {
			hasRoot = true
		}
		if f.Line == 4 {
			hasADD = true
		}
		if f.Line == 5 {
			hasCurl = true
		}
	}
	if !hasRoot || !hasADD || !hasCurl {
		t.Errorf("expected findings at lines 2(USER root), 4(ADD http), 5(curl|bash)")
	}
}

// ── GitHub Actions ────────────────────────────────────────────────────────────

func TestActionsDangerousRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := t.Context()
	target := testdataDir(t, "actions-dangerous")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "actions-dangerous")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected Actions findings, got 0")
	}

	// Should flag curl|bash and GITHUB_TOKEN
	hasCurl := false
	hasToken := false
	for _, f := range findings {
		if f.Line == 9 {
			hasCurl = true
		}
		if f.Line == 12 {
			hasToken = true
		}
	}
	if !hasCurl {
		t.Error("expected curl|bash finding at line 9")
	}
	if !hasToken {
		t.Error("expected GITHUB_TOKEN finding at line 12")
	}
}
