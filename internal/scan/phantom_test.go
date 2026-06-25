package scan

import (
	"context"
	"strings"
	"testing"
)

// ── Detection tests ──────────────────────────────────────────────────────────

// TestNpmPhantomDependencyRule detects phantom dependencies
// that are declared in package.json but never imported in source files.
// Pattern: axios attack (Mar 2026) where plain-crypto-js was injected as
// a runtime dependency but never imported — acted as postinstall RAT vector.
func TestNpmPhantomDependencyRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-phantom-dependency")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-phantom-dependency")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected phantom dependency finding for plain-crypto-js, got 0")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "plain-crypto-js") {
			found = true
			break
		}
	}
	if !found {
		t.Error("plain-crypto-js should be flagged as phantom dependency (declared but never imported)")
	}
}

// TestNpmPhantomWithPostinstall flags phantoms that ALSO have a postinstall script.
// This is the real threat model — a phantom dep with a lifecycle hook.
func TestNpmPhantomWithPostinstall(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-phantom-with-postinstall")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-phantom-dependency")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Message, "plain-crypto-js") {
			found = true
			break
		}
	}
	if !found {
		t.Error("plain-crypto-js should be flagged as phantom even with postinstall script in host package")
	}
}

// ── False-positive prevention tests ──────────────────────────────────────────

// TestNpmPhantomCleanImports produces 0 findings when all deps are imported.
func TestNpmPhantomCleanImports(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-clean-imports")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-phantom-dependency")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 phantom findings on clean imports, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s", f.Message)
		}
	}
}

// TestNpmPhantomPluginDeps produces 0 findings when deps are
// known plugin/config packages that are never directly imported.
func TestNpmPhantomPluginDeps(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "npm-plugin-deps")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-phantom-dependency")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 phantom findings on plugin deps, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s", f.Message)
		}
	}
}

// TestNpmPhantomNoSourceFiles produces 0 findings when no JS/TS
// source files exist (can't determine what's a phantom).
func TestNpmPhantomNoSourceFiles(t *testing.T) {
	// Use a dir with package.json but no .js/.ts source files
	// The clean directory has only safe.sh and no JS files
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "clean")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-phantom-dependency")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 phantom findings with no JS source files, got %d", len(findings))
	}
}

// TestNpmPhantomNoPackageJson produces 0 findings when no package.json exists.
func TestNpmPhantomNoPackageJson(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "shell-malware") // has .sh files, no package.json

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "npm-phantom-dependency")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 phantom findings with no package.json, got %d", len(findings))
	}
}
