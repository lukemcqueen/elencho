package scan

import (
	"context"
	"testing"
)

// ── Detection tests ──────────────────────────────────────────────────────────

// TestAiConfigPersistenceRule detects AI tool config files
// with auto-execution capabilities — the Miasma worm persistence pattern.
func TestAiConfigPersistenceRule(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "ai-persistence")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "ai-config-persistence")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 AI config persistence findings, got %d", len(findings))
	}

	flagged := make(map[string]bool)
	for _, f := range findings {
		flagged[f.File] = true
	}

	if !flagged[".claude/settings.json"] {
		t.Error(".claude/settings.json should be flagged for onSessionStart hook")
	}
	if !flagged[".vscode/tasks.json"] {
		t.Error(".vscode/tasks.json should be flagged for folderOpen auto-run")
	}

	// clean-settings.json has no dangerous content — should NOT be flagged
	if flagged["clean-settings.json"] {
		t.Error("clean-settings.json (no dangerous content) should NOT be flagged")
	}
}

// ── False-positive prevention tests ──────────────────────────────────────────

// TestAiConfigLegitimateTasks produces 0 findings for legitimate VS Code
// tasks that don't have auto-run (folderOpen) or download commands.
func TestAiConfigLegitimateTasks(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	target := testdataDir(t, "ai-legitimate-tasks")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "ai-config-persistence")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 findings on legitimate VS Code tasks (no folderOpen), got %d", len(findings))
		for _, f := range findings {
			t.Logf("  unexpected finding: %s", f.Message)
		}
	}
}

// TestAiConfigNoAiFiles produces 0 findings on directories without AI configs.
func TestAiConfigNoAiFiles(t *testing.T) {
	reg := DefaultRegistry()
	ctx := context.Background()
	// shell-malware has no .claude/.cursor/.vscode files
	target := testdataDir(t, "shell-malware")

	files, err := discoverFiles(target, DefaultScanOptions(target))
	if err != nil {
		t.Fatalf("discoverFiles: %v", err)
	}

	rule := findRule(reg, "ai-config-persistence")
	findings, err := rule.Detect(ctx, target, files)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("expected 0 findings on shell-malware (no AI configs), got %d", len(findings))
	}
}
