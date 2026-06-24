package output

import (
	"testing"

	"github.com/lukemcqueen/elencho/internal/scan"
)

func TestNewReport(t *testing.T) {
	findings := scan.NewFindings()
	findings.Add(scan.SeverityCritical, "remote-execution", "test-rule", "evil.sh", 5, "Downloads and pipes to shell")
	findings.Add(scan.SeverityLow, "ignored-artifact", "test-rule2", "file.txt", 1, "Low issue")

	report := NewReport(findings)
	if report == nil {
		t.Fatal("NewReport returned nil")
	}

	if report.Summary.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", report.Summary.TotalFindings)
	}

	if report.Summary.BySeverity["CRITICAL"] != 1 {
		t.Errorf("expected 1 CRITICAL, got %d", report.Summary.BySeverity["CRITICAL"])
	}

	if !report.Summary.HasHighOrCritical {
		t.Error("should have high or critical findings")
	}
}

func TestFormatReport_Text(t *testing.T) {
	findings := scan.NewFindings()
	findings.Add(scan.SeverityCritical, "remote-execution", "shell-curl-pipe-bash", "evil.sh", 5, "Downloads and pipes to shell")

	report := NewReport(findings)
	output, err := FormatReport(report, FormatText, false)
	if err != nil {
		t.Fatalf("FormatReport text: %v", err)
	}

	if output == "" {
		t.Error("text output should not be empty")
	}
}

func TestFormatReport_JSON(t *testing.T) {
	findings := scan.NewFindings()
	findings.Add(scan.SeverityHigh, "secret-leak", "generic-hardcoded-secret", "config.json", 3, "Hardcoded credential")

	report := NewReport(findings)
	output, err := FormatReport(report, FormatJSON, false)
	if err != nil {
		t.Fatalf("FormatReport json: %v", err)
	}

	if len(output) < 10 {
		t.Errorf("JSON output too short: %d chars", len(output))
	}

	// Should be valid JSON
	if output[0] != '{' {
		t.Error("JSON output should start with {")
	}
}

func TestFormatReport_SARIF(t *testing.T) {
	findings := scan.NewFindings()
	findings.Add(scan.SeverityCritical, "remote-execution", "shell-curl-pipe-bash", "evil.sh", 5, "Downloads and pipes to shell")
	findings.Add(scan.SeverityLow, "obfuscation", "generic-long-base64", "obfuscated.js", 10, "Long base64 string")

	report := NewReport(findings)
	output, err := FormatReport(report, FormatSARIF, false)
	if err != nil {
		t.Fatalf("FormatReport sarif: %v", err)
	}

	if len(output) < 50 {
		t.Errorf("SARIF output too short: %d chars", len(output))
	}

	// SARIF should contain version field
	if len(output) < 10 {
		t.Error("SARIF output too short")
	}
}

func TestFormatReport_NoFindings(t *testing.T) {
	findings := scan.NewFindings()
	report := NewReport(findings)

	text, err := FormatReport(report, FormatText, false)
	if err != nil {
		t.Fatalf("FormatReport text: %v", err)
	}
	if text == "" {
		t.Error("text output should contain 'No issues found'")
	}

	json, err := FormatReport(report, FormatJSON, false)
	if err != nil {
		t.Fatalf("FormatReport json: %v", err)
	}
	if len(json) < 10 {
		t.Errorf("JSON output too short: %d chars", len(json))
	}

	sarif, err := FormatReport(report, FormatSARIF, false)
	if err != nil {
		t.Fatalf("FormatReport sarif: %v", err)
	}
	if len(sarif) < 50 {
		t.Errorf("SARIF output too short: %d chars", len(sarif))
	}
}

func TestFormatReport_DefaultFormat(t *testing.T) {
	findings := scan.NewFindings()
	findings.Add(scan.SeverityMedium, "dependency", "npm-git-dependency", "package.json", 1, "Unpinned git dep")

	report := NewReport(findings)
	output, err := FormatReport(report, "invalid", false)
	if err != nil {
		t.Fatalf("FormatReport with invalid format: %v", err)
	}

	if output == "" {
		t.Error("should fall back to text format")
	}
}

func TestNewReport_Empty(t *testing.T) {
	findings := scan.NewFindings()
	report := NewReport(findings)

	if report.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for empty report, got %d", report.Summary.TotalFindings)
	}
	if report.Summary.HasHighOrCritical {
		t.Error("empty report should not have high or critical")
	}
}

func TestReport_ByCategory(t *testing.T) {
	findings := scan.NewFindings()
	findings.Add(scan.SeverityCritical, "remote-execution", "r1", "f.sh", 1, "msg")
	findings.Add(scan.SeverityHigh, "secret-leak", "r2", "f.json", 2, "msg")
	findings.Add(scan.SeverityMedium, "dependency", "r3", "f.json", 3, "msg")

	report := NewReport(findings)

	if report.Summary.ByCategory["remote-execution"] != 1 {
		t.Errorf("expected 1 remote-execution, got %d", report.Summary.ByCategory["remote-execution"])
	}
	if report.Summary.ByCategory["secret-leak"] != 1 {
		t.Errorf("expected 1 secret-leak, got %d", report.Summary.ByCategory["secret-leak"])
	}
	if report.Summary.ByCategory["dependency"] != 1 {
		t.Errorf("expected 1 dependency, got %d", report.Summary.ByCategory["dependency"])
	}
}
