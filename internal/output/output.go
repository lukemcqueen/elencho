package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lukemcqueen/elencho/internal/scan"
)

// Format defines the output format type.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatSARIF Format = "sarif"
)

// Report contains all scan results and metadata.
type Report struct {
	Findings []scan.Finding `json:"findings"`
	Summary  Summary        `json:"summary"`
}

// Summary contains aggregate statistics about the scan.
type Summary struct {
	TotalFindings      int            `json:"total_findings"`
	BySeverity        map[string]int `json:"by_severity"`
	ByCategory        map[string]int `json:"by_category"`
	HasHighOrCritical bool           `json:"has_high_or_critical"`
}

// NewReport creates a report from scan findings.
func NewReport(findings *scan.Findings) *Report {
	all := findings.All()
	bySev := make(map[string]int)
	byCat := make(map[string]int)

	for _, f := range all {
		bySev[string(f.Severity)]++
		byCat[f.Category]++
	}

	return &Report{
		Findings: all,
		Summary: Summary{
			TotalFindings:      len(all),
			BySeverity:        bySev,
			ByCategory:        byCat,
			HasHighOrCritical: findings.HasHighOrCritical(),
		},
	}
}

// FormatReport formats a report in the requested format.
func FormatReport(report *Report, format Format) (string, error) {
	switch format {
	case FormatJSON:
		return formatJSON(report)
	case FormatText:
		return formatText(report)
	case FormatSARIF:
		return formatSARIF(report)
	default:
		return formatText(report)
	}
}

type jsonOutput struct {
	Findings []scan.Finding `json:"findings"`
	Summary  Summary        `json:"summary"`
}

func formatJSON(report *Report) (string, error) {
	out := jsonOutput{
		Findings: report.Findings,
		Summary:  report.Summary,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON marshaling failed: %w", err)
	}
	return string(data), nil
}

func formatText(report *Report) (string, error) {
	var b strings.Builder

	if report.Summary.TotalFindings == 0 {
		b.WriteString("✓ No issues found\n")
		return b.String(), nil
	}

	// Summary header
	b.WriteString(fmt.Sprintf("Findings: %d total\n", report.Summary.TotalFindings))
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if count, ok := report.Summary.BySeverity[sev]; ok && count > 0 {
			b.WriteString(fmt.Sprintf("  %s: %d\n", sev, count))
		}
	}
	b.WriteString("\n")

	// Individual findings
	for _, f := range report.Findings {
		color := ""
		switch f.Severity {
		case scan.SeverityCritical, scan.SeverityHigh:
			color = "\033[0;31m" // red
		case scan.SeverityMedium:
			color = "\033[1;33m" // yellow
		default:
			color = "\033[0;90m" // gray
		}
		reset := "\033[0m"
		cyan := "\033[0;36m"
		gray := "\033[0;90m"

		b.WriteString(fmt.Sprintf("%s[%s]%s %s%s%s — %s\n",
			color, f.Severity, reset,
			cyan, f.RuleID, reset, f.Message))
		b.WriteString(fmt.Sprintf("       %s%s:%d%s\n\n",
			gray, f.File, f.Line, reset))
	}

	return b.String(), nil
}
