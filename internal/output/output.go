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
// verbose controls whether LOW-severity findings are shown in text output.
func FormatReport(report *Report, format Format, verbose bool) (string, error) {
	switch format {
	case FormatJSON:
		return formatJSON(report)
	case FormatText:
		return formatText(report, verbose)
	case FormatSARIF:
		return formatSARIF(report)
	default:
		return formatText(report, verbose)
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

func formatText(report *Report, verbose bool) (string, error) {
	var b strings.Builder

	if report.Summary.TotalFindings == 0 {
		b.WriteString("✓ No issues found\n")
		return b.String(), nil
	}

	// Summary header
	b.WriteString(fmt.Sprintf("%d total", report.Summary.TotalFindings))

	// Show severity breakdown for non-LOW only
	parts := make([]string, 0)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM"} {
		if count, ok := report.Summary.BySeverity[sev]; ok && count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", sev, count))
		}
	}
	if len(parts) > 0 {
		b.WriteString(" - ")
		b.WriteString(strings.Join(parts, ", "))
	}

	// Group findings by (severity, ruleID, message)
	type groupKey struct {
		sev     scan.Severity
		ruleID  string
		message string
	}
	groups := make(map[groupKey][]string)
	order := make([]groupKey, 0)

	for _, f := range report.Findings {
		// Skip LOW findings unless verbose
		if !verbose && f.Severity == scan.SeverityLow {
			continue
		}
		key := groupKey{sev: f.Severity, ruleID: f.RuleID, message: f.Message}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], loc)
	}

	// Render grouped findings
	for _, key := range order {
		locs := groups[key]
		color := ""
		switch key.sev {
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

		b.WriteString(fmt.Sprintf("\n%s[%s]%s %s%s%s — %s\n",
			color, key.sev, reset,
			cyan, key.ruleID, reset, key.message))

		if len(locs) == 1 {
			b.WriteString(fmt.Sprintf("     %s%s%s", gray, locs[0], reset))
		} else {
			b.WriteString(fmt.Sprintf("     %sFiles: %s%s", gray, strings.Join(locs, ", "), reset))
		}
	}

	b.WriteString("\n")
	return b.String(), nil
}
