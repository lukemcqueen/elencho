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
		b.WriteString("no issues found.\n")
		return b.String(), nil
	}

	// Summary line
	high := report.Summary.BySeverity["HIGH"] + report.Summary.BySeverity["CRITICAL"]
	med := report.Summary.BySeverity["MEDIUM"]
	low := report.Summary.BySeverity["LOW"]

	if high+med == 0 {
		// Only LOW findings
		b.WriteString(fmt.Sprintf("no major issues. %d low priority found.", low))
	} else {
		// Has HIGH/MEDIUM findings
		parts := make([]string, 0)
		if high > 0 {
			parts = append(parts, fmt.Sprintf("%d high", high))
		}
		if med > 0 {
			parts = append(parts, fmt.Sprintf("%d medium", med))
		}
		if low > 0 {
			last := parts[len(parts)-1]
			parts[len(parts)-1] = last + " and " + fmt.Sprintf("%d low", low)
		}
		plural := "issues"
		if high+med+low == 1 {
			plural = "issue"
		}
		b.WriteString(strings.Join(parts, ", ") + " priority " + plural + " found.")
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
		green := "\033[0;32m"

		// Get suggestion and confidence from the first finding in the group
		var suggestion, fixCmd string
		lowConf := false
		for _, f := range report.Findings {
			if f.RuleID == key.ruleID {
				suggestion = f.Suggestion
				fixCmd = f.FixCommand
				lowConf = f.LowConfidence()
				break
			}
		}

		b.WriteString(fmt.Sprintf("\n%s[%s]%s %s%s%s — %s\n",
			color, key.sev, reset,
			cyan, key.ruleID, reset, key.message))

		if lowConf {
			b.WriteString(fmt.Sprintf("     %s⚠ Possibly a false positive (file context suggests benign)%s\n", "\033[1;33m", reset))
		}

		if len(locs) == 1 {
			b.WriteString(fmt.Sprintf("     %s%s%s", gray, locs[0], reset))
		} else {
			b.WriteString(fmt.Sprintf("     %sFiles: %s%s", gray, strings.Join(locs, ", "), reset))
		}

		if suggestion != "" {
			b.WriteString(fmt.Sprintf("\n     %sfix: %s%s", green, suggestion, reset))
			if fixCmd != "" {
				b.WriteString(fmt.Sprintf("\n     %s  $ %s%s", gray, fixCmd, reset))
			}
		}
	}

	b.WriteString("\n")
	return b.String(), nil
}
