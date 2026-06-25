package scan

import (
	"fmt"
	"strings"
)

// Severity levels for findings.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ValidSeverities returns all valid severity levels.
func ValidSeverities() []Severity {
	return []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// IsValidSeverity checks if the given severity is valid.
func IsValidSeverity(s string) bool {
	switch Severity(s) {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// Finding represents a single detection result from a rule.
type Finding struct {
	Severity   Severity `json:"severity"`
	Category   string   `json:"category"`
	RuleID     string   `json:"rule"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Message    string   `json:"message"`
	Confidence float64  `json:"confidence"` // 0.0 (probably FP) → 1.0 (definite finding)
	Suggestion string   `json:"suggestion,omitempty"`
	FixCommand string   `json:"fix_command,omitempty"`
}

// String returns a human-readable representation of the finding.
func (f *Finding) String() string {
	conf := ""
	if f.Confidence > 0 && f.Confidence < 1.0 {
		conf = fmt.Sprintf(" [confidence: %.0f%%]", f.Confidence*100)
	}
	return fmt.Sprintf("[%s]%s %s — %s\n       %s:%d",
		f.Severity, conf, f.RuleID, f.Message, f.File, f.Line)
}

// LowConfidence returns true if confidence is below the standard threshold (0.5).
func (f *Finding) LowConfidence() bool {
	return f.Confidence > 0 && f.Confidence < 0.5
}

// Findings is a collection of findings with severity-level tracking.
type Findings struct {
	items []Finding
}

// NewFindings creates a new empty findings collection.
func NewFindings() *Findings {
	return &Findings{items: make([]Finding, 0)}
}

// Add appends a finding to the collection.
func (f *Findings) Add(sev Severity, category, ruleID, file string, line int, message string) {
	f.items = append(f.items, Finding{
		Severity:   sev,
		Category:   category,
		RuleID:     ruleID,
		File:       file,
		Line:       line,
		Message:    message,
		Confidence: 1.0,
	})
}

// AddWithConfidence appends a finding with an explicit confidence value.
func (f *Findings) AddWithConfidence(sev Severity, category, ruleID, file string, line int, message string, confidence float64) {
	f.items = append(f.items, Finding{
		Severity:   sev,
		Category:   category,
		RuleID:     ruleID,
		File:       file,
		Line:       line,
		Message:    message,
		Confidence: confidence,
	})
}

// All returns all findings.
func (f *Findings) All() []Finding {
	return f.items
}

// Count returns the total number of findings.
func (f *Findings) Count() int {
	return len(f.items)
}

// CountBySeverity returns findings filtered by severity level.
func (f *Findings) CountBySeverity(sev Severity) int {
	count := 0
	for _, finding := range f.items {
		if finding.Severity == sev {
			count++
		}
	}
	return count
}

// HasHighOrCritical returns true if any finding is HIGH or CRITICAL severity.
func (f *Findings) HasHighOrCritical() bool {
	for _, finding := range f.items {
		if finding.Severity == SeverityHigh || finding.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// ExitCode returns 1 if any HIGH or CRITICAL finding exists, 0 otherwise.
func (f *Findings) ExitCode() int {
	if f.HasHighOrCritical() {
		return 1
	}
	return 0
}

func (f *Findings) String() string {
	var b strings.Builder
	for i, finding := range f.items {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(finding.String())
	}
	return b.String()
}
