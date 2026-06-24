package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lukemcqueen/elencho/internal/scan"
)

// SARIFReport represents a SARIF 2.1 format report.
// This is a minimal implementation covering the fields we need.
type SARIFReport struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema,omitempty"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool            `json:"tool"`
	Results []SARIFResult        `json:"results"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string          `json:"name"`
	Version         string          `json:"version,omitempty"`
	InformationURI string          `json:"informationUri,omitempty"`
	Rules           []SARIFRule     `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID              string              `json:"id"`
	Name            string              `json:"name,omitempty"`
	ShortDescription SARIFMessage       `json:"shortDescription,omitempty"`
	FullDescription  SARIFMessage       `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFConfiguration `json:"defaultConfiguration,omitempty"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID    string       `json:"ruleId"`
	Level     string       `json:"level"`
	Message   SARIFMessage `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func severityToSARIFLevel(sev scan.Severity) string {
	switch sev {
	case scan.SeverityCritical:
		return "error"
	case scan.SeverityHigh:
		return "error"
	case scan.SeverityMedium:
		return "warning"
	case scan.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

func severityToSARIFConfigLevel(sev scan.Severity) string {
	switch sev {
	case scan.SeverityCritical, scan.SeverityHigh:
		return "error"
	case scan.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func formatSARIF(report *Report) (string, error) {
	if len(report.Findings) == 0 {
		empty := SARIFReport{
			Version: "2.1.0",
			Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
			Runs: []SARIFRun{{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "Elencho",
						Version: "0.1.0",
					},
				},
				Results: []SARIFResult{},
			}},
		}
		data, err := json.MarshalIndent(empty, "", "  ")
		if err != nil {
			return "", fmt.Errorf("SARIF marshaling failed: %w", err)
		}
		return string(data), nil
	}

	// Build unique rules list from findings
	ruleMap := make(map[string]bool)
	var sarifRules []SARIFRule
	for _, f := range report.Findings {
		if !ruleMap[f.RuleID] {
			ruleMap[f.RuleID] = true
			sarifRules = append(sarifRules, SARIFRule{
				ID:   f.RuleID,
				Name: f.RuleID,
				ShortDescription: SARIFMessage{
					Text: f.Message,
				},
				DefaultConfiguration: SARIFConfiguration{
					Level: severityToSARIFConfigLevel(f.Severity),
				},
				Properties: map[string]interface{}{
					"category": f.Category,
					"severity": string(f.Severity),
				},
			})
		}
	}

	// Build results
	var sarifResults []SARIFResult
	for _, f := range report.Findings {
		uri := f.File
		if !strings.HasPrefix(uri, "file://") {
			uri = "file://" + uri
		}
		sarifResults = append(sarifResults, SARIFResult{
			RuleID: f.RuleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: SARIFMessage{
				Text: f.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: uri,
						},
						Region: SARIFRegion{
							StartLine: f.Line,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"category": f.Category,
				"severity": string(f.Severity),
			},
		})
	}

	sarifReport := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:    "Elencho",
					Version: "0.1.0",
					Rules:   sarifRules,
				},
			},
			Results: sarifResults,
			Properties: map[string]interface{}{
				"totalFindings":      report.Summary.TotalFindings,
				"hasHighOrCritical":  report.Summary.HasHighOrCritical,
			},
		}},
	}

	data, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return "", fmt.Errorf("SARIF marshaling failed: %w", err)
	}
	return string(data), nil
}
