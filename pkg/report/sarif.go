package report

import (
	"encoding/json"
	"io"

	"kubescan/pkg/policy"
)

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                   `json:"id"`
	Name                 string                   `json:"name"`
	ShortDescription     sarifMessage             `json:"shortDescription"`
	FullDescription      sarifMessage             `json:"fullDescription,omitempty"`
	Help                 sarifMessage             `json:"help,omitempty"`
	DefaultConfiguration sarifReportingDescriptor `json:"defaultConfiguration"`
}

type sarifReportingDescriptor struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

func WriteSARIF(w io.Writer, result ScanResult) error {
	report := buildSARIF(result)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func buildSARIF(result ScanResult) sarifReport {
	rules := []sarifRule{}
	seenRules := map[string]struct{}{}
	sarifResults := make([]sarifResult, 0, len(result.Findings))

	for _, finding := range result.Findings {
		if _, ok := seenRules[finding.RuleID]; !ok {
			seenRules[finding.RuleID] = struct{}{}
			rules = append(rules, sarifRule{
				ID:               finding.RuleID,
				Name:             finding.Title,
				ShortDescription: sarifMessage{Text: finding.Title},
				FullDescription:  sarifMessage{Text: finding.Message},
				Help:             sarifMessage{Text: finding.Remediation},
				DefaultConfiguration: sarifReportingDescriptor{
					Level: sarifLevel(finding.Severity),
				},
			})
		}

		properties := map[string]any{
			"category":     finding.Category,
			"severity":     finding.Severity,
			"resourceKind": finding.Resource.Kind,
			"resourceName": finding.Resource.Name,
			"namespace":    finding.Resource.Namespace,
		}
		if finding.OriginalSeverity != "" {
			properties["originalSeverity"] = finding.OriginalSeverity
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID:  finding.RuleID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifMessage{Text: finding.Message},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: resourceURI(finding.Resource),
						},
					},
					LogicalLocations: []sarifLogicalLocation{
						{
							Name:               finding.Resource.Name,
							FullyQualifiedName: fullyQualifiedResourceName(finding.Resource),
							Kind:               "kubernetesResource",
						},
					},
				},
			},
			Properties: properties,
		})
	}

	return sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "kubescan",
						Version: "dev",
						Rules:   rules,
					},
				},
				Results: sarifResults,
			},
		},
	}
}

func sarifLevel(severity policy.Severity) string {
	switch severity {
	case policy.SeverityCritical, policy.SeverityHigh:
		return "error"
	case policy.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func resourceURI(resource policy.ResourceRef) string {
	if resource.Namespace != "" {
		return "k8s://" + resource.Namespace + "/" + resource.Kind + "/" + resource.Name
	}
	return "k8s://cluster/" + resource.Kind + "/" + resource.Name
}

func fullyQualifiedResourceName(resource policy.ResourceRef) string {
	if resource.Namespace != "" {
		return resource.Namespace + "/" + resource.Kind + "/" + resource.Name
	}
	return resource.Kind + "/" + resource.Name
}
