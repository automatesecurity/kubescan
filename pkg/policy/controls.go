package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

type Controls struct {
	APIVersion        string             `json:"apiVersion,omitempty" yaml:"apiVersion"`
	Kind              string             `json:"kind,omitempty" yaml:"kind"`
	Suppressions      []Suppression      `json:"suppressions,omitempty" yaml:"suppressions"`
	SeverityOverrides []SeverityOverride `json:"severityOverrides,omitempty" yaml:"severityOverrides"`
}

const (
	ControlsAPIVersion = "kubescan.automatesecurity.github.io/v1alpha1"
	ControlsKind       = "PolicyControls"
)

type Suppression struct {
	ID        string `json:"id,omitempty" yaml:"id"`
	RuleID    string `json:"ruleId" yaml:"ruleId"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace"`
	Kind      string `json:"kind,omitempty" yaml:"kind"`
	Name      string `json:"name,omitempty" yaml:"name"`
	ExpiresOn string `json:"expiresOn,omitempty" yaml:"expiresOn"`
	Reason    string `json:"reason,omitempty" yaml:"reason"`
}

type SeverityOverride struct {
	RuleID    string   `json:"ruleId" yaml:"ruleId"`
	Namespace string   `json:"namespace,omitempty" yaml:"namespace"`
	Kind      string   `json:"kind,omitempty" yaml:"kind"`
	Name      string   `json:"name,omitempty" yaml:"name"`
	Severity  Severity `json:"severity" yaml:"severity"`
}

func LoadControls(path string) (Controls, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Controls{}, fmt.Errorf("read policy file: %w", err)
	}
	return LoadControlsBytes(content)
}

func LoadControlsBytes(content []byte) (Controls, error) {
	var controls Controls
	if err := yaml.Unmarshal(content, &controls); err != nil {
		return Controls{}, fmt.Errorf("decode policy file: %w", err)
	}
	controls = normalizeControls(controls)
	if err := validateControls(controls); err != nil {
		return Controls{}, err
	}
	return controls, nil
}

func ApplyControls(findings []Finding, controls Controls, now time.Time) ([]Finding, error) {
	processed := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		updated := finding
		for _, override := range controls.SeverityOverrides {
			if !matchesFinding(override.RuleID, override.Namespace, override.Kind, override.Name, finding) {
				continue
			}
			if updated.Severity != override.Severity {
				updated.OriginalSeverity = updated.Severity
				updated.Severity = override.Severity
			}
		}

		suppressed := false
		for _, suppression := range controls.Suppressions {
			if !matchesFinding(suppression.RuleID, suppression.Namespace, suppression.Kind, suppression.Name, finding) {
				continue
			}
			active, err := suppressionActive(suppression, now)
			if err != nil {
				return nil, err
			}
			if active {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		processed = append(processed, updated)
	}
	return processed, nil
}

func validateControls(controls Controls) error {
	controls = normalizeControls(controls)
	if controls.APIVersion != ControlsAPIVersion {
		return fmt.Errorf("unsupported policy controls apiVersion %q", controls.APIVersion)
	}
	if controls.Kind != ControlsKind {
		return fmt.Errorf("policy controls kind must be %s", ControlsKind)
	}
	for _, suppression := range controls.Suppressions {
		if suppression.RuleID == "" {
			return fmt.Errorf("suppression ruleId is required")
		}
		if suppression.ExpiresOn != "" {
			if _, err := parseExpiration(suppression.ExpiresOn); err != nil {
				return fmt.Errorf("invalid suppression expiration for rule %s: %w", suppression.RuleID, err)
			}
		}
	}
	for _, override := range controls.SeverityOverrides {
		if override.RuleID == "" {
			return fmt.Errorf("severity override ruleId is required")
		}
		if !isValidSeverity(override.Severity) {
			return fmt.Errorf("invalid severity override %q for rule %s", override.Severity, override.RuleID)
		}
	}
	return nil
}

func normalizeControls(controls Controls) Controls {
	if strings.TrimSpace(controls.APIVersion) == "" {
		controls.APIVersion = ControlsAPIVersion
	} else if controls.APIVersion == "kubescan.io/v1alpha1" {
		controls.APIVersion = ControlsAPIVersion
	}
	if strings.TrimSpace(controls.Kind) == "" {
		controls.Kind = ControlsKind
	}
	return controls
}

func suppressionActive(suppression Suppression, now time.Time) (bool, error) {
	if suppression.ExpiresOn == "" {
		return true, nil
	}
	expiresAt, err := parseExpiration(suppression.ExpiresOn)
	if err != nil {
		return false, fmt.Errorf("parse suppression expiration: %w", err)
	}
	return !now.After(expiresAt), nil
}

func parseExpiration(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}

	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected YYYY-MM-DD or RFC3339 timestamp")
	}
	return time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 23, 59, 59, 0, time.UTC), nil
}

func matchesFinding(ruleID, namespace, kind, name string, finding Finding) bool {
	if ruleID != "" && ruleID != finding.RuleID {
		return false
	}
	if namespace != "" && namespace != finding.Resource.Namespace {
		return false
	}
	if kind != "" && !strings.EqualFold(kind, finding.Resource.Kind) {
		return false
	}
	if name != "" && name != finding.Resource.Name {
		return false
	}
	return true
}

func isValidSeverity(severity Severity) bool {
	switch strings.ToLower(string(severity)) {
	case string(SeverityLow), string(SeverityMedium), string(SeverityHigh), string(SeverityCritical):
		return true
	default:
		return false
	}
}
