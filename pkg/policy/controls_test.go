package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyControlsSuppressesMatchingFinding(t *testing.T) {
	findings := []Finding{
		{
			RuleID:   "KS012",
			Severity: SeverityMedium,
			Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
		},
		{
			RuleID:   "KS012",
			Severity: SeverityMedium,
			Resource: ResourceRef{Kind: "Deployment", Namespace: "orders", Name: "api"},
		},
	}

	processed, err := ApplyControls(findings, Controls{
		Suppressions: []Suppression{
			{
				RuleID:    "KS012",
				Namespace: "payments",
				Kind:      "Deployment",
				Name:      "api",
				ExpiresOn: "2099-01-01",
			},
		},
	}, time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ApplyControls returned error: %v", err)
	}

	if got := len(processed); got != 1 {
		t.Fatalf("expected 1 remaining finding, got %d", got)
	}
	if processed[0].Resource.Namespace != "orders" {
		t.Fatalf("expected orders finding to remain, got %q", processed[0].Resource.Namespace)
	}
}

func TestApplyControlsIgnoresExpiredSuppression(t *testing.T) {
	findings := []Finding{
		{
			RuleID:   "KS012",
			Severity: SeverityMedium,
			Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
		},
	}

	processed, err := ApplyControls(findings, Controls{
		Suppressions: []Suppression{
			{
				RuleID:    "KS012",
				Namespace: "payments",
				Kind:      "Deployment",
				Name:      "api",
				ExpiresOn: "2026-03-19",
			},
		},
	}, time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ApplyControls returned error: %v", err)
	}

	if got := len(processed); got != 1 {
		t.Fatalf("expected expired suppression to be ignored, got %d findings", got)
	}
}

func TestApplyControlsAppliesSeverityOverride(t *testing.T) {
	findings := []Finding{
		{
			RuleID:   "KS010",
			Severity: SeverityHigh,
			Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
		},
	}

	processed, err := ApplyControls(findings, Controls{
		SeverityOverrides: []SeverityOverride{
			{
				RuleID:    "KS010",
				Namespace: "payments",
				Kind:      "Deployment",
				Name:      "api",
				Severity:  SeverityCritical,
			},
		},
	}, time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ApplyControls returned error: %v", err)
	}

	if got := len(processed); got != 1 {
		t.Fatalf("expected 1 finding, got %d", got)
	}
	if processed[0].Severity != SeverityCritical {
		t.Fatalf("expected severity critical, got %s", processed[0].Severity)
	}
	if processed[0].OriginalSeverity != SeverityHigh {
		t.Fatalf("expected original severity high, got %s", processed[0].OriginalSeverity)
	}
}

func TestLoadControlsValidatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := `
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: PolicyControls
suppressions:
  - ruleId: KS012
    namespace: payments
    kind: Deployment
    name: api
    expiresOn: 2026-12-31
severityOverrides:
  - ruleId: KS010
    namespace: payments
    kind: Deployment
    name: api
    severity: critical
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	controls, err := LoadControls(path)
	if err != nil {
		t.Fatalf("LoadControls returned error: %v", err)
	}
	if got := len(controls.Suppressions); got != 1 {
		t.Fatalf("expected 1 suppression, got %d", got)
	}
	if got := len(controls.SeverityOverrides); got != 1 {
		t.Fatalf("expected 1 severity override, got %d", got)
	}
	if controls.APIVersion != ControlsAPIVersion {
		t.Fatalf("expected apiVersion %q, got %q", ControlsAPIVersion, controls.APIVersion)
	}
	if controls.Kind != ControlsKind {
		t.Fatalf("expected kind %q, got %q", ControlsKind, controls.Kind)
	}
}

func TestLoadControlsDefaultsSchemaMarkers(t *testing.T) {
	controls, err := LoadControlsBytes([]byte(`
suppressions:
  - ruleId: KS012
`))
	if err != nil {
		t.Fatalf("LoadControlsBytes returned error: %v", err)
	}
	if controls.APIVersion != ControlsAPIVersion {
		t.Fatalf("expected default apiVersion %q, got %q", ControlsAPIVersion, controls.APIVersion)
	}
	if controls.Kind != ControlsKind {
		t.Fatalf("expected default kind %q, got %q", ControlsKind, controls.Kind)
	}
}

func TestLoadControlsRejectsUnsupportedSchemaMarkers(t *testing.T) {
	_, err := LoadControlsBytes([]byte(`
apiVersion: kubescan.io/v2
kind: PolicyControls
suppressions:
  - ruleId: KS012
`))
	if err == nil {
		t.Fatalf("expected schema validation error")
	}
}
