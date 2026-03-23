package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRuleBundleAllowsNumericComparisonOperators(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR100",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace threshold rule",
				Severity:    SeverityHigh,
				Message:     "Namespace exceeds the threshold.",
				Remediation: "Reduce the count.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "publicServiceCount", Op: "greater_or_equal", Value: 2},
						{Field: "networkPolicyCount", Op: "less_than", Value: 1},
					},
				},
			},
		},
	}

	if err := ValidateRuleBundle(bundle); err != nil {
		t.Fatalf("ValidateRuleBundle returned error: %v", err)
	}
}

func TestValidateRuleBundleAllowsBooleanClauses(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR102",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace boolean rule",
				Severity:    SeverityHigh,
				Message:     "Namespace matches boolean logic.",
				Remediation: "Reduce exposure.",
				Match: MatchClause{
					Any: []Predicate{
						{Field: "hasPublicService", Op: "equals", Value: true},
					},
					Not: []Predicate{
						{Field: "hasNetworkPolicy", Op: "equals", Value: true},
					},
				},
			},
		},
	}

	if err := ValidateRuleBundle(bundle); err != nil {
		t.Fatalf("ValidateRuleBundle returned error: %v", err)
	}
}

func TestValidateRuleBundleAllowsNestedBooleanClauses(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR104",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Nested namespace rule",
				Severity:    SeverityHigh,
				Message:     "Namespace matches nested logic.",
				Remediation: "Reduce exposure.",
				Match: MatchClause{
					All: []Predicate{
						{
							Any: []Predicate{
								{Field: "hasPublicService", Op: "equals", Value: true},
								{
									All: []Predicate{
										{Field: "serviceCount", Op: "greater_than", Value: 1},
										{Field: "networkPolicyCount", Op: "less_than", Value: 1},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := ValidateRuleBundle(bundle); err != nil {
		t.Fatalf("ValidateRuleBundle returned error: %v", err)
	}
}

func TestValidateRuleBundleAllowsServiceAccountTarget(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR106",
				Target:      "serviceAccount",
				Category:    CategoryIdentity,
				Title:       "Service account rule",
				Severity:    SeverityHigh,
				Message:     "Service account is over-privileged.",
				Remediation: "Reduce bindings and permissions.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "hasWildcardPermissions", Op: "equals", Value: true},
					},
				},
			},
		},
	}

	if err := ValidateRuleBundle(bundle); err != nil {
		t.Fatalf("ValidateRuleBundle returned error: %v", err)
	}
}

func TestValidateRuleBundleRejectsUnknownOperator(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR101",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Invalid rule",
				Severity:    SeverityHigh,
				Message:     "Invalid operator.",
				Remediation: "Fix the operator.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "publicServiceCount", Op: "between", Value: 2},
					},
				},
			},
		},
	}

	err := ValidateRuleBundle(bundle)
	if err == nil {
		t.Fatalf("expected validation error for unknown operator")
	}
	if !strings.Contains(err.Error(), "unsupported operator") {
		t.Fatalf("expected unsupported operator error, got %v", err)
	}
}

func TestValidateRuleBundleRejectsEmptyMatchClause(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR103",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Empty match",
				Severity:    SeverityHigh,
				Message:     "Should fail validation.",
				Remediation: "Add predicates.",
			},
		},
	}

	err := ValidateRuleBundle(bundle)
	if err == nil {
		t.Fatalf("expected validation error for empty match clause")
	}
	if !strings.Contains(err.Error(), "requires at least one match predicate") {
		t.Fatalf("expected empty match validation error, got %v", err)
	}
}

func TestValidateRuleBundleRejectsMixedLeafAndNestedPredicate(t *testing.T) {
	bundle := RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR105",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Mixed predicate",
				Severity:    SeverityHigh,
				Message:     "Should fail validation.",
				Remediation: "Use either a leaf predicate or nested clauses.",
				Match: MatchClause{
					All: []Predicate{
						{
							Field: "hasPublicService",
							Op:    "equals",
							Value: true,
							Any: []Predicate{
								{Field: "serviceCount", Op: "greater_than", Value: 1},
							},
						},
					},
				},
			},
		},
	}

	err := ValidateRuleBundle(bundle)
	if err == nil {
		t.Fatalf("expected validation error for mixed leaf and nested predicate")
	}
	if !strings.Contains(err.Error(), "cannot mix predicate fields with nested boolean clauses") {
		t.Fatalf("expected mixed predicate validation error, got %v", err)
	}
}

func TestLoadRuleBundleDefaultsSchemaMarkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	content := `
rules:
  - id: KS003
    enabled: false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	bundle, err := LoadRuleBundle(path)
	if err != nil {
		t.Fatalf("LoadRuleBundle returned error: %v", err)
	}
	if bundle.APIVersion != RuleBundleAPIVersion {
		t.Fatalf("expected apiVersion %q, got %q", RuleBundleAPIVersion, bundle.APIVersion)
	}
	if bundle.Kind != RuleBundleKind {
		t.Fatalf("expected kind %q, got %q", RuleBundleKind, bundle.Kind)
	}
}

func TestLoadRuleBundleRejectsUnsupportedSchemaMarkers(t *testing.T) {
	_, err := LoadRuleBundleBytes([]byte(`
apiVersion: kubescan.io/v2
kind: RuleBundle
rules:
  - id: KS003
    enabled: false
`))
	if err == nil {
		t.Fatalf("expected schema validation error")
	}
}

