package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"kubescan/pkg/k8s"
	"kubescan/pkg/policy"
)

func TestExampleManifestsEmitExpectedFindings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		file          string
		profile       policy.RuleProfile
		expectedRules []string
	}{
		{
			name:    "default sample",
			file:    "sample.yaml",
			profile: policy.RuleProfileDefault,
			expectedRules: []string{
				"KS003", "KS005", "KS010", "KS011", "KS022", "KS023", "KS030", "KS031",
			},
		},
		{
			name:    "hardening sample",
			file:    "hardening-sample.yaml",
			profile: policy.RuleProfileHardening,
			expectedRules: []string{
				"KS006", "KS007", "KS008", "KS009", "KS012", "KS018", "KS019", "KS027", "KS028", "KS030", "KS031",
			},
		},
		{
			name:    "enterprise sample",
			file:    "enterprise-sample.yaml",
			profile: policy.RuleProfileEnterprise,
			expectedRules: []string{
				"KS029", "KS032",
			},
		},
		{
			name:    "rbac sample",
			file:    "rbac-sample.yaml",
			profile: policy.RuleProfileDefault,
			expectedRules: []string{
				"KS013", "KS016", "KS017", "KS020", "KS021", "KS026",
			},
		},
		{
			name:    "badpods sample",
			file:    "badpods-sample.yaml",
			profile: policy.RuleProfileHardening,
			expectedRules: []string{
				"KS001", "KS002", "KS024", "KS033", "KS034", "KS035", "KS036",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inventory := loadExampleInventory(t, tc.file)
			findings := policy.EvaluateWithProfile(inventory, tc.profile)

			for _, ruleID := range tc.expectedRules {
				assertRulePresent(t, findings, ruleID)
			}
		})
	}
}

func loadExampleInventory(t *testing.T, file string) policy.Inventory {
	t.Helper()

	path := filepath.Join("..", "..", "examples", file)
	handle, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer handle.Close()

	inventory, err := k8s.LoadInventory(handle)
	if err != nil {
		t.Fatalf("LoadInventory returned error: %v", err)
	}
	return inventory
}

func assertRulePresent(t *testing.T, findings []policy.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to be present", ruleID)
}
