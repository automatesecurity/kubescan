package imagescan

import (
	"testing"
	"time"

	"kubescan/pkg/licensescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/secretscan"
)

func TestScanLayerFileFindsSecretsInConfigLikeFiles(t *testing.T) {
	findings := scanLayerFile(
		policy.ResourceRef{Kind: "Image", Name: "ghcr.io/acme/api:1.0.0"},
		"ghcr.io/acme/api:1.0.0",
		"app/.env",
		[]byte("API_TOKEN=super-secret\n"),
		licensescan.Policy{},
		secretscan.ModeBalanced,
		time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
	)

	assertLayerRulePresent(t, findings, "KI005")
}

func TestScanLayerFileFindsLicensePolicyViolations(t *testing.T) {
	findings := scanLayerFile(
		policy.ResourceRef{Kind: "Image", Name: "ghcr.io/acme/api:1.0.0"},
		"ghcr.io/acme/api:1.0.0",
		"app/package.json",
		[]byte(`{"name":"demo","license":"GPL-3.0-only"}`),
		licensescan.Policy{
			Allowlist: []string{"MIT"},
			Denylist:  []string{"GPL-3.0-only"},
		},
		secretscan.ModeBalanced,
		time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
	)

	assertLayerRulePresent(t, findings, "KI006")
	assertLayerRulePresent(t, findings, "KI007")
}

func TestScanLayerFileBalancedModeAvoidsMarkdownAssignmentNoise(t *testing.T) {
	findings := scanLayerFile(
		policy.ResourceRef{Kind: "Image", Name: "ghcr.io/acme/api:1.0.0"},
		"ghcr.io/acme/api:1.0.0",
		"app/README.md",
		[]byte("API_TOKEN=super-secret\n"),
		licensescan.Policy{},
		secretscan.ModeBalanced,
		time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
	)

	for _, finding := range findings {
		if finding.RuleID == "KI005" {
			t.Fatalf("did not expect KI005 for markdown in balanced mode, got %+v", findings)
		}
	}
}

func assertLayerRulePresent(t *testing.T, findings []policy.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s, got %+v", ruleID, findings)
}
