package vuln

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"kubescan/pkg/k8s"
	"kubescan/pkg/policy"
)

func TestExampleVulnerabilityInputsMatchFindings(t *testing.T) {
	inventory := loadExampleInventory(t, "vuln-sample.yaml")
	sbom, err := LoadSBOM(filepath.Join("..", "..", "examples", "vuln-sbom.json"))
	if err != nil {
		t.Fatalf("LoadSBOM returned error: %v", err)
	}
	advisories, err := LoadAdvisories(filepath.Join("..", "..", "examples", "advisories.yaml"))
	if err != nil {
		t.Fatalf("LoadAdvisories returned error: %v", err)
	}

	findings := MatchInventory(inventory, SBOMIndex{sbom.ImageRef: sbom}, advisories, time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "CVE-2026-0001" {
		t.Fatalf("expected CVE-2026-0001, got %s", findings[0].RuleID)
	}
}

func TestExampleMultiSBOMInputsMatchFindings(t *testing.T) {
	inventory := loadExampleInventory(t, "vuln-multi.yaml")
	index, err := LoadSBOMIndex([]string{
		filepath.Join("..", "..", "examples", "vuln-sbom.json"),
		filepath.Join("..", "..", "examples", "vuln-worker-sbom.json"),
	}, LoadSBOM)
	if err != nil {
		t.Fatalf("LoadSBOMIndex returned error: %v", err)
	}
	advisories, err := LoadAdvisories(filepath.Join("..", "..", "examples", "advisories.yaml"))
	if err != nil {
		t.Fatalf("LoadAdvisories returned error: %v", err)
	}

	findings := MatchInventory(inventory, index, advisories, time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC))
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	assertFindingRulePresent(t, findings, "CVE-2026-0001")
	assertFindingRulePresent(t, findings, "CVE-2026-0002")
}

func loadExampleInventory(t *testing.T, file string) policy.Inventory {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "examples", file))
	if err != nil {
		t.Fatalf("Abs returned error: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer f.Close()

	inventory, err := k8s.LoadInventory(f)
	if err != nil {
		t.Fatalf("LoadInventory returned error: %v", err)
	}
	return inventory
}

func assertFindingRulePresent(t *testing.T, findings []policy.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected finding rule %s to be present", ruleID)
}
