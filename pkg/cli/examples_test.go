package cli

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kubescan/pkg/policy"
)

func TestRunScanScopedSummaryExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join("..", "..", "examples", "scoping-sample.yaml")

	exitCode := RunScan([]string{
		"--input", path,
		"--include-kind", "Service",
		"--include-namespace", "public",
		"--report", "summary",
		"--format", "json",
	}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"KS011\"") {
		t.Fatalf("expected KS011 in scoped summary output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"totalFindings\": 1") {
		t.Fatalf("expected a single finding in scoped summary output, got %s", stdout.String())
	}
}

func TestRunScanAttackPathsExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join("..", "..", "examples", "attackpaths-sample.yaml")

	exitCode := RunScan([]string{
		"--input", path,
		"--attack-paths",
		"--format", "json",
	}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	for _, attackPathID := range []string{"AP001", "AP002", "AP003", "AP004", "AP005", "AP006"} {
		if !strings.Contains(stdout.String(), "\"id\": \""+attackPathID+"\"") {
			t.Fatalf("expected %s in attack path output, got %s", attackPathID, stdout.String())
		}
	}
}

func TestRunFSExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join("..", "..", "examples", "fs-demo")

	exitCode := RunFS([]string{
		"--path", path,
		"--format", "json",
	}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"KF001\"") {
		t.Fatalf("expected KF001 in fs output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"KS010\"") {
		t.Fatalf("expected KS010 in fs output, got %s", stdout.String())
	}
}

func TestRunFSSecretExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join("..", "..", "examples", "secret-demo")

	exitCode := RunFS([]string{
		"--path", path,
		"--format", "json",
	}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"KF001\"") {
		t.Fatalf("expected KF001 in fs secret output, got %s", stdout.String())
	}
}

func TestRunFSLicenseExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join("..", "..", "examples", "license-demo")

	exitCode := RunFS([]string{
		"--path", path,
		"--license-deny", "GPL-3.0-only",
		"--format", "json",
	}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"KL001\"") {
		t.Fatalf("expected KL001 in fs license output, got %s", stdout.String())
	}
}

func TestRenderKustomizeExampleScans(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		if _, kubectlErr := exec.LookPath("kubectl"); kubectlErr != nil {
			t.Skip("kustomize renderer not available")
		}
	}

	path := filepath.Join("..", "..", "examples", "kustomize", "overlays", "prod")
	content, err := renderKustomizeDir(path)
	if err != nil {
		t.Fatalf("renderKustomizeDir returned error: %v", err)
	}
	inventory, err := loadInventoryFromBytes(content)
	if err != nil {
		t.Fatalf("loadInventoryFromBytes returned error: %v", err)
	}
	findings := evaluateRulesForProfile(inventory, policy.RuleProfileDefault, nil)

	assertFindingPresent(t, findings, "KS010")
	assertFindingPresent(t, findings, "KS011")
}

func TestRenderHelmExampleScansIfHelmAvailable(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}

	chart := filepath.Join("..", "..", "examples", "helm", "api")
	values := filepath.Join(chart, "values.yaml")
	content, err := renderHelmChart(chart, "kubescan", "default", []string{values})
	if err != nil {
		t.Fatalf("renderHelmChart returned error: %v", err)
	}
	inventory, err := loadInventoryFromBytes(content)
	if err != nil {
		t.Fatalf("loadInventoryFromBytes returned error: %v", err)
	}
	findings := evaluateRulesForProfile(inventory, policy.RuleProfileDefault, nil)

	assertFindingPresent(t, findings, "KS010")
	assertFindingPresent(t, findings, "KS011")
}

func assertFindingPresent(t *testing.T, findings []policy.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to be present", ruleID)
}
