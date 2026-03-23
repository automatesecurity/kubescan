package filescan

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"kubescan/pkg/licensescan"
	"kubescan/pkg/policy"
)

func TestScanPathDetectsSecretsAndManifestFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN=super-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deployment.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  template:
    spec:
      containers:
        - name: api
          image: nginx:latest
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}

	assertRulePresent(t, result.Findings, "KF001")
	assertRulePresent(t, result.Findings, "KS010")
}

func TestScanPathSkipsTemplatedValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN=${TOKEN}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "KF001" {
			t.Fatalf("did not expect plaintext secret finding for templated value")
		}
	}
}

func TestScanPathSkipsKnownBuildDirs(t *testing.T) {
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, ".env"), []byte("PASSWORD=hunter2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings from skipped dirs, got %+v", result.Findings)
	}
}

func TestScanPathFindsKnownSecretPatterns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.txt"), []byte("github_token=ghp_0123456789abcdef0123456789abcdef0123\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}

	assertRulePresent(t, result.Findings, "KF001")
}

func TestScanPathFindsDeniedLicenseDeclarations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"demo","license":"GPL-3.0-only"}`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPathWithOptions(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC), Options{
		LicensePolicy: licensescan.Policy{Denylist: []string{"GPL-3.0-only"}},
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}

	assertRulePresent(t, result.Findings, "KL001")
}

func TestScanPathAvoidsMarkdownAndSourceFalsePositives(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("completion_tokens: 42\napi_key: str\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy-site.yml"), []byte("id-token: write\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "KF001" {
			t.Fatalf("did not expect KF001 for benign docs/config examples, got %+v", result.Findings)
		}
	}
}

func TestScanPathSkipsLockfilesForSecretScanning(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"js-tokens","integrity":"sha512-abcdefghijklmnopqrstuvwxyz0123456789"}`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "KF001" {
			t.Fatalf("did not expect KF001 for lockfile, got %+v", result.Findings)
		}
	}
}

func TestScanPathRespectsExcludePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".plans"), 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".plans", "secret.env"), []byte("API_TOKEN=super-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN=super-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	result, err := ScanPathWithOptions(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC), Options{
		ExcludePaths: []string{".plans/**"},
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.RuleID == "KF001" {
			count++
			if finding.Resource.Name != ".env" {
				t.Fatalf("expected excluded path to be skipped, got %+v", result.Findings)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 KF001 finding after exclude, got %+v", result.Findings)
	}
}

func TestScanPathSecretModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("API_TOKEN=super-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	patternsResult, err := ScanPathWithOptions(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC), Options{
		SecretScanMode: "patterns",
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}
	if hasRule(patternsResult.Findings, "KF001") {
		t.Fatalf("did not expect KF001 in patterns mode, got %+v", patternsResult.Findings)
	}

	balancedResult, err := ScanPathWithOptions(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC), Options{
		SecretScanMode: "balanced",
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}
	if hasRule(balancedResult.Findings, "KF001") {
		t.Fatalf("did not expect KF001 in balanced mode for markdown, got %+v", balancedResult.Findings)
	}

	aggressiveResult, err := ScanPathWithOptions(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC), Options{
		SecretScanMode: "aggressive",
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}
	if !hasRule(aggressiveResult.Findings, "KF001") {
		t.Fatalf("expected KF001 in aggressive mode, got %+v", aggressiveResult.Findings)
	}
}

func TestScanPathSkipsSymlinkedFiles(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.env")
	if err := os.WriteFile(outside, []byte("API_TOKEN=super-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	link := filepath.Join(dir, "linked.env")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation not available: %v", err)
	}

	result, err := ScanPath(dir, policy.RuleProfileDefault, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}
	if hasRule(result.Findings, "KF001") {
		t.Fatalf("did not expect secret findings from symlinked file, got %+v", result.Findings)
	}
}

func assertRulePresent(t *testing.T, findings []policy.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s, got %+v", ruleID, findings)
}

func hasRule(findings []policy.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
