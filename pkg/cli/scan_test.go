package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kubescan/pkg/k8s"
	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

func TestRunScanUsesManifestInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--format", "json"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"findings\"") {
		t.Fatalf("expected JSON findings output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"apiVersion\": \"report.automatesecurity.github.io/v1\"") {
		t.Fatalf("expected stable scan result apiVersion, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"schemaVersion\": \"1.0.0\"") {
		t.Fatalf("expected stable scan result schemaVersion, got %s", stdout.String())
	}
}

func TestRunScanUsesClusterCollector(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	exitCode := runScan([]string{"--namespace", "payments", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: func(string) (policy.Inventory, error) {
			t.Fatalf("loadFromFile should not be called")
			return policy.Inventory{}, nil
		},
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		collect: func(_ context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
			called = true
			if options.Namespace != "payments" {
				t.Fatalf("expected namespace payments, got %q", options.Namespace)
			}
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !called {
		t.Fatalf("expected collect to be called")
	}
}

func TestRunScanRejectsComponentVulnsWithManifestInput(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runScan([]string{"--input", "sample.yaml", "--component-vulns", "--advisories", "components.yaml"}, &stdout, &stderr, scanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "only supported for live cluster scans") {
		t.Fatalf("expected component-vulns live cluster validation error, got %s", stderr.String())
	}
}

func TestRunScanRejectsComponentVulnsWithoutAdvisories(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runScan([]string{"--component-vulns"}, &stdout, &stderr, scanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--component-vulns requires --advisories or --advisories-bundle") {
		t.Fatalf("expected component-vulns advisory validation error, got %s", stderr.String())
	}
}

func TestRunScanRejectsMixedSources(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runScan([]string{"--input", "sample.yaml", "--namespace", "payments"}, &stdout, &stderr, scanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "cannot be combined with cluster scan flags") {
		t.Fatalf("expected mixed source error, got %s", stderr.String())
	}
}

func TestRunScanAppliesPolicyControls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := runScan([]string{"--input", path, "--policy", "controls.yaml", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: loadInventoryFromFile,
		loadPolicy: func(path string) (policy.Controls, error) {
			if path != "controls.yaml" {
				t.Fatalf("expected controls.yaml, got %q", path)
			}
			return policy.Controls{
				Suppressions: []policy.Suppression{
					{
						RuleID:    "KS003",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS005",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS006",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS007",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS008",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS009",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS011",
						Namespace: "payments",
						Kind:      "Service",
						Name:      "api",
					},
					{
						RuleID:    "KS012",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
					},
					{
						RuleID:    "KS014",
						Namespace: "payments",
						Kind:      "Namespace",
						Name:      "payments",
					},
				},
				SeverityOverrides: []policy.SeverityOverride{
					{
						RuleID:    "KS010",
						Namespace: "payments",
						Kind:      "Deployment",
						Name:      "api",
						Severity:  policy.SeverityCritical,
					},
				},
			}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"severity\": \"critical\"") {
		t.Fatalf("expected overridden severity in output, got %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "\"ruleId\": \"KS003\"") {
		t.Fatalf("expected suppressed finding KS003 to be absent, got %s", stdout.String())
	}
}

func TestRunScanWritesSARIFToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	outPath := filepath.Join(dir, "findings.sarif")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--format", "sarif", "--out", outPath}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected stdout to remain empty when --out is used, got %s", stdout.String())
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(content), "\"version\": \"2.1.0\"") {
		t.Fatalf("expected SARIF content in file, got %s", string(content))
	}
}

func TestRunScanWritesHTMLToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	outPath := filepath.Join(dir, "findings.html")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--format", "html", "--out", outPath}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected stdout to remain empty when --out is used, got %s", stdout.String())
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !strings.Contains(string(content), "Kubescan HTML Report") {
		t.Fatalf("expected HTML content in file, got %s", string(content))
	}
	if !strings.Contains(string(content), "<html") {
		t.Fatalf("expected HTML document in file, got %s", string(content))
	}
}

func TestRunScanRejectsAttackPathsWithSARIF(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--attack-paths", "--format", "sarif"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "not supported") {
		t.Fatalf("expected attack path sarif validation error, got %s", stderr.String())
	}
}

func TestRunScanFailOnThresholdReturnsZeroBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          image: nginx:1.27.1
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--fail-on", "critical"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 below threshold, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunScanFailOnThresholdReturnsFourAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          securityContext:
            privileged: true
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--fail-on", "critical"}, &stdout, &stderr)
	if exitCode != 4 {
		t.Fatalf("expected exit code 4 at threshold, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunScanRejectsInvalidFailOnSeverity(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--fail-on", "urgent"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "parse fail-on severity") {
		t.Fatalf("expected parse error, got %s", stderr.String())
	}
}

func TestRunScanRejectsInvalidComplianceProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--compliance", "bogus-profile"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "parse compliance profile") {
		t.Fatalf("expected compliance parse error, got %s", stderr.String())
	}
}

func TestRunScanRejectsInvalidRuleProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--profile", "strict"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "parse rule profile") {
		t.Fatalf("expected rule profile parse error, got %s", stderr.String())
	}
}

func TestRunScanIncludesComplianceReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          securityContext:
            privileged: true
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--compliance", "pss-restricted", "--format", "json"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"profile\": \"pss-restricted\"") {
		t.Fatalf("expected compliance report in output, got %s", stdout.String())
	}
}

func TestRunScanEnterpriseProfileIncludesEnterpriseRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          image: nginx:1.27.1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: payments
data:
  api_token: super-secret
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--profile", "enterprise", "--format", "json"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"KS032\"") {
		t.Fatalf("expected enterprise profile to include KS032, got %s", stdout.String())
	}
}

func TestRunScanAppliesInventoryFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: payments
spec:
  type: LoadBalancer
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--include-kind", "Service", "--format", "json"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String(), "\"ruleId\": \"KS010\"") {
		t.Fatalf("expected deployment finding to be filtered out, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"KS011\"") {
		t.Fatalf("expected service finding to remain, got %s", stdout.String())
	}
}

func TestRunScanWritesSummaryReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--report", "summary"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Kubescan Scan Summary") {
		t.Fatalf("expected summary output, got %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "payments/Deployment/api") {
		t.Fatalf("expected detailed findings to be omitted in summary mode, got %s", stdout.String())
	}
}

func TestRunScanRejectsSummarySarif(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--report", "summary", "--format", "sarif"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "not supported") {
		t.Fatalf("expected unsupported summary sarif error, got %s", stderr.String())
	}
}

func TestRunScanRejectsSummaryOCSF(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--report", "summary", "--format", "ocsf-json"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "not supported") {
		t.Fatalf("expected unsupported summary ocsf error, got %s", stderr.String())
	}
}

func TestRunScanRejectsInvalidColorMode(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--color", "rainbow"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "unsupported color mode") {
		t.Fatalf("expected color mode validation error, got %s", stderr.String())
	}
}

func TestRunScanWritesColoredTableWhenForced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          securityContext:
            privileged: true
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--color", "always"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("expected ANSI color sequences in output, got %q", stdout.String())
	}
}

func TestRunScanIncludesAttackPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attackpaths.yaml")
	if err := os.WriteFile(path, []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: api
      hostPID: true
      containers:
        - name: api
          image: nginx:latest
          securityContext:
            privileged: true
      volumes:
        - name: kubelet
          hostPath:
            path: /var/lib/kubelet
---
apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: payments
spec:
  type: LoadBalancer
  selector:
    app: api
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wildcard
  namespace: payments
rules:
  - verbs: ["*"]
    resources: ["pods"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bind-api
  namespace: payments
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: wildcard
subjects:
  - kind: ServiceAccount
    namespace: payments
    name: api
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--attack-paths", "--format", "json"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"attackPaths\"") {
		t.Fatalf("expected attack paths section in output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"id\": \"AP001\"") {
		t.Fatalf("expected AP001 in output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"id\": \"AP002\"") {
		t.Fatalf("expected AP002 in output, got %s", stdout.String())
	}
}

func TestRunScanWritesOCSFJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := RunScan([]string{"--input", path, "--format", "ocsf-json"}, &stdout, &stderr)
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"class_name\": \"Application Security Posture Finding\"") {
		t.Fatalf("expected OCSF class in output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"version\": \"1.8.0\"") {
		t.Fatalf("expected OCSF schema version in output, got %s", stdout.String())
	}
}

func TestRunScanUsesHelmChartSource(t *testing.T) {
	var stdout, stderr bytes.Buffer
	renderCalled := false
	loadBytesCalled := false

	exitCode := runScan([]string{"--helm-chart", ".\\chart", "--helm-values", ".\\values.yaml", "--format", "json"}, &stdout, &stderr, scanDeps{
		renderHelm: func(chartPath, releaseName, namespace string, valuesFiles []string) ([]byte, error) {
			renderCalled = true
			if chartPath != ".\\chart" {
				t.Fatalf("unexpected chart path %q", chartPath)
			}
			if releaseName != "kubescan" || namespace != "default" {
				t.Fatalf("unexpected helm render args %q %q", releaseName, namespace)
			}
			if len(valuesFiles) != 1 || valuesFiles[0] != ".\\values.yaml" {
				t.Fatalf("unexpected values files %v", valuesFiles)
			}
			return []byte("rendered"), nil
		},
		loadFromBytes: func(content []byte) (policy.Inventory, error) {
			loadBytesCalled = true
			if string(content) != "rendered" {
				t.Fatalf("unexpected rendered content %q", string(content))
			}
			return policy.Inventory{}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !renderCalled || !loadBytesCalled {
		t.Fatalf("expected helm render and loadFromBytes to be called")
	}
}

func TestRunScanUsesKustomizeSource(t *testing.T) {
	var stdout, stderr bytes.Buffer
	renderCalled := false

	exitCode := runScan([]string{"--kustomize-dir", ".\\overlay", "--format", "json"}, &stdout, &stderr, scanDeps{
		renderKustomize: func(path string) ([]byte, error) {
			renderCalled = true
			if path != ".\\overlay" {
				t.Fatalf("unexpected kustomize path %q", path)
			}
			return []byte("rendered"), nil
		},
		loadFromBytes: func(content []byte) (policy.Inventory, error) {
			return policy.Inventory{}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !renderCalled {
		t.Fatalf("expected kustomize render to be called")
	}
}

func TestRunScanRejectsMultipleExplicitSources(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--input", "a.yaml", "--helm-chart", ".\\chart"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("expected explicit source validation error, got %s", stderr.String())
	}
}

func TestRunScanRejectsHalfConfiguredVulnInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--sbom", "sample.json"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--sbom requires --advisories or --advisories-bundle") {
		t.Fatalf("expected paired-input error, got %s", stderr.String())
	}
}

func TestRunScanAddsVulnerabilityFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          image: ghcr.io/acme/api:1.0.0
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := runScan([]string{"--input", path, "--sbom", "image.sbom.json", "--advisories", "advisories.yaml", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: loadInventoryFromFile,
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		loadSBOM: func(path string) (vuln.SBOM, error) {
			if path != "image.sbom.json" {
				t.Fatalf("unexpected sbom path %q", path)
			}
			return vuln.SBOM{
				ImageRef: "ghcr.io/acme/api:1.0.0",
				Packages: []vuln.Package{
					{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
				},
			}, nil
		},
		loadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "advisories.yaml" {
				t.Fatalf("unexpected advisories path %q", path)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{
					{
						ID:               "CVE-2026-0001",
						PackageName:      "openssl",
						Ecosystem:        "apk",
						AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
						FixedVersion:     "1.1.1-r1",
						Severity:         policy.SeverityHigh,
						Summary:          "OpenSSL vulnerable package",
					},
				},
			}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-0001\"") {
		t.Fatalf("expected vulnerability finding in output, got %s", stdout.String())
	}
}

func TestRunScanAddsVulnerabilityFindingsFromMultipleSBOMs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          image: ghcr.io/acme/api:1.0.0
        - name: worker
          image: ghcr.io/acme/worker:2.0.0
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	loadCalls := 0
	exitCode := runScan([]string{"--input", path, "--sbom", "api.sbom.json", "--sbom", "worker.sbom.json", "--advisories", "advisories.yaml", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: loadInventoryFromFile,
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		loadSBOM: func(path string) (vuln.SBOM, error) {
			loadCalls++
			switch path {
			case "api.sbom.json":
				return vuln.SBOM{
					ImageRef: "ghcr.io/acme/api:1.0.0",
					Packages: []vuln.Package{
						{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
					},
				}, nil
			case "worker.sbom.json":
				return vuln.SBOM{
					ImageRef: "ghcr.io/acme/worker:2.0.0",
					Packages: []vuln.Package{
						{Name: "busybox", Version: "1.36.0-r0", Ecosystem: "apk"},
					},
				}, nil
			default:
				t.Fatalf("unexpected sbom path %q", path)
				return vuln.SBOM{}, nil
			}
		},
		loadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "advisories.yaml" {
				t.Fatalf("unexpected advisories path %q", path)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{
					{
						ID:               "CVE-2026-0001",
						PackageName:      "openssl",
						Ecosystem:        "apk",
						AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
						FixedVersion:     "1.1.1-r1",
						Severity:         policy.SeverityHigh,
						Summary:          "OpenSSL vulnerable package",
					},
					{
						ID:               "CVE-2026-0002",
						PackageName:      "busybox",
						Ecosystem:        "apk",
						AffectedVersions: []string{"<1.36.0-r2"},
						FixedVersion:     "1.36.0-r2",
						Severity:         policy.SeverityMedium,
						Summary:          "Busybox vulnerable package",
					},
				},
			}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if loadCalls != 2 {
		t.Fatalf("expected 2 sbom loads, got %d", loadCalls)
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-0001\"") {
		t.Fatalf("expected API vulnerability finding, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-0002\"") {
		t.Fatalf("expected worker vulnerability finding, got %s", stdout.String())
	}
}

func TestRunScanRejectsMissingBundleKey(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--sbom", "a.json", "--advisories-bundle", "bundle.yaml"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--policy-bundle and --advisories-bundle require --bundle-key") {
		t.Fatalf("expected bundle-key validation error, got %s", stderr.String())
	}
}

func TestRunScanRejectsPolicyBundleWithoutKey(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--policy-bundle", "policy.bundle.yaml"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--policy-bundle and --advisories-bundle require --bundle-key") {
		t.Fatalf("expected bundle-key validation error, got %s", stderr.String())
	}
}

func TestRunScanRejectsRulesBundleWithoutKey(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := RunScan([]string{"--rules-bundle", "rules.bundle.yaml"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--rules-bundle requires --bundle-key") {
		t.Fatalf("expected bundle-key validation error, got %s", stderr.String())
	}
}

func TestRunScanLoadsSignedPolicyBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := runScan([]string{"--input", path, "--policy-bundle", "policy.bundle.yaml", "--bundle-key", "policy.pub.pem", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: loadInventoryFromFile,
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		loadPolicyBundle: func(bundlePath, keyPath string) (policy.Controls, error) {
			if bundlePath != "policy.bundle.yaml" || keyPath != "policy.pub.pem" {
				t.Fatalf("unexpected signed policy inputs: %q %q", bundlePath, keyPath)
			}
			return policy.Controls{
				Suppressions: []policy.Suppression{
					{RuleID: "KS003", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS005", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS006", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS007", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS008", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS009", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS012", Namespace: "payments", Kind: "Deployment", Name: "api"},
					{RuleID: "KS014", Namespace: "payments", Kind: "Namespace", Name: "payments"},
				},
				SeverityOverrides: []policy.SeverityOverride{
					{RuleID: "KS010", Namespace: "payments", Kind: "Deployment", Name: "api", Severity: policy.SeverityCritical},
				},
			}, nil
		},
		loadSBOM: func(string) (vuln.SBOM, error) {
			t.Fatalf("loadSBOM should not be called")
			return vuln.SBOM{}, nil
		},
		loadAdvisories: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisories should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"severity\": \"critical\"") {
		t.Fatalf("expected overridden severity in output, got %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "\"ruleId\": \"KS003\"") {
		t.Fatalf("expected suppressed finding KS003 to be absent, got %s", stdout.String())
	}
}

func TestRunScanLoadsSignedRuleBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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

	var stdout, stderr bytes.Buffer
	exitCode := runScan([]string{"--input", path, "--rules-bundle", "rules.bundle.yaml", "--bundle-key", "rules.pub.pem", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: loadInventoryFromFile,
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		loadPolicyBundle: func(string, string) (policy.Controls, error) {
			t.Fatalf("loadPolicyBundle should not be called")
			return policy.Controls{}, nil
		},
		loadRuleBundle: func(bundlePath, keyPath string) (policy.RuleBundle, error) {
			if bundlePath != "rules.bundle.yaml" || keyPath != "rules.pub.pem" {
				t.Fatalf("unexpected signed rule inputs: %q %q", bundlePath, keyPath)
			}
			critical := policy.SeverityCritical
			disabled := false
			return policy.RuleBundle{
				Rules: []policy.RuleConfig{
					{ID: "KS003", Enabled: &disabled},
					{ID: "KS010", Severity: &critical},
				},
				CustomRules: []policy.CustomRuleSpec{
					{
						ID:          "CR001",
						Target:      "container",
						Category:    policy.CategorySupplyChain,
						Title:       "Custom registry allowlist",
						Severity:    policy.SeverityHigh,
						Message:     "Container image is from nginx registry.",
						Remediation: "Use the approved registry pattern.",
						Match: policy.MatchClause{
							All: []policy.Predicate{
								{Field: "image", Op: "contains", Value: "nginx"},
							},
						},
					},
				},
			}, nil
		},
		loadSBOM: func(string) (vuln.SBOM, error) {
			t.Fatalf("loadSBOM should not be called")
			return vuln.SBOM{}, nil
		},
		loadAdvisories: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisories should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String(), "\"ruleId\": \"KS003\"") {
		t.Fatalf("expected KS003 to be disabled, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"severity\": \"critical\"") {
		t.Fatalf("expected overridden severity in output, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CR001\"") {
		t.Fatalf("expected custom rule finding, got %s", stdout.String())
	}
}

func TestRunScanLoadsSignedAdvisoryBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte(`
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
          image: ghcr.io/acme/api:1.0.0
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := runScan([]string{"--input", path, "--sbom", "image.sbom.json", "--advisories-bundle", "advisories.bundle.yaml", "--bundle-key", "advisories.pub.pem", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: loadInventoryFromFile,
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		loadSBOM: func(path string) (vuln.SBOM, error) {
			return vuln.SBOM{
				ImageRef: "ghcr.io/acme/api:1.0.0",
				Packages: []vuln.Package{
					{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
				},
			}, nil
		},
		loadAdvisories: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisories should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadAdvisoryBundle: func(bundlePath, keyPath string) (vuln.AdvisoryBundle, error) {
			if bundlePath != "advisories.bundle.yaml" || keyPath != "advisories.pub.pem" {
				t.Fatalf("unexpected signed bundle inputs: %q %q", bundlePath, keyPath)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{
					{
						ID:               "CVE-2026-0001",
						PackageName:      "openssl",
						Ecosystem:        "apk",
						AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
						FixedVersion:     "1.1.1-r1",
						Severity:         policy.SeverityHigh,
						Summary:          "OpenSSL vulnerable package",
					},
				},
			}, nil
		},
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			t.Fatalf("collect should not be called")
			return policy.Inventory{}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-0001\"") {
		t.Fatalf("expected vulnerability finding in output, got %s", stdout.String())
	}
}

func TestRunScanMatchesClusterComponentVulnerabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runScan([]string{"--component-vulns", "--advisories", "components.yaml", "--format", "json"}, &stdout, &stderr, scanDeps{
		loadFromFile: func(string) (policy.Inventory, error) {
			t.Fatalf("loadFromFile should not be called")
			return policy.Inventory{}, nil
		},
		loadPolicy: func(string) (policy.Controls, error) {
			t.Fatalf("loadPolicy should not be called")
			return policy.Controls{}, nil
		},
		loadSBOM: func(string) (vuln.SBOM, error) {
			t.Fatalf("loadSBOM should not be called")
			return vuln.SBOM{}, nil
		},
		loadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "components.yaml" {
				t.Fatalf("expected advisory path components.yaml, got %q", path)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{
					{
						ID:               "CVE-2026-2001",
						PackageName:      "kubelet",
						Ecosystem:        "kubernetes",
						AffectedVersions: []string{">=v1.31.0,<v1.31.3"},
						FixedVersion:     "v1.31.3",
						Severity:         policy.SeverityHigh,
						Summary:          "Kubelet vulnerability",
					},
				},
			}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		collect: func(_ context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
			if options.Namespace != "" {
				t.Fatalf("expected all namespaces scan, got %q", options.Namespace)
			}
			return policy.Inventory{
				Components: []policy.ClusterComponent{
					{
						Resource:  policy.ResourceRef{Kind: "Node", Name: "worker-1"},
						Name:      "kubelet",
						Version:   "v1.31.1",
						Ecosystem: "kubernetes",
						Source:    "node.status.nodeInfo.kubeletVersion",
					},
				},
			}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-2001\"") {
		t.Fatalf("expected component vulnerability finding, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"componentName\": \"kubelet\"") {
		t.Fatalf("expected component evidence in output, got %s", stdout.String())
	}
}

func TestRunVerifyBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath, keyPath := writeSignedBundleFixture(t, dir, "advisories", advisoryPayload())

	var stdout, stderr bytes.Buffer
	exitCode := RunVerify([]string{"bundle", "--bundle", bundlePath, "--key", keyPath}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bundle verified") {
		t.Fatalf("expected verification output, got %s", stdout.String())
	}
}

func writeSignedBundleFixture(t *testing.T, dir, bundleType, payload string) (string, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	payload = strings.TrimSuffix(payload, "\n")
	signedContent, err := signedBundleContent("kubescan.automatesecurity.github.io/v1alpha1", "SignedBundle", bundleType, "ed25519", payload)
	if err != nil {
		t.Fatalf("signedBundleContent returned error: %v", err)
	}
	signature := ed25519.Sign(privateKey, signedContent)
	bundleContent := `apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: SignedBundle
metadata:
  type: ` + bundleType + `
  algorithm: ed25519
payload: |-
` + indentBlock(payload, "  ") + `
signature: ` + base64.StdEncoding.EncodeToString(signature) + `
`

	bundlePath := filepath.Join(dir, "advisories.bundle.yaml")
	if err := os.WriteFile(bundlePath, []byte(bundleContent), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey returned error: %v", err)
	}
	keyPath := filepath.Join(dir, "advisories.pub.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return bundlePath, keyPath
}

func signedBundleContent(apiVersion, kind, bundleType, algorithm, payload string) ([]byte, error) {
	envelope := struct {
		APIVersion string `json:"apiVersion,omitempty"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Type      string `json:"type"`
			Algorithm string `json:"algorithm"`
		} `json:"metadata"`
		Payload string `json:"payload"`
	}{
		APIVersion: apiVersion,
		Kind:       kind,
		Payload:    payload,
	}
	envelope.Metadata.Type = bundleType
	envelope.Metadata.Algorithm = algorithm
	return json.Marshal(envelope)
}

func advisoryPayload() string {
	return `apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: AdvisoryBundle
advisories:
  - id: CVE-2026-0001
    packageName: openssl
    ecosystem: apk
    affectedVersions:
      - ">=1.1.1-r0, <1.1.1-r2"
    fixedVersion: 1.1.1-r1
    severity: high
    summary: OpenSSL package vulnerability in the base image
`
}

func indentBlock(value, prefix string) string {
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

