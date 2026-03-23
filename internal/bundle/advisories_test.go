package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSignedAdvisories(t *testing.T) {
	dir := t.TempDir()
	bundlePath, keyPath := writeSignedBundleFixture(t, dir, "advisories", advisoryPayload())

	advisories, err := LoadSignedAdvisories(bundlePath, keyPath)
	if err != nil {
		t.Fatalf("LoadSignedAdvisories returned error: %v", err)
	}
	if got := len(advisories.Advisories); got != 1 {
		t.Fatalf("expected 1 advisory, got %d", got)
	}
	if advisories.Advisories[0].ID != "CVE-2026-0001" {
		t.Fatalf("unexpected advisory id %q", advisories.Advisories[0].ID)
	}
}

func TestLoadSignedBundleDefaultsSchemaMarkers(t *testing.T) {
	bundle, err := LoadSignedBundleBytes([]byte(`kind: SignedBundle
metadata:
  type: advisories
  algorithm: ed25519
payload: test
signature: ZmFrZQ==
`))
	if err != nil {
		t.Fatalf("LoadSignedBundleBytes returned error: %v", err)
	}
	if bundle.APIVersion != "" {
		t.Fatalf("expected apiVersion to remain empty for unsigned normalization safety, got %q", bundle.APIVersion)
	}
	if bundle.Kind != SignedBundleKind {
		t.Fatalf("expected kind %q, got %q", SignedBundleKind, bundle.Kind)
	}
}

func TestLoadSignedBundleRejectsUnsupportedSchemaMarkers(t *testing.T) {
	_, err := LoadSignedBundleBytes([]byte(`apiVersion: kubescan.io/v2
kind: SignedBundle
metadata:
  type: advisories
  algorithm: ed25519
payload: test
signature: ZmFrZQ==
`))
	if err == nil {
		t.Fatalf("expected schema validation error")
	}
}

func TestLoadSignedBundleAcceptsLegacySchemaMarker(t *testing.T) {
	bundle, err := LoadSignedBundleBytes([]byte(`apiVersion: security.kubescan.io/v1alpha1
kind: SignedBundle
metadata:
  type: advisories
  algorithm: ed25519
payload: test
signature: ZmFrZQ==
`))
	if err != nil {
		t.Fatalf("LoadSignedBundleBytes returned error: %v", err)
	}
	if bundle.APIVersion != LegacySignedBundleAPIVersion2 {
		t.Fatalf("expected legacy apiVersion to be preserved for signature safety, got %q", bundle.APIVersion)
	}
}

func TestVerifyBundleRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	bundlePath, keyPath := writeSignedBundleFixture(t, dir, "advisories", advisoryPayload())

	content, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	tampered := strings.Replace(string(content), "OpenSSL package vulnerability in the base image", "Tampered advisory payload", 1)
	if err := os.WriteFile(bundlePath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err = LoadSignedAdvisories(bundlePath, keyPath)
	if err == nil {
		t.Fatalf("expected tampered bundle to fail verification")
	}
}

func TestVerifyBundleRejectsMetadataTampering(t *testing.T) {
	dir := t.TempDir()
	bundlePath, keyPath := writeSignedBundleFixture(t, dir, "advisories", advisoryPayload())

	content, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	tampered := strings.Replace(string(content), "type: advisories", "type: rules", 1)
	if err := os.WriteFile(bundlePath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err = LoadSignedAdvisories(bundlePath, keyPath)
	if err == nil {
		t.Fatalf("expected metadata-tampered bundle to fail verification")
	}
}

func TestLoadSignedPolicyControls(t *testing.T) {
	dir := t.TempDir()
	bundlePath, keyPath := writeSignedBundleFixture(t, dir, "policy-controls", policyPayload())

	controls, err := LoadSignedPolicyControls(bundlePath, keyPath)
	if err != nil {
		t.Fatalf("LoadSignedPolicyControls returned error: %v", err)
	}
	if got := len(controls.Suppressions); got != 1 {
		t.Fatalf("expected 1 suppression, got %d", got)
	}
	if got := len(controls.SeverityOverrides); got != 1 {
		t.Fatalf("expected 1 severity override, got %d", got)
	}
}

func TestLoadSignedRuleBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath, keyPath := writeSignedBundleFixture(t, dir, "rules", rulePayload())

	ruleBundle, err := LoadSignedRuleBundle(bundlePath, keyPath)
	if err != nil {
		t.Fatalf("LoadSignedRuleBundle returned error: %v", err)
	}
	if got := len(ruleBundle.Rules); got != 2 {
		t.Fatalf("expected 2 rule configs, got %d", got)
	}
	if got := len(ruleBundle.CustomRules); got != 2 {
		t.Fatalf("expected 2 custom rules, got %d", got)
	}
	if ruleBundle.CustomRules[1].Target != "serviceAccount" {
		t.Fatalf("expected second custom rule target serviceAccount, got %q", ruleBundle.CustomRules[1].Target)
	}
	if got := len(ruleBundle.CustomRules[1].Match.All); got != 2 {
		t.Fatalf("expected 2 all predicates, got %d", got)
	}
	if got := len(ruleBundle.CustomRules[1].Match.Any); got != 1 {
		t.Fatalf("expected 1 any predicate, got %d", got)
	}
	if got := len(ruleBundle.CustomRules[1].Match.Not); got != 1 {
		t.Fatalf("expected 1 not predicate, got %d", got)
	}
	if got := len(ruleBundle.CustomRules[1].Match.Any[0].All); got != 2 {
		t.Fatalf("expected nested all predicate group, got %d", got)
	}
}

func writeSignedBundleFixture(t *testing.T, dir, bundleType, payload string) (string, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	payload = strings.TrimSuffix(payload, "\n")
	signedContent, err := signedBundleContent(SignedBundle{
		APIVersion: "kubescan.io/v1alpha1",
		Kind:       "SignedBundle",
		Metadata: BundleMetadata{
			Type:      bundleType,
			Algorithm: "ed25519",
		},
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("signedBundleContent returned error: %v", err)
	}
	signature := ed25519.Sign(privateKey, signedContent)

	bundleContent := `apiVersion: kubescan.io/v1alpha1
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})
	keyPath := filepath.Join(dir, "advisories.pub.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return bundlePath, keyPath
}

func advisoryPayload() string {
	return `apiVersion: kubescan.io/v1alpha1
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

func policyPayload() string {
	return `apiVersion: kubescan.io/v1alpha1
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
}

func rulePayload() string {
	return `apiVersion: kubescan.io/v1alpha1
kind: RuleBundle
rules:
  - id: KS003
    enabled: false
  - id: KS010
    severity: critical
customRules:
  - id: CR001
    target: container
    category: supply-chain
    title: Custom registry allowlist
    severity: high
    message: Container image is from ghcr.io/acme.
    remediation: Use the approved registry pattern.
    match:
      all:
        - field: image
          op: contains
          value: ghcr.io/acme/
  - id: CR002
    target: serviceAccount
    category: identity
    title: Service account needs hardening
    severity: high
    message: Service account is broadly reachable.
    remediation: Reduce automounting workloads and bound permissions.
    match:
      all:
        - field: hasWildcardPermissions
          op: equals
          value: true
        - field: workloadCount
          op: greater_than
          value: 0
      any:
        - all:
            - field: bindingCount
              op: greater_or_equal
              value: 1
            - field: automountingWorkloadCount
              op: greater_than
              value: 0
      not:
        - field: namespace
          op: equals
          value: kube-system
`
}

func indentBlock(value, prefix string) string {
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
