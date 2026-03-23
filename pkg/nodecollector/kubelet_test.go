package nodecollector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadKubeletObservations(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "var", "lib", "kubelet")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`
authentication:
  anonymous:
    enabled: true
  webhook:
    enabled: false
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: AlwaysAllow
readOnlyPort: 10255
protectKernelDefaults: false
failSwapOn: false
rotateCertificates: false
serverTLSBootstrap: false
seccompDefault: false
`), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	observations, err := LoadKubeletObservations("node-a", root, "/var/lib/kubelet/config.yaml")
	if err != nil {
		t.Fatalf("LoadKubeletObservations returned error: %v", err)
	}
	if observations.NodeName != "node-a" {
		t.Fatalf("expected node name node-a, got %q", observations.NodeName)
	}
	if observations.KubeletConfigPath != "/var/lib/kubelet/config.yaml" {
		t.Fatalf("expected normalized config path, got %q", observations.KubeletConfigPath)
	}
	if observations.AnonymousAuthEnabled == nil || !*observations.AnonymousAuthEnabled {
		t.Fatalf("expected anonymous auth enabled")
	}
	if observations.WebhookAuthenticationEnabled == nil || *observations.WebhookAuthenticationEnabled {
		t.Fatalf("expected webhook authentication disabled")
	}
	if observations.AuthorizationMode != "AlwaysAllow" {
		t.Fatalf("expected authorization mode AlwaysAllow, got %q", observations.AuthorizationMode)
	}
	if observations.AuthenticationX509ClientCAFile != "/etc/kubernetes/pki/ca.crt" {
		t.Fatalf("expected x509 client CA file, got %q", observations.AuthenticationX509ClientCAFile)
	}
	if observations.ReadOnlyPort == nil || *observations.ReadOnlyPort != 10255 {
		t.Fatalf("expected readOnlyPort 10255, got %#v", observations.ReadOnlyPort)
	}
	if observations.ProtectKernelDefaults == nil || *observations.ProtectKernelDefaults {
		t.Fatalf("expected protectKernelDefaults false")
	}
	if observations.FailSwapOn == nil || *observations.FailSwapOn {
		t.Fatalf("expected failSwapOn false")
	}
	if observations.RotateCertificates == nil || *observations.RotateCertificates {
		t.Fatalf("expected rotateCertificates false")
	}
	if observations.ServerTLSBootstrap == nil || *observations.ServerTLSBootstrap {
		t.Fatalf("expected serverTLSBootstrap false")
	}
	if observations.SeccompDefault == nil || *observations.SeccompDefault {
		t.Fatalf("expected seccompDefault false")
	}
}

func TestBuildNodeReportError(t *testing.T) {
	report := BuildNodeReportError("node-a", "/var/lib/kubelet/config.yaml", time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC), os.ErrNotExist)
	if report.Status.Phase != "Error" {
		t.Fatalf("expected error phase, got %q", report.Status.Phase)
	}
	if report.Spec.NodeName != "node-a" {
		t.Fatalf("expected node name node-a, got %q", report.Spec.NodeName)
	}
	if report.Spec.KubeletConfigPath != "/var/lib/kubelet/config.yaml" {
		t.Fatalf("expected config path, got %q", report.Spec.KubeletConfigPath)
	}
	if report.Status.LastError == "" {
		t.Fatalf("expected lastError to be populated")
	}
}
