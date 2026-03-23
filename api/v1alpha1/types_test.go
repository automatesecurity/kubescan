package v1alpha1

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

type crdManifest struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Group string `yaml:"group"`
		Scope string `yaml:"scope"`
		Names struct {
			Plural string `yaml:"plural"`
			Kind   string `yaml:"kind"`
		} `yaml:"names"`
		Versions []struct {
			Name    string `yaml:"name"`
			Served  bool   `yaml:"served"`
			Storage bool   `yaml:"storage"`
		} `yaml:"versions"`
	} `yaml:"spec"`
}

func TestScanPolicyCRDContract(t *testing.T) {
	manifest := loadCRDManifest(t, filepath.Join("..", "..", "deploy", "crds", "security.automatesecurity.github.io_scanpolicies.yaml"))
	if manifest.Metadata.Name != "scanpolicies."+GroupName {
		t.Fatalf("unexpected metadata.name %q", manifest.Metadata.Name)
	}
	if manifest.Spec.Group != GroupName {
		t.Fatalf("unexpected group %q", manifest.Spec.Group)
	}
	if manifest.Spec.Scope != "Cluster" {
		t.Fatalf("unexpected scope %q", manifest.Spec.Scope)
	}
	if manifest.Spec.Names.Kind != ScanPolicyKind {
		t.Fatalf("unexpected kind %q", manifest.Spec.Names.Kind)
	}
	assertStoredVersion(t, manifest, Version)
}

func TestScanReportCRDContract(t *testing.T) {
	manifest := loadCRDManifest(t, filepath.Join("..", "..", "deploy", "crds", "security.automatesecurity.github.io_scanreports.yaml"))
	if manifest.Metadata.Name != "scanreports."+GroupName {
		t.Fatalf("unexpected metadata.name %q", manifest.Metadata.Name)
	}
	if manifest.Spec.Group != GroupName {
		t.Fatalf("unexpected group %q", manifest.Spec.Group)
	}
	if manifest.Spec.Scope != "Cluster" {
		t.Fatalf("unexpected scope %q", manifest.Spec.Scope)
	}
	if manifest.Spec.Names.Kind != ScanReportKind {
		t.Fatalf("unexpected kind %q", manifest.Spec.Names.Kind)
	}
	assertStoredVersion(t, manifest, Version)
}

func TestSBOMReportCRDContract(t *testing.T) {
	manifest := loadCRDManifest(t, filepath.Join("..", "..", "deploy", "crds", "security.automatesecurity.github.io_sbomreports.yaml"))
	if manifest.Metadata.Name != "sbomreports."+GroupName {
		t.Fatalf("unexpected metadata.name %q", manifest.Metadata.Name)
	}
	if manifest.Spec.Group != GroupName {
		t.Fatalf("unexpected group %q", manifest.Spec.Group)
	}
	if manifest.Spec.Scope != "Namespaced" {
		t.Fatalf("unexpected scope %q", manifest.Spec.Scope)
	}
	if manifest.Spec.Names.Kind != SBOMReportKind {
		t.Fatalf("unexpected kind %q", manifest.Spec.Names.Kind)
	}
	assertStoredVersion(t, manifest, Version)
}

func TestNodeReportCRDContract(t *testing.T) {
	manifest := loadCRDManifest(t, filepath.Join("..", "..", "deploy", "crds", "security.automatesecurity.github.io_nodereports.yaml"))
	if manifest.Metadata.Name != "nodereports."+GroupName {
		t.Fatalf("unexpected metadata.name %q", manifest.Metadata.Name)
	}
	if manifest.Spec.Group != GroupName {
		t.Fatalf("unexpected group %q", manifest.Spec.Group)
	}
	if manifest.Spec.Scope != "Cluster" {
		t.Fatalf("unexpected scope %q", manifest.Spec.Scope)
	}
	if manifest.Spec.Names.Kind != NodeReportKind {
		t.Fatalf("unexpected kind %q", manifest.Spec.Names.Kind)
	}
	assertStoredVersion(t, manifest, Version)
}

func loadCRDManifest(t *testing.T, path string) crdManifest {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	var manifest crdManifest
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		t.Fatalf("yaml.Unmarshal returned error: %v", err)
	}
	return manifest
}

func assertStoredVersion(t *testing.T, manifest crdManifest, version string) {
	t.Helper()
	if len(manifest.Spec.Versions) == 0 {
		t.Fatalf("expected CRD versions")
	}
	if manifest.Spec.Versions[0].Name != version {
		t.Fatalf("unexpected version %q", manifest.Spec.Versions[0].Name)
	}
	if !manifest.Spec.Versions[0].Served {
		t.Fatalf("expected version %q to be served", version)
	}
	if !manifest.Spec.Versions[0].Storage {
		t.Fatalf("expected version %q to be storage", version)
	}
}
