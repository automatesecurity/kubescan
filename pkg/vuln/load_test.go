package vuln

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.json")
	content := `{
  "metadata": {
    "component": {
      "type": "container",
      "name": "ghcr.io/acme/api:1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "1.1.1-r0",
      "purl": "pkg:apk/alpine/openssl@1.1.1-r0"
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21"
    },
    {
      "type": "library",
      "name": "stdlib",
      "version": "1.0.0",
      "purl": "pkg:golang/std@1.0.0"
    }
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	sbom, err := LoadSBOM(path)
	if err != nil {
		t.Fatalf("LoadSBOM returned error: %v", err)
	}
	if sbom.ImageRef != "ghcr.io/acme/api:1.0.0" {
		t.Fatalf("unexpected image ref %q", sbom.ImageRef)
	}
	if got := len(sbom.Packages); got != 3 {
		t.Fatalf("expected 3 supported packages, got %d", got)
	}
}

func TestLoadSPDXSBOM(t *testing.T) {
	sbom, err := LoadSBOMBytes([]byte(`{
  "spdxVersion": "SPDX-2.3",
  "name": "ghcr.io/acme/api:1.0.0",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-1",
      "name": "github.com/google/uuid",
      "versionInfo": "1.6.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/github.com/google/uuid@1.6.0"
        }
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-2",
      "name": "org.slf4j:slf4j-api",
      "versionInfo": "2.0.13",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:maven/org.slf4j/slf4j-api@2.0.13"
        }
      ]
    }
  ]
}`))
	if err != nil {
		t.Fatalf("LoadSBOMBytes returned error: %v", err)
	}
	if sbom.ImageRef != "ghcr.io/acme/api:1.0.0" {
		t.Fatalf("unexpected image ref %q", sbom.ImageRef)
	}
	if got := len(sbom.Packages); got != 2 {
		t.Fatalf("expected 2 packages, got %d", got)
	}
}

func TestLoadAdvisories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "advisories.yaml")
	content := `
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: AdvisoryBundle
advisories:
  - id: CVE-2026-0001
    packageName: openssl
    ecosystem: apk
    affectedVersions: [">=1.1.1-r0, <1.1.1-r2"]
    fixedVersion: 1.1.1-r1
    severity: high
    summary: OpenSSL vulnerable package
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	bundle, err := LoadAdvisories(path)
	if err != nil {
		t.Fatalf("LoadAdvisories returned error: %v", err)
	}
	if got := len(bundle.Advisories); got != 1 {
		t.Fatalf("expected 1 advisory, got %d", got)
	}
	if bundle.Advisories[0].ID != "CVE-2026-0001" {
		t.Fatalf("unexpected advisory id %q", bundle.Advisories[0].ID)
	}
	if bundle.APIVersion != AdvisoryBundleAPIVersion {
		t.Fatalf("expected apiVersion %q, got %q", AdvisoryBundleAPIVersion, bundle.APIVersion)
	}
	if bundle.Kind != AdvisoryBundleKind {
		t.Fatalf("expected kind %q, got %q", AdvisoryBundleKind, bundle.Kind)
	}
}

func TestLoadSBOMIndex(t *testing.T) {
	index, err := LoadSBOMIndex([]string{"a", "b"}, func(path string) (SBOM, error) {
		return SBOM{ImageRef: "image-" + path}, nil
	})
	if err != nil {
		t.Fatalf("LoadSBOMIndex returned error: %v", err)
	}
	if got := len(index); got != 2 {
		t.Fatalf("expected 2 sboms, got %d", got)
	}
	if _, ok := index["image-a"]; !ok {
		t.Fatalf("expected image-a to be indexed")
	}
	if _, ok := index["image-b"]; !ok {
		t.Fatalf("expected image-b to be indexed")
	}
}

func TestLoadAdvisoriesDefaultsSchemaMarkers(t *testing.T) {
	bundle, err := LoadAdvisoriesBytes([]byte(`
advisories:
  - id: CVE-2026-0001
    packageName: openssl
    ecosystem: apk
    affectedVersions: [">=1.1.1-r0, <1.1.1-r2"]
    severity: high
    summary: OpenSSL vulnerable package
`))
	if err != nil {
		t.Fatalf("LoadAdvisoriesBytes returned error: %v", err)
	}
	if bundle.APIVersion != AdvisoryBundleAPIVersion {
		t.Fatalf("expected apiVersion %q, got %q", AdvisoryBundleAPIVersion, bundle.APIVersion)
	}
	if bundle.Kind != AdvisoryBundleKind {
		t.Fatalf("expected kind %q, got %q", AdvisoryBundleKind, bundle.Kind)
	}
}

func TestLoadAdvisoriesRejectsUnsupportedSchemaMarkers(t *testing.T) {
	_, err := LoadAdvisoriesBytes([]byte(`
apiVersion: kubescan.io/v2
kind: AdvisoryBundle
advisories:
  - id: CVE-2026-0001
    packageName: openssl
    ecosystem: apk
    affectedVersions: [">=1.1.1-r0, <1.1.1-r2"]
    severity: high
    summary: OpenSSL vulnerable package
`))
	if err == nil {
		t.Fatalf("expected schema validation error")
	}
}
