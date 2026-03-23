package imagescan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractRootFSSBOM(t *testing.T) {
	root := t.TempDir()

	dpkgDir := filepath.Join(root, "var", "lib", "dpkg")
	if err := os.MkdirAll(dpkgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll dpkg returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dpkgDir, "status"), []byte("Package: openssl\nStatus: install ok installed\nVersion: 1.1.1-r0\n\n"), 0o644); err != nil {
		t.Fatalf("WriteFile status returned error: %v", err)
	}

	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("MkdirAll app returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile requirements returned error: %v", err)
	}

	sbom, err := ExtractRootFSSBOM(root, "/mnt/vm")
	if err != nil {
		t.Fatalf("ExtractRootFSSBOM returned error: %v", err)
	}
	if sbom.ImageRef != "/mnt/vm" {
		t.Fatalf("expected image ref /mnt/vm, got %q", sbom.ImageRef)
	}
	if len(sbom.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %+v", sbom.Packages)
	}
}
