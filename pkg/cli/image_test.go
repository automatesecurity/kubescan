package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/imagescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

func TestRunImageRequiresImage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage(nil, &stdout, &stderr, imageDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--image is required") {
		t.Fatalf("expected image requirement error, got %s", stderr.String())
	}
}

func TestRunImageOutputsImageFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{"--image", "nginx:latest", "--format", "json"}, &stdout, &stderr, imageDeps{
		inspect: func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error) {
			return imagescan.Metadata{
				Reference: "nginx:latest",
				Tag:       "latest",
				User:      "",
				Env:       []string{"API_TOKEN=super-secret"},
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
		scanLayers: func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error) {
			t.Fatalf("scanLayers should not be called")
			return nil, nil
		},
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			t.Fatalf("extractSBOM should not be called")
			return vuln.SBOM{}, nil
		},
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSBOM should not be called")
			return nil
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"KI001\"") {
		t.Fatalf("expected mutable tag finding, got %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"KI003\"") {
		t.Fatalf("expected root-user finding, got %s", stdout.String())
	}
}

func TestRunImageMatchesSBOMVulnerabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{"--image", "ghcr.io/acme/api:1.0.0", "--sbom", "image.sbom.json", "--advisories", "advisories.yaml", "--format", "json"}, &stdout, &stderr, imageDeps{
		inspect: func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error) {
			return imagescan.Metadata{
				Reference: "ghcr.io/acme/api:1.0.0",
				Tag:       "1.0.0",
				User:      "1000",
			}, nil
		},
		loadSBOM: func(path string) (vuln.SBOM, error) {
			if path != "image.sbom.json" {
				t.Fatalf("expected image.sbom.json, got %q", path)
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
				t.Fatalf("expected advisories.yaml, got %q", path)
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
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		scanLayers: func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error) {
			t.Fatalf("scanLayers should not be called")
			return nil, nil
		},
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			t.Fatalf("extractSBOM should not be called when --sbom is supplied")
			return vuln.SBOM{}, nil
		},
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeCycloneDX should not be called")
			return nil
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
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
		t.Fatalf("expected vulnerability finding, got %s", stdout.String())
	}
}

func TestRunImageRejectsLayerOnlyFlagsWithoutScanLayers(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{"--image", "nginx:1.27", "--secret-scan", "patterns"}, &stdout, &stderr, imageDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "require --scan-layers") {
		t.Fatalf("expected scan-layers validation error, got %s", stderr.String())
	}
}

func TestRunImageRejectsSBOMAndSBOMOutTogether(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{"--image", "nginx:1.27", "--sbom", "image.sbom.json", "--sbom-out", "generated.json", "--advisories", "advisories.yaml"}, &stdout, &stderr, imageDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--sbom and --sbom-out cannot be used together") {
		t.Fatalf("expected sbom-out validation error, got %s", stderr.String())
	}
}

func TestRunImageScansLayers(t *testing.T) {
	var stdout, stderr bytes.Buffer
	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)

	exitCode := runImage([]string{
		"--image", "ghcr.io/acme/api:1.0.0",
		"--scan-layers",
		"--secret-scan", "patterns",
		"--license-deny", "GPL-3.0-only",
		"--format", "json",
	}, &stdout, &stderr, imageDeps{
		inspect: func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error) {
			return imagescan.Metadata{
				Reference: "ghcr.io/acme/api:1.0.0",
				Tag:       "1.0.0",
				User:      "1000",
			}, nil
		},
		scanLayers: func(_ context.Context, imageRef string, auth imagescan.AuthOptions, options imagescan.LayerScanOptions, scanTime time.Time) ([]policy.Finding, error) {
			if imageRef != "ghcr.io/acme/api:1.0.0" {
				t.Fatalf("expected image ref to be forwarded, got %q", imageRef)
			}
			if options.SecretScanMode != "patterns" {
				t.Fatalf("expected secret scan mode to be forwarded, got %q", options.SecretScanMode)
			}
			if len(options.LicensePolicy.Denylist) != 1 || options.LicensePolicy.Denylist[0] != "GPL-3.0-only" {
				t.Fatalf("expected denylist to be forwarded, got %+v", options.LicensePolicy.Denylist)
			}
			if scanTime.IsZero() {
				t.Fatalf("expected non-zero scan time")
			}
			return []policy.Finding{{
				ID:          "layerfinding",
				Category:    policy.CategoryExposure,
				RuleID:      "KI005",
				Title:       "Image layer contains sensitive file content",
				Severity:    policy.SeverityHigh,
				RuleVersion: "image-layer/v1alpha1",
				Resource:    policy.ResourceRef{Kind: "Image", Name: imageRef},
				Message:     "Image/ghcr.io/acme/api:1.0.0 file app/.env contains a plaintext credential-like value",
				Timestamp:   now,
			}}, nil
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
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			t.Fatalf("extractSBOM should not be called")
			return vuln.SBOM{}, nil
		},
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeCycloneDX should not be called")
			return nil
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"KI005\"") {
		t.Fatalf("expected image layer finding, got %s", stdout.String())
	}
}

func TestRunImageMatchesExtractedPackagesWithoutSBOM(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{"--image", "ghcr.io/acme/api:1.0.0", "--advisories", "advisories.yaml", "--format", "json"}, &stdout, &stderr, imageDeps{
		inspect: func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error) {
			return imagescan.Metadata{
				Reference: "ghcr.io/acme/api:1.0.0",
				Tag:       "1.0.0",
				User:      "1000",
			}, nil
		},
		extractSBOM: func(_ context.Context, imageRef string, auth imagescan.AuthOptions) (vuln.SBOM, error) {
			if imageRef != "ghcr.io/acme/api:1.0.0" {
				t.Fatalf("expected image ref to be forwarded, got %q", imageRef)
			}
			return vuln.SBOM{
				ImageRef: imageRef,
				Packages: []vuln.Package{
					{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
				},
			}, nil
		},
		loadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "advisories.yaml" {
				t.Fatalf("expected advisories.yaml, got %q", path)
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
		loadSBOM: func(string) (vuln.SBOM, error) {
			t.Fatalf("loadSBOM should not be called")
			return vuln.SBOM{}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		scanLayers: func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error) {
			t.Fatalf("scanLayers should not be called")
			return nil, nil
		},
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeCycloneDX should not be called")
			return nil
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
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
		t.Fatalf("expected vulnerability finding, got %s", stdout.String())
	}
}

func TestRunImageWritesExtractedSBOM(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var sbomOutput bytes.Buffer

	exitCode := runImage([]string{"--image", "registry.internal/acme/api:1.0.0", "--sbom-out", "generated.sbom.json"}, &stdout, &stderr, imageDeps{
		inspect: func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error) {
			return imagescan.Metadata{
				Reference: "registry.internal/acme/api:1.0.0",
				Tag:       "1.0.0",
				User:      "1000",
			}, nil
		},
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			return vuln.SBOM{
				ImageRef: "registry.internal/acme/api:1.0.0",
				Packages: []vuln.Package{
					{Name: "openssl", Version: "3.3.0-r0", Ecosystem: "apk", PURL: "pkg:apk/kubescan/openssl@3.3.0-r0"},
				},
			}, nil
		},
		writeCycloneDX: func(w io.Writer, sbom vuln.SBOM) error {
			if sbom.ImageRef != "registry.internal/acme/api:1.0.0" {
				t.Fatalf("unexpected sbom %+v", sbom)
			}
			_, err := io.WriteString(w, "sbom-json")
			return err
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
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
		scanLayers: func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error) {
			t.Fatalf("scanLayers should not be called")
			return nil, nil
		},
		openOutput: func(path string) (io.WriteCloser, error) {
			if path != "generated.sbom.json" {
				t.Fatalf("unexpected output path %q", path)
			}
			return nopWriteCloser{Writer: &sbomOutput}, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if sbomOutput.String() != "sbom-json" {
		t.Fatalf("expected sbom output to be written, got %q", sbomOutput.String())
	}
}

func TestRunImageWritesSPDXSBOM(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var sbomOutput bytes.Buffer

	exitCode := runImage([]string{
		"--image", "registry.internal/acme/api:1.0.0",
		"--sbom-out", "generated.spdx.json",
		"--sbom-format", "spdx",
	}, &stdout, &stderr, imageDeps{
		inspect: func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error) {
			return imagescan.Metadata{Reference: "registry.internal/acme/api:1.0.0", Tag: "1.0.0", User: "1000"}, nil
		},
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			return vuln.SBOM{ImageRef: "registry.internal/acme/api:1.0.0"}, nil
		},
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeCycloneDX should not be called")
			return nil
		},
		writeSPDX: func(w io.Writer, sbom vuln.SBOM) error {
			_, err := io.WriteString(w, "spdx-json")
			return err
		},
		loadSBOM: func(string) (vuln.SBOM, error) { return vuln.SBOM{}, nil },
		loadAdvisories: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		openOutput: func(path string) (io.WriteCloser, error) {
			if path != "generated.spdx.json" {
				t.Fatalf("unexpected output path %q", path)
			}
			return nopWriteCloser{Writer: &sbomOutput}, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if sbomOutput.String() != "spdx-json" {
		t.Fatalf("expected spdx output, got %q", sbomOutput.String())
	}
}

func TestRunImageForwardsExplicitRegistryUsernamePassword(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{
		"--image", "registry.internal/acme/api:1.0.0",
		"--registry-username", "robot$kubescan",
		"--registry-password", "secret-pass",
		"--format", "json",
	}, &stdout, &stderr, imageDeps{
		inspect: func(_ context.Context, imageRef string, auth imagescan.AuthOptions) (imagescan.Metadata, error) {
			if imageRef != "registry.internal/acme/api:1.0.0" {
				t.Fatalf("unexpected image ref %q", imageRef)
			}
			if auth.Username != "robot$kubescan" || auth.Password != "secret-pass" || auth.Token != "" {
				t.Fatalf("unexpected auth %+v", auth)
			}
			return imagescan.Metadata{Reference: imageRef, Tag: "1.0.0", User: "1000"}, nil
		},
		scanLayers: func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error) {
			t.Fatalf("scanLayers should not be called")
			return nil, nil
		},
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			t.Fatalf("extractSBOM should not be called")
			return vuln.SBOM{}, nil
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
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeCycloneDX should not be called")
			return nil
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
		stdin: strings.NewReader("ignored"),
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunImageReadsRegistryPasswordFromStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{
		"--image", "registry.internal/acme/api:1.0.0",
		"--registry-username", "robot$kubescan",
		"--registry-password-stdin",
		"--format", "json",
	}, &stdout, &stderr, imageDeps{
		inspect: func(_ context.Context, imageRef string, auth imagescan.AuthOptions) (imagescan.Metadata, error) {
			if auth.Username != "robot$kubescan" || auth.Password != "stdin-pass" || auth.Token != "" {
				t.Fatalf("unexpected auth %+v", auth)
			}
			return imagescan.Metadata{Reference: imageRef, Tag: "1.0.0", User: "1000"}, nil
		},
		scanLayers: func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error) {
			t.Fatalf("scanLayers should not be called")
			return nil, nil
		},
		extractSBOM: func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error) {
			t.Fatalf("extractSBOM should not be called")
			return vuln.SBOM{}, nil
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
		writeCycloneDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeCycloneDX should not be called")
			return nil
		},
		writeSPDX: func(io.Writer, vuln.SBOM) error {
			t.Fatalf("writeSPDX should not be called")
			return nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
		stdin: strings.NewReader("stdin-pass\n"),
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunImageRejectsConflictingRegistryAuthFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runImage([]string{
		"--image", "registry.internal/acme/api:1.0.0",
		"--registry-token", "token",
		"--registry-username", "robot",
		"--registry-password", "password",
	}, &stdout, &stderr, imageDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--registry-token cannot be combined") {
		t.Fatalf("expected registry auth validation error, got %s", stderr.String())
	}
}

type nopWriteCloser struct {
	io.Writer
}

func (n nopWriteCloser) Close() error {
	return nil
}
