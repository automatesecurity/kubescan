package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/filescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/vmscan"
	"kubescan/pkg/vuln"
)

func TestRunVMRequiresRootFS(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := runVM(nil, &stdout, &stderr, vmDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "either --rootfs or --disk is required") {
		t.Fatalf("expected rootfs/disk validation error, got %s", stderr.String())
	}
}

func TestRunVMMatchesVulnerabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := runVM([]string{"--rootfs", "/mnt/vm", "--advisories", "advisories.yaml", "--format", "json"}, &stdout, &stderr, vmDeps{
		resolveTarget: func(rootfs, disk string) (vmscan.ResolvedTarget, error) {
			if rootfs != "/mnt/vm" || disk != "" {
				t.Fatalf("unexpected target inputs %q %q", rootfs, disk)
			}
			return vmscan.ResolvedTarget{RootFSPath: "/mnt/vm", SourceRef: "/mnt/vm", Cleanup: func() {}}, nil
		},
		scanResolvedRootFS: func(target vmscan.ResolvedTarget, profile policy.RuleProfile, now time.Time, options filescan.Options) ([]policy.Finding, error) {
			if target.RootFSPath != "/mnt/vm" {
				t.Fatalf("unexpected resolved target %+v", target)
			}
			return nil, nil
		},
		extractSBOM: func(target vmscan.ResolvedTarget) (vuln.SBOM, error) {
			if target.RootFSPath != "/mnt/vm" {
				t.Fatalf("unexpected target %+v", target)
			}
			return vuln.SBOM{
				ImageRef: target.SourceRef,
				Packages: []vuln.Package{{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"}},
			}, nil
		},
		loadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "advisories.yaml" {
				t.Fatalf("unexpected advisories path %q", path)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "CVE-2026-0001",
					PackageName:      "openssl",
					Ecosystem:        "apk",
					AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
					FixedVersion:     "1.1.1-r1",
					Severity:         policy.SeverityHigh,
					Summary:          "OpenSSL vulnerable package",
				}},
			}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
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
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-0001\"") {
		t.Fatalf("expected vulnerability finding, got %s", stdout.String())
	}
}

func TestRunVMRejectsRootFSAndDiskTogether(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := runVM([]string{"--rootfs", "/mnt/vm", "--disk", "./image.qcow2"}, &stdout, &stderr, vmDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--rootfs and --disk cannot be used together") {
		t.Fatalf("expected mutual exclusion error, got %s", stderr.String())
	}
}

func TestRunVMLoadsAdvisoriesFromDB(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := runVM([]string{"--rootfs", "/mnt/vm", "--advisories-db", "advisories.db", "--format", "json"}, &stdout, &stderr, vmDeps{
		resolveTarget: func(rootfs, disk string) (vmscan.ResolvedTarget, error) {
			return vmscan.ResolvedTarget{RootFSPath: rootfs, SourceRef: rootfs, Cleanup: func() {}}, nil
		},
		scanResolvedRootFS: func(target vmscan.ResolvedTarget, profile policy.RuleProfile, now time.Time, options filescan.Options) ([]policy.Finding, error) {
			return nil, nil
		},
		extractSBOM: func(target vmscan.ResolvedTarget) (vuln.SBOM, error) {
			return vuln.SBOM{
				ImageRef: target.SourceRef,
				Packages: []vuln.Package{{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"}},
			}, nil
		},
		loadAdvisoryDB: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "advisories.db" {
				t.Fatalf("unexpected db path %q", path)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "CVE-2026-0001",
					PackageName:      "openssl",
					Ecosystem:        "apk",
					AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
					FixedVersion:     "1.1.1-r1",
					Severity:         policy.SeverityHigh,
					Summary:          "OpenSSL vulnerable package",
				}},
			}, nil
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
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"CVE-2026-0001\"") {
		t.Fatalf("expected vulnerability finding, got %s", stdout.String())
	}
}
