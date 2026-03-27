package vulndb

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

func TestLoadSourceManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: VulnDBSources
sources:
  - name: curated
    kind: AdvisoryBundle
    path: ./examples/advisories.yaml
    priority: 90
  - name: alpine-main
    kind: AlpineSecDB
    url: https://secdb.alpinelinux.org/v3.20/main.json
    priority: 80
  - name: debian-bookworm
    kind: DebianSecurityTracker
    url: https://security-tracker.debian.org/tracker/data/json
    release: bookworm
    priority: 85
  - name: osv-upstream
    kind: OSV
    path: ./examples/osv-sample.json
`), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	manifest, err := LoadSourceManifest(path)
	if err != nil {
		t.Fatalf("LoadSourceManifest returned error: %v", err)
	}
	if len(manifest.Sources) != 4 {
		t.Fatalf("expected 4 sources, got %d", len(manifest.Sources))
	}
}

func TestResolveSourcesAppliesPriority(t *testing.T) {
	manifest := SourceManifest{
		APIVersion: SourceManifestAPIVersion,
		Kind:       SourceManifestKind,
		Sources: []SourceSpec{
			{Name: "osv", Kind: "OSV", Path: "osv.json", Priority: 60},
			{Name: "curated", Kind: "AdvisoryBundle", Path: "advisories.yaml", Priority: 90},
		},
	}

	bundle, err := ResolveSources(context.Background(), manifest, SourceResolver{
		LoadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "CVE-2026-0001",
					Aliases:          []string{"GHSA-1234"},
					PackageName:      "openssl",
					Ecosystem:        "apk",
					AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r3"},
					Severity:         policy.SeverityCritical,
					Summary:          "Curated advisory",
				}},
			}, nil
		},
		LoadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadOSVSource: func(path string) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "GHSA-1234",
					Aliases:          []string{"CVE-2026-0001"},
					PackageName:      "openssl",
					Ecosystem:        "apk",
					AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
					Severity:         policy.SeverityHigh,
					Summary:          "OSV advisory",
				}},
			}, nil
		},
		LoadAlpineSecDB:    func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
	})
	if err != nil {
		t.Fatalf("ResolveSources returned error: %v", err)
	}
	if len(bundle.Advisories) != 1 {
		t.Fatalf("expected 1 merged advisory, got %d", len(bundle.Advisories))
	}
	if bundle.Advisories[0].Source != "curated" || bundle.Advisories[0].SourcePriority != 90 {
		t.Fatalf("expected curated advisory to win, got %+v", bundle.Advisories[0])
	}
	if bundle.Advisories[0].Severity != policy.SeverityCritical {
		t.Fatalf("expected higher-priority severity, got %+v", bundle.Advisories[0])
	}
}

func TestResolveSourcesNormalizesPackageNamesForPriority(t *testing.T) {
	manifest := SourceManifest{
		APIVersion: SourceManifestAPIVersion,
		Kind:       SourceManifestKind,
		Sources: []SourceSpec{
			{Name: "osv", Kind: "OSV", Path: "osv.json", Priority: 60},
			{Name: "curated", Kind: "AdvisoryBundle", Path: "advisories.yaml", Priority: 90},
		},
	}

	bundle, err := ResolveSources(context.Background(), manifest, SourceResolver{
		LoadAdvisories: func(path string) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "CVE-2026-0001",
					Aliases:          []string{"GHSA-1234"},
					PackageName:      "jinja2-legacy-name",
					Ecosystem:        "pypi",
					AffectedVersions: []string{"<3.1.6"},
					Severity:         policy.SeverityCritical,
					Summary:          "Curated advisory",
				}},
			}, nil
		},
		LoadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadOSVSource: func(path string) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "GHSA-1234",
					Aliases:          []string{"CVE-2026-0001"},
					PackageName:      "Jinja2_Legacy.Name",
					Ecosystem:        "pypi",
					AffectedVersions: []string{"<3.1.6"},
					Severity:         policy.SeverityHigh,
					Summary:          "OSV advisory",
				}},
			}, nil
		},
		LoadAlpineSecDB:    func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
	})
	if err != nil {
		t.Fatalf("ResolveSources returned error: %v", err)
	}
	if len(bundle.Advisories) != 1 || bundle.Advisories[0].Source != "curated" {
		t.Fatalf("expected normalized package names to dedupe, got %+v", bundle.Advisories)
	}
}

func TestResolveSourcesVendorFeedOutranksOSVByDefault(t *testing.T) {
	manifest := SourceManifest{
		APIVersion: SourceManifestAPIVersion,
		Kind:       SourceManifestKind,
		Sources: []SourceSpec{
			{Name: "osv", Kind: "OSV", Path: "osv.json"},
			{Name: "alpine", Kind: "AlpineSecDB", Path: "main.json"},
		},
	}

	bundle, err := ResolveSources(context.Background(), manifest, SourceResolver{
		LoadAdvisories:     func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadOSVSource: func(string) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{Advisories: []vuln.Advisory{{
				ID:               "CVE-2026-0001",
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{"<3.0.14-r0"},
				FixedVersion:     "3.0.14-r0",
				Severity:         policy.SeverityHigh,
				Summary:          "OSV record",
			}}}, nil
		},
		LoadAlpineSecDB: func(string) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{Advisories: []vuln.Advisory{{
				ID:               "CVE-2026-0001",
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{"<3.0.15-r0"},
				FixedVersion:     "3.0.15-r0",
				Severity:         policy.SeverityMedium,
				Summary:          "Vendor record",
			}}}, nil
		},
		LoadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		LoadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
	})
	if err != nil {
		t.Fatalf("ResolveSources returned error: %v", err)
	}
	if len(bundle.Advisories) != 1 {
		t.Fatalf("expected 1 merged advisory, got %d", len(bundle.Advisories))
	}
	if bundle.Advisories[0].Source != "alpine" || bundle.Advisories[0].SourcePriority != 80 {
		t.Fatalf("expected AlpineSecDB source to win, got %+v", bundle.Advisories[0])
	}
}
