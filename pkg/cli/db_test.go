package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
	"kubescan/pkg/vulndb"
)

func TestRunDBBuildWritesDatabase(t *testing.T) {
	var stdout, stderr bytes.Buffer
	wrotePath := ""

	exitCode := runDB([]string{"build", "--advisories", "advisories.yaml", "--out", "advisories.db"}, &stdout, &stderr, dbDeps{
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
					Severity:         policy.SeverityHigh,
					Summary:          "OpenSSL vulnerability",
				}},
			}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadOSVSource: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadOSVSource should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadAlpineSecDB: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAlpineSecDB should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadDebianTracker: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadDebianTracker should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadUbuntuNotices: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadUbuntuNotices should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadKubernetesFeed should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadSourceManifest: func(string) (vulndb.SourceManifest, error) {
			t.Fatalf("loadSourceManifest should not be called")
			return vulndb.SourceManifest{}, nil
		},
		resolveSources: func(context.Context, vulndb.SourceManifest, vulndb.SourceResolver) (vuln.AdvisoryBundle, error) {
			t.Fatalf("resolveSources should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		writeDB: func(path string, bundle vuln.AdvisoryBundle) error {
			wrotePath = path
			if len(bundle.Advisories) != 1 || bundle.Advisories[0].ID != "CVE-2026-0001" {
				t.Fatalf("unexpected bundle %+v", bundle)
			}
			return nil
		},
		inspectDB: func(string) (vulndb.Info, error) {
			t.Fatalf("inspectDB should not be called")
			return vulndb.Info{}, nil
		},
		buildMetadata: func(string, vulndb.Info) (vulndb.ArtifactMetadata, error) {
			t.Fatalf("buildMetadata should not be called")
			return vulndb.ArtifactMetadata{}, nil
		},
		writeMetadata: func(string, vulndb.ArtifactMetadata) error {
			t.Fatalf("writeMetadata should not be called")
			return nil
		},
		writeSignature: func(string, string, string) error {
			t.Fatalf("writeSignature should not be called")
			return nil
		},
		verifyArtifact: func(string, string, string, string) error {
			t.Fatalf("verifyArtifact should not be called")
			return nil
		},
		downloadDB: func(vulndb.DownloadOptions) error {
			t.Fatalf("downloadDB should not be called")
			return nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if wrotePath != "advisories.db" {
		t.Fatalf("expected db path advisories.db, got %q", wrotePath)
	}
	if !strings.Contains(stdout.String(), "wrote vulnerability database") {
		t.Fatalf("expected success output, got %q", stdout.String())
	}
}

func TestRunDBBuildMergesOSVSources(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runDB([]string{"build", "--osv", "osv.json", "--out", "advisories.db"}, &stdout, &stderr, dbDeps{
		loadAdvisories: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisories should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAdvisoryBundle should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadOSVSource: func(path string) (vuln.AdvisoryBundle, error) {
			if path != "osv.json" {
				t.Fatalf("unexpected osv path %q", path)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "GHSA-1234",
					PackageName:      "jinja2",
					Ecosystem:        "pypi",
					AffectedVersions: []string{"<=2.11.3"},
					Severity:         policy.SeverityHigh,
					Summary:          "Jinja2 vulnerability",
				}},
			}, nil
		},
		loadAlpineSecDB: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadAlpineSecDB should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadDebianTracker: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadDebianTracker should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadUbuntuNotices: func(string, string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadUbuntuNotices should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) {
			t.Fatalf("loadKubernetesFeed should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		loadSourceManifest: func(string) (vulndb.SourceManifest, error) {
			t.Fatalf("loadSourceManifest should not be called")
			return vulndb.SourceManifest{}, nil
		},
		resolveSources: func(context.Context, vulndb.SourceManifest, vulndb.SourceResolver) (vuln.AdvisoryBundle, error) {
			t.Fatalf("resolveSources should not be called")
			return vuln.AdvisoryBundle{}, nil
		},
		writeDB: func(path string, bundle vuln.AdvisoryBundle) error {
			if len(bundle.Advisories) != 1 || bundle.Advisories[0].ID != "GHSA-1234" {
				t.Fatalf("unexpected merged bundle %+v", bundle)
			}
			return nil
		},
		inspectDB:      func(string) (vulndb.Info, error) { return vulndb.Info{}, nil },
		buildMetadata:  func(string, vulndb.Info) (vulndb.ArtifactMetadata, error) { return vulndb.ArtifactMetadata{}, nil },
		writeMetadata:  func(string, vulndb.ArtifactMetadata) error { return nil },
		writeSignature: func(string, string, string) error { return nil },
		verifyArtifact: func(string, string, string, string) error { return nil },
		downloadDB:     func(vulndb.DownloadOptions) error { return nil },
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunDBBuildUsesSourceManifest(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runDB([]string{"build", "--source-manifest", "sources.yaml", "--out", "advisories.db"}, &stdout, &stderr, dbDeps{
		loadAdvisories:     func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadOSVSource:      func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAlpineSecDB:    func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadSourceManifest: func(path string) (vulndb.SourceManifest, error) {
			if path != "sources.yaml" {
				t.Fatalf("unexpected source manifest path %q", path)
			}
			return vulndb.SourceManifest{
				APIVersion: vulndb.SourceManifestAPIVersion,
				Kind:       vulndb.SourceManifestKind,
				Sources:    []vulndb.SourceSpec{{Name: "curated", Kind: "AdvisoryBundle", Path: "advisories.yaml"}},
			}, nil
		},
		resolveSources: func(ctx context.Context, manifest vulndb.SourceManifest, resolver vulndb.SourceResolver) (vuln.AdvisoryBundle, error) {
			if len(manifest.Sources) != 1 || manifest.Sources[0].Name != "curated" {
				t.Fatalf("unexpected manifest %+v", manifest)
			}
			return vuln.AdvisoryBundle{
				Advisories: []vuln.Advisory{{
					ID:               "CVE-2026-0001",
					PackageName:      "openssl",
					Ecosystem:        "apk",
					AffectedVersions: []string{"<1.1.1-r2"},
					Severity:         policy.SeverityHigh,
					Summary:          "OpenSSL vulnerability",
				}},
			}, nil
		},
		writeDB: func(path string, bundle vuln.AdvisoryBundle) error {
			if len(bundle.Advisories) != 1 || bundle.Advisories[0].ID != "CVE-2026-0001" {
				t.Fatalf("unexpected bundle %+v", bundle)
			}
			return nil
		},
		inspectDB:      func(string) (vulndb.Info, error) { return vulndb.Info{}, nil },
		buildMetadata:  func(string, vulndb.Info) (vulndb.ArtifactMetadata, error) { return vulndb.ArtifactMetadata{}, nil },
		writeMetadata:  func(string, vulndb.ArtifactMetadata) error { return nil },
		writeSignature: func(string, string, string) error { return nil },
		verifyArtifact: func(string, string, string, string) error { return nil },
		downloadDB:     func(vulndb.DownloadOptions) error { return nil },
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunDBInfoWritesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	builtAt := time.Date(2026, 3, 27, 12, 0, 0, 0, time.UTC)

	exitCode := runDB([]string{"info", "--db", "advisories.db", "--format", "json"}, &stdout, &stderr, dbDeps{
		loadAdvisories:     func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadOSVSource:      func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAlpineSecDB:    func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadSourceManifest: func(string) (vulndb.SourceManifest, error) { return vulndb.SourceManifest{}, nil },
		resolveSources: func(context.Context, vulndb.SourceManifest, vulndb.SourceResolver) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{}, nil
		},
		writeDB: func(string, vuln.AdvisoryBundle) error { return nil },
		inspectDB: func(path string) (vulndb.Info, error) {
			if path != "advisories.db" {
				t.Fatalf("unexpected db path %q", path)
			}
			return vulndb.Info{
				Schema:           vulndb.SchemaName,
				SchemaVersion:    vulndb.SchemaVersion,
				AdvisoryCount:    42,
				BuiltAt:          builtAt,
				BundleAPIVersion: vuln.AdvisoryBundleAPIVersion,
				BundleKind:       vuln.AdvisoryBundleKind,
			}, nil
		},
		buildMetadata: func(string, vulndb.Info) (vulndb.ArtifactMetadata, error) {
			t.Fatalf("buildMetadata should not be called")
			return vulndb.ArtifactMetadata{}, nil
		},
		writeMetadata: func(string, vulndb.ArtifactMetadata) error {
			t.Fatalf("writeMetadata should not be called")
			return nil
		},
		writeSignature: func(string, string, string) error {
			t.Fatalf("writeSignature should not be called")
			return nil
		},
		verifyArtifact: func(string, string, string, string) error {
			t.Fatalf("verifyArtifact should not be called")
			return nil
		},
		downloadDB: func(vulndb.DownloadOptions) error {
			t.Fatalf("downloadDB should not be called")
			return nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	var info vulndb.Info
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if info.AdvisoryCount != 42 {
		t.Fatalf("expected advisory count 42, got %+v", info)
	}
}

func TestRunDBVerify(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	exitCode := runDB([]string{"verify", "--db", "advisories.db", "--metadata", "advisories.db.metadata.json", "--signature", "advisories.db.sig", "--key", "bundle.pub.pem"}, &stdout, &stderr, dbDeps{
		loadAdvisories:     func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadOSVSource:      func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAlpineSecDB:    func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadSourceManifest: func(string) (vulndb.SourceManifest, error) { return vulndb.SourceManifest{}, nil },
		resolveSources: func(context.Context, vulndb.SourceManifest, vulndb.SourceResolver) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{}, nil
		},
		writeDB:        func(string, vuln.AdvisoryBundle) error { return nil },
		inspectDB:      func(string) (vulndb.Info, error) { return vulndb.Info{}, nil },
		buildMetadata:  func(string, vulndb.Info) (vulndb.ArtifactMetadata, error) { return vulndb.ArtifactMetadata{}, nil },
		writeMetadata:  func(string, vulndb.ArtifactMetadata) error { return nil },
		writeSignature: func(string, string, string) error { return nil },
		verifyArtifact: func(dbPath, metadataPath, signaturePath, keyPath string) error {
			called = true
			if dbPath != "advisories.db" || metadataPath != "advisories.db.metadata.json" || signaturePath != "advisories.db.sig" || keyPath != "bundle.pub.pem" {
				t.Fatalf("unexpected verify args %q %q %q %q", dbPath, metadataPath, signaturePath, keyPath)
			}
			return nil
		},
		downloadDB: func(vulndb.DownloadOptions) error { return nil },
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !called {
		t.Fatalf("expected verifyArtifact to be called")
	}
	if !strings.Contains(stdout.String(), "vulnerability db verified") {
		t.Fatalf("expected verify output, got %q", stdout.String())
	}
}

func TestRunDBUpdate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	exitCode := runDB([]string{"update", "--url", "https://example.com/advisories.db", "--metadata-url", "https://example.com/advisories.db.metadata.json", "--signature-url", "https://example.com/advisories.db.sig", "--key", "bundle.pub.pem", "--out", "cache/advisories.db"}, &stdout, &stderr, dbDeps{
		loadAdvisories:     func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAdvisoryBundle: func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadOSVSource:      func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadAlpineSecDB:    func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadDebianTracker:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadUbuntuNotices:  func(string, string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadKubernetesFeed: func(string) (vuln.AdvisoryBundle, error) { return vuln.AdvisoryBundle{}, nil },
		loadSourceManifest: func(string) (vulndb.SourceManifest, error) { return vulndb.SourceManifest{}, nil },
		resolveSources: func(context.Context, vulndb.SourceManifest, vulndb.SourceResolver) (vuln.AdvisoryBundle, error) {
			return vuln.AdvisoryBundle{}, nil
		},
		writeDB:        func(string, vuln.AdvisoryBundle) error { return nil },
		inspectDB:      func(string) (vulndb.Info, error) { return vulndb.Info{}, nil },
		buildMetadata:  func(string, vulndb.Info) (vulndb.ArtifactMetadata, error) { return vulndb.ArtifactMetadata{}, nil },
		writeMetadata:  func(string, vulndb.ArtifactMetadata) error { return nil },
		writeSignature: func(string, string, string) error { return nil },
		verifyArtifact: func(string, string, string, string) error { return nil },
		downloadDB: func(options vulndb.DownloadOptions) error {
			called = true
			if options.DBURL != "https://example.com/advisories.db" || options.MetadataURL != "https://example.com/advisories.db.metadata.json" || options.SignatureURL != "https://example.com/advisories.db.sig" || options.KeyPath != "bundle.pub.pem" || options.OutPath != "cache/advisories.db" {
				t.Fatalf("unexpected download options %+v", options)
			}
			return nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !called {
		t.Fatalf("expected downloadDB to be called")
	}
	if !strings.Contains(stdout.String(), "downloaded vulnerability db") {
		t.Fatalf("expected update output, got %q", stdout.String())
	}
}
