package vulndb

import (
	"path/filepath"
	"testing"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

func TestWriteLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "advisories.db")
	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
		Advisories: []vuln.Advisory{
			{
				ID:               "CVE-2026-0001",
				Aliases:          []string{"GHSA-example"},
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
				FixedVersion:     "1.1.1-r2",
				Severity:         policy.SeverityHigh,
				Summary:          "OpenSSL vulnerability",
			},
		},
	}

	if err := Write(path, bundle); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.APIVersion != bundle.APIVersion {
		t.Fatalf("expected apiVersion %q, got %q", bundle.APIVersion, loaded.APIVersion)
	}
	if loaded.Kind != bundle.Kind {
		t.Fatalf("expected kind %q, got %q", bundle.Kind, loaded.Kind)
	}
	if len(loaded.Advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(loaded.Advisories))
	}
	if loaded.Advisories[0].ID != "CVE-2026-0001" {
		t.Fatalf("unexpected advisory %+v", loaded.Advisories[0])
	}
	if len(loaded.Advisories[0].Aliases) != 1 || loaded.Advisories[0].Aliases[0] != "GHSA-example" {
		t.Fatalf("expected aliases to round-trip, got %+v", loaded.Advisories[0].Aliases)
	}
}

func TestInspect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "advisories.db")
	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
		Advisories: []vuln.Advisory{
			{
				ID:               "CVE-2026-0001",
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
				Severity:         policy.SeverityHigh,
				Summary:          "OpenSSL vulnerability",
			},
			{
				ID:               "CVE-2026-0002",
				PackageName:      "busybox",
				Ecosystem:        "apk",
				AffectedVersions: []string{"<1.36.0-r2"},
				Severity:         policy.SeverityMedium,
				Summary:          "Busybox vulnerability",
			},
		},
	}

	if err := Write(path, bundle); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if info.Schema != SchemaName {
		t.Fatalf("expected schema %q, got %q", SchemaName, info.Schema)
	}
	if info.SchemaVersion != SchemaVersion {
		t.Fatalf("expected schema version %q, got %q", SchemaVersion, info.SchemaVersion)
	}
	if info.AdvisoryCount != 2 {
		t.Fatalf("expected advisory count 2, got %d", info.AdvisoryCount)
	}
	if info.BundleAPIVersion != vuln.AdvisoryBundleAPIVersion {
		t.Fatalf("expected bundle apiVersion %q, got %q", vuln.AdvisoryBundleAPIVersion, info.BundleAPIVersion)
	}
	if info.BundleKind != vuln.AdvisoryBundleKind {
		t.Fatalf("expected bundle kind %q, got %q", vuln.AdvisoryBundleKind, info.BundleKind)
	}
	if info.BuiltAt.IsZero() {
		t.Fatalf("expected builtAt to be populated")
	}
}
