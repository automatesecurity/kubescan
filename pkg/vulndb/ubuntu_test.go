package vulndb

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestLoadUbuntuSecurityNoticesBytesReleaseScoped(t *testing.T) {
	content := []byte(`{
  "schema_version": "1.7.0",
  "id": "UBUNTU-CVE-2026-0001",
  "summary": "Ubuntu package vulnerability",
  "upstream": ["CVE-2026-0001"],
  "severity": [{"type": "Ubuntu", "score": "high"}],
  "affected": [
    {
      "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"},
      "versions": ["3.0.13-0ubuntu3.2"],
      "ecosystem_specific": {
        "binaries": [
          {"binary_name": "libssl3", "binary_version": "3.0.13-0ubuntu3.2"},
          {"binary_name": "openssl", "binary_version": "3.0.13-0ubuntu3.2"}
        ]
      }
    }
  ]
}`)

	bundle, err := LoadUbuntuSecurityNoticesBytes(content, "24.04")
	if err != nil {
		t.Fatalf("LoadUbuntuSecurityNoticesBytes returned error: %v", err)
	}
	if len(bundle.Advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(bundle.Advisories))
	}
	if bundle.Advisories[0].Ecosystem != "deb" || bundle.Advisories[0].AffectedVersions[0] != "=3.0.13-0ubuntu3.2" {
		t.Fatalf("unexpected ubuntu advisories %+v", bundle.Advisories)
	}
}

func TestLoadUbuntuSecurityNoticesZipArchive(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	file, err := zw.Create("ubuntu-security-notices-main/osv/cve/2026/UBUNTU-CVE-2026-0001.json")
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	_, _ = file.Write([]byte(`{
  "schema_version": "1.7.0",
  "id": "UBUNTU-CVE-2026-0001",
  "summary": "Ubuntu package vulnerability",
  "severity": [{"type": "Ubuntu", "score": "medium"}],
  "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"}, "versions": ["3.0.13-0ubuntu3.2"]}]
}`))
	if err := zw.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	bundle, err := LoadUbuntuSecurityNoticesBytes(buf.Bytes(), "24.04")
	if err != nil {
		t.Fatalf("LoadUbuntuSecurityNoticesBytes returned error: %v", err)
	}
	if len(bundle.Advisories) != 1 || bundle.Advisories[0].PackageName != "openssl" {
		t.Fatalf("unexpected archive advisories %+v", bundle.Advisories)
	}
}
