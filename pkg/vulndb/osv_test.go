package vulndb

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadOSVBytesNormalizesSupportedEcosystems(t *testing.T) {
	content := []byte(`[
  {
    "id": "GHSA-1234",
    "aliases": ["CVE-2026-0001"],
    "summary": "OpenSSL vulnerability",
    "database_specific": {"severity": "high"},
    "affected": [
      {
        "package": {"name": "openssl", "ecosystem": "Alpine"},
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {"introduced": "0"},
              {"fixed": "1.1.1-r2"}
            ]
          }
        ]
      },
      {
        "package": {"name": "jinja2", "ecosystem": "PyPI"},
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {"introduced": "2.0.0"},
              {"last_affected": "2.11.3"}
            ]
          }
        ]
      }
    ]
  }
]`)

	bundle, err := LoadOSVBytes(content)
	if err != nil {
		t.Fatalf("LoadOSVBytes returned error: %v", err)
	}
	if len(bundle.Advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(bundle.Advisories))
	}
	if bundle.Advisories[0].Ecosystem != "apk" {
		t.Fatalf("expected Alpine to normalize to apk, got %+v", bundle.Advisories[0])
	}
	if bundle.Advisories[0].AffectedVersions[0] != "<1.1.1-r2" {
		t.Fatalf("unexpected apk range %+v", bundle.Advisories[0].AffectedVersions)
	}
	if bundle.Advisories[1].Ecosystem != "pypi" {
		t.Fatalf("expected PyPI to normalize to pypi, got %+v", bundle.Advisories[1])
	}
	if bundle.Advisories[1].AffectedVersions[0] != ">=2.0.0,<=2.11.3" {
		t.Fatalf("unexpected pypi range %+v", bundle.Advisories[1].AffectedVersions)
	}
}

func TestLoadOSVSourceSupportsHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"id": "GHSA-1234",
			"summary": "OpenSSL vulnerability",
			"database_specific": {"severity": "high"},
			"affected": [{
				"package": {"name": "openssl", "ecosystem": "Alpine"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced":"0"},{"fixed":"1.1.1-r2"}]}]
			}]
		}`))
	}))
	defer server.Close()

	bundle, err := LoadOSVSource(server.URL)
	if err != nil {
		t.Fatalf("LoadOSVSource returned error: %v", err)
	}
	if len(bundle.Advisories) != 1 || bundle.Advisories[0].PackageName != "openssl" {
		t.Fatalf("unexpected advisories %+v", bundle.Advisories)
	}
}
