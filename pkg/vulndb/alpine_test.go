package vulndb

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadAlpineSecDBBytesNormalizesPackages(t *testing.T) {
	content := []byte(`{
  "distroversion": "v3.20",
  "reponame": "main",
  "packages": [
    {
      "pkg": {
        "name": "openssl",
        "secfixes": {
          "3.0.15-r0": ["CVE-2026-0001"],
          "3.0.16-r0": ["CVE-2026-0002"]
        }
      }
    }
  ]
}`)

	bundle, err := LoadAlpineSecDBBytes(content)
	if err != nil {
		t.Fatalf("LoadAlpineSecDBBytes returned error: %v", err)
	}
	if len(bundle.Advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(bundle.Advisories))
	}
	if bundle.Advisories[0].Ecosystem != "apk" {
		t.Fatalf("expected apk ecosystem, got %+v", bundle.Advisories[0])
	}
	if bundle.Advisories[0].AffectedVersions[0] != "<3.0.15-r0" {
		t.Fatalf("unexpected affected versions %+v", bundle.Advisories[0].AffectedVersions)
	}
	if bundle.Advisories[0].FixedVersion != "3.0.15-r0" {
		t.Fatalf("unexpected fixed version %+v", bundle.Advisories[0])
	}
}

func TestLoadAlpineSecDBSourceSupportsHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
  "distroversion": "v3.20",
  "reponame": "main",
  "packages": [
    {
      "pkg": {
        "name": "busybox",
        "secfixes": {
          "1.36.1-r2": ["CVE-2026-0003"]
        }
      }
    }
  ]
}`))
	}))
	defer server.Close()

	bundle, err := LoadAlpineSecDBSource(server.URL)
	if err != nil {
		t.Fatalf("LoadAlpineSecDBSource returned error: %v", err)
	}
	if len(bundle.Advisories) != 1 || bundle.Advisories[0].PackageName != "busybox" {
		t.Fatalf("unexpected advisories %+v", bundle.Advisories)
	}
}
