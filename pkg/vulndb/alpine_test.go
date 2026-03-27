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
	byID := map[string]struct {
		ecosystem string
		affected  string
		fixed     string
	}{}
	for _, advisory := range bundle.Advisories {
		if len(advisory.AffectedVersions) == 0 {
			t.Fatalf("expected affected versions for advisory %+v", advisory)
		}
		byID[advisory.ID] = struct {
			ecosystem string
			affected  string
			fixed     string
		}{
			ecosystem: advisory.Ecosystem,
			affected:  advisory.AffectedVersions[0],
			fixed:     advisory.FixedVersion,
		}
	}
	if got := byID["CVE-2026-0001"]; got.ecosystem != "apk" || got.affected != "<3.0.15-r0" || got.fixed != "3.0.15-r0" {
		t.Fatalf("unexpected advisory for CVE-2026-0001: %+v", got)
	}
	if got := byID["CVE-2026-0002"]; got.ecosystem != "apk" || got.affected != "<3.0.16-r0" || got.fixed != "3.0.16-r0" {
		t.Fatalf("unexpected advisory for CVE-2026-0002: %+v", got)
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
