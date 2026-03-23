package vuln

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteCycloneDX(t *testing.T) {
	var output bytes.Buffer

	err := WriteCycloneDX(&output, SBOM{
		ImageRef: "ghcr.io/acme/api:1.0.0",
		Packages: []Package{
			{Name: "openssl", Version: "3.3.0-r0", Ecosystem: "apk", PURL: "pkg:apk/kubescan/openssl@3.3.0-r0"},
			{Name: "glibc", Version: "2.36-9+deb12u9", Ecosystem: "deb", PURL: "pkg:deb/kubescan/glibc@2.36-9+deb12u9"},
		},
	})
	if err != nil {
		t.Fatalf("WriteCycloneDX returned error: %v", err)
	}

	text := output.String()
	for _, expected := range []string{
		`"bomFormat": "CycloneDX"`,
		`"specVersion": "1.6"`,
		`"name": "ghcr.io/acme/api:1.0.0"`,
		`"purl": "pkg:apk/kubescan/openssl@3.3.0-r0"`,
		`"purl": "pkg:deb/kubescan/glibc@2.36-9+deb12u9"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected output to contain %s, got %s", expected, text)
		}
	}
}
