package vuln

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteSPDX(t *testing.T) {
	var output bytes.Buffer
	err := WriteSPDX(&output, SBOM{
		ImageRef: "ghcr.io/acme/api:1.0.0",
		Packages: []Package{
			{Name: "github.com/google/uuid", Version: "1.6.0", Ecosystem: "golang", PURL: "pkg:golang/github.com/google/uuid@1.6.0"},
		},
	})
	if err != nil {
		t.Fatalf("WriteSPDX returned error: %v", err)
	}
	for _, want := range []string{
		`"spdxVersion": "SPDX-2.3"`,
		`"name": "ghcr.io/acme/api:1.0.0"`,
		`"referenceType": "purl"`,
		`pkg:golang/github.com/google/uuid@1.6.0`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("expected output to contain %q, got %s", want, output.String())
		}
	}
}
