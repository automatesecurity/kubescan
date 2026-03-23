package ci

import (
	"strings"
	"testing"
)

func TestReleaseWorkflowIncludesArtifactSigningAndProvenance(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/release.yaml")
	for _, expected := range []string{
		"id-token: write",
		"attestations: write",
		"sigstore/cosign-installer@v3",
		"cosign sign-blob --yes",
		"cosign verify-blob",
		"gh release upload",
		"cosign sign --yes ghcr.io/automatesecurity/kubescan@",
		"cosign sign --yes ghcr.io/automatesecurity/kubescan-operator@",
		"cosign sign --yes ghcr.io/automatesecurity/kubescan-node-collector@",
		"cosign verify",
		"actions/attest-build-provenance@v2",
	} {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("release workflow is missing hardened release behavior %q", expected)
		}
	}
}
