package ci

import (
	"strings"
	"testing"
)

func TestVulnDBWorkflowPublishesScheduledSignedArtifacts(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/vulndb.yaml")
	for _, expected := range []string{
		`cron: "0 6 * * *"`,
		"workflow_dispatch:",
		"manifest_path:",
		"release_tag:",
		"concurrency:",
		"id-token: write",
		"sigstore/cosign-installer@v3",
		"--source-manifest \"$MANIFEST_PATH\"",
		"--metadata-out \"$METADATA_PATH\"",
		"cosign sign-blob --yes --new-bundle-format --bundle \"$BUNDLE_PATH\" \"$DB_PATH\"",
		"cosign verify-blob",
		"--bundle \"$BUNDLE_PATH\"",
		"--certificate-identity-regexp 'https://github.com/.+/.+/.github/workflows/vulndb.yaml@.+'",
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"gh release create \"$RELEASE_TAG\"",
		"gh release edit \"$RELEASE_TAG\"",
		"gh release upload \"$RELEASE_TAG\"",
		"actions/upload-artifact@v4",
		"retention-days: 14",
	} {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("vulnerability db workflow is missing expected behavior %q", expected)
		}
	}
}
