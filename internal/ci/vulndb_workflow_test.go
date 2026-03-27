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
		"KUBESCAN_DB_SIGNING_KEY",
		"--source-manifest \"$MANIFEST_PATH\"",
		"--metadata-out \"$METADATA_PATH\"",
		"--signature-out \"$SIGNATURE_PATH\"",
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
