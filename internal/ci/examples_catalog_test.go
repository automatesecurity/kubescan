package ci

import (
	"strings"
	"testing"
)

func TestReadmeDocumentsKeyExampleCatalogEntries(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	for _, expected := range []string{
		"## Example Catalog",
		"examples/operator-scanpolicy.yaml",
		"examples/operator-scanpolicy-bundles.yaml",
		"examples/operator-scanpolicy-github-sbom.yaml",
		"examples/operator-scanpolicy-history.yaml",
		"examples/operator-scanpolicy-slack.yaml",
		"examples/operator-sbomreport.yaml",
		"examples/operator-scanpolicy-remote-sboms.yaml",
		"deploy/node-collector/node-collector.yaml",
		"deploy/operator/operator.yaml",
		"deploy/operator/operator-namespace.yaml",
		"examples/fs-demo/.env",
		"examples/fs-demo/deployment.yaml",
		"examples/secret-demo/app.env",
		"examples/secret-demo/id_rsa",
		"examples/license-demo/package.json",
		"examples/sample.yaml",
		"examples/hardening-sample.yaml",
		"examples/enterprise-sample.yaml",
		"examples/rbac-sample.yaml",
		"examples/badpods-sample.yaml",
		"examples/attackpaths-sample.yaml",
		"examples/scoping-sample.yaml",
		"examples/kustomize/overlays/prod/kustomization.yaml",
		"examples/helm/api/Chart.yaml",
		"examples/helm/api/values.yaml",
		"examples/helm/api/values-prod.yaml",
		"examples/vuln-sample.yaml",
		"examples/vuln-sbom.json",
		"examples/vuln-multi.yaml",
		"examples/vuln-worker-sbom.json",
		"examples/advisories.yaml",
		"examples/k8s-components-advisories.yaml",
		"examples/vm-demo/var/lib/dpkg/status",
		"examples/vm-demo/app/requirements.txt",
		"examples/controls.yaml",
		"examples/policy.bundle.yaml",
		"examples/rules.bundle.yaml",
		"examples/advisories.bundle.yaml",
		"examples/bundle.pub.pem",
		"credentialed private-registry image example",
		"credentialed private Git HTTPS example",
		"provider-native GitHub archive retrieval plus sparse remote-scan example",
		"credentialed private Git SSH example",
	} {
		if !strings.Contains(readme, expected) {
			t.Fatalf("README.md is missing key example catalog entry %q", expected)
		}
	}
}
