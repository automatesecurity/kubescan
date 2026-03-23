package ci

import (
	"strings"
	"testing"
)

func TestOperatorDeploymentManifestsIncludeBaselineContainerHardening(t *testing.T) {
	for _, relative := range []string{
		"deploy/operator/operator.yaml",
		"deploy/operator/operator-namespace.yaml",
	} {
		content := readRepositoryFile(t, relative)
		for _, expected := range []string{
			"automountServiceAccountToken: true",
			"securityContext:",
			"runAsNonRoot: true",
			"type: RuntimeDefault",
			"allowPrivilegeEscalation: false",
			"readOnlyRootFilesystem: true",
			"drop:",
			"- ALL",
			"requests:",
			"cpu: 100m",
			"memory: 128Mi",
			"limits:",
			"cpu: 500m",
			"memory: 512Mi",
		} {
			if !strings.Contains(content, expected) {
				t.Fatalf("%s is missing hardened deployment setting %q", relative, expected)
			}
		}
	}
}

func TestNodeCollectorManifestIncludesBaselineContainerHardening(t *testing.T) {
	content := readRepositoryFile(t, "deploy/node-collector/node-collector.yaml")
	for _, expected := range []string{
		"serviceAccountName: kubescan-node-collector",
		"type: RuntimeDefault",
		"runAsUser: 0",
		"allowPrivilegeEscalation: false",
		"readOnlyRootFilesystem: true",
		"drop:",
		"- ALL",
		"readOnly: true",
		"path: /var/lib/kubelet",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("deploy/node-collector/node-collector.yaml is missing hardened setting %q", expected)
		}
	}
}
