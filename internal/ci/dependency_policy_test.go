package ci

import (
	"strings"
	"testing"
)

func TestCIWorkflowIncludesDependencyVerification(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/ci.yaml")
	for _, expected := range []string{
		"go mod verify",
		"govulncheck",
		"golang.org/x/vuln/cmd/govulncheck@latest",
	} {
		if !strings.Contains(workflow, expected) {
			t.Fatalf("CI workflow is missing %q", expected)
		}
	}
}

func TestDependabotConfigExistsForGoAndGitHubActions(t *testing.T) {
	content := readRepositoryFile(t, ".github/dependabot.yml")
	for _, expected := range []string{
		`package-ecosystem: "gomod"`,
		`package-ecosystem: "github-actions"`,
		`interval: "weekly"`,
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("dependabot config is missing %q", expected)
		}
	}
}

func TestDockerfilesUseNonRootRuntimeImages(t *testing.T) {
	cliDockerfile := readRepositoryFile(t, "Dockerfile")
	if !strings.Contains(cliDockerfile, "USER 65532:65532") {
		t.Fatalf("Dockerfile must run as a non-root user")
	}
	operatorDockerfile := readRepositoryFile(t, "Dockerfile.operator")
	if !strings.Contains(operatorDockerfile, "distroless/static-debian12:nonroot") {
		t.Fatalf("Dockerfile.operator must use the nonroot distroless runtime image")
	}
}
