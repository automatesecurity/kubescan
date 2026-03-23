package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReadmeDoesNotContainMachineSpecificOrWindowsCommandArtifacts(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	for _, forbidden := range []string{
		`C:\Users\Daniel`,
		`C:\Users\Daniel\tools`,
		`powershell`,
		`.exe`,
		`.\`,
	} {
		if strings.Contains(readme, forbidden) {
			t.Fatalf("README.md contains forbidden machine-specific or Windows-specific token %q", forbidden)
		}
	}
}

func TestReadmeReferencedRepoPathsExist(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	referencePattern := regexp.MustCompile(`\./((?:examples|deploy|schemas)/[A-Za-z0-9._/-]+)`)
	matches := referencePattern.FindAllStringSubmatch(readme, -1)
	if len(matches) == 0 {
		t.Fatalf("expected README to contain repository path references")
	}

	seen := map[string]struct{}{}
	for _, match := range matches {
		relative := filepath.FromSlash(match[1])
		if _, ok := seen[relative]; ok {
			continue
		}
		seen[relative] = struct{}{}
		if _, err := os.Stat(repoPath(relative)); err != nil {
			t.Fatalf("README references missing path %q: %v", match[1], err)
		}
	}
}

func TestAllCheckedInSchemasAreDocumentedInReadme(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	entries, err := os.ReadDir(repoPath("schemas"))
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected checked-in schema files")
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		expected := "schemas/" + entry.Name()
		if !strings.Contains(readme, expected) {
			t.Fatalf("README.md does not document schema %q", expected)
		}
	}
}

func TestAllOperatorCRDsAreDocumentedInReadme(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	entries, err := os.ReadDir(repoPath(filepath.Join("deploy", "crds")))
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected checked-in CRD files")
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		expected := "deploy/crds/" + entry.Name()
		if !strings.Contains(readme, expected) {
			t.Fatalf("README.md does not document CRD %q", expected)
		}
	}
}

func readRepositoryFile(t *testing.T, relative string) string {
	t.Helper()
	content, err := os.ReadFile(repoPath(relative))
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", relative, err)
	}
	return string(content)
}

func repoPath(relative string) string {
	return filepath.Clean(filepath.Join("..", "..", relative))
}
