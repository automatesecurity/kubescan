package imagescan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseAPKInstalled(t *testing.T) {
	content := []byte("P:busybox\nV:1.36.1-r2\n\nP:openssl\nV:3.3.0-r0\n\n")

	packages := parseAPKInstalled(content)
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %+v", packages)
	}
	if packages[0].Name != "busybox" || packages[0].Version != "1.36.1-r2" || packages[0].Ecosystem != "apk" {
		t.Fatalf("unexpected first package %+v", packages[0])
	}
	if packages[1].Name != "openssl" || packages[1].Version != "3.3.0-r0" || packages[1].Ecosystem != "apk" {
		t.Fatalf("unexpected second package %+v", packages[1])
	}
}

func TestParseDPKGStatus(t *testing.T) {
	content := []byte("Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u9\n\nPackage: oldpkg\nStatus: deinstall ok config-files\nVersion: 1.0.0\n\n")

	packages := parseDPKGStatus(content)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %+v", packages)
	}
	if packages[0].Name != "libc6" || packages[0].Version != "2.36-9+deb12u9" || packages[0].Ecosystem != "deb" {
		t.Fatalf("unexpected package %+v", packages[0])
	}
}

func TestExtractSBOMFromFiles(t *testing.T) {
	sbom := extractSBOMFromFiles("ghcr.io/acme/api:1.0.0", map[string][]byte{
		"lib/apk/db/installed":  []byte("P:busybox\nV:1.36.1-r2\n\n"),
		"var/lib/dpkg/status":   []byte("Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u9\n\n"),
		"app/package-lock.json": []byte(`{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`),
		"app/yarn.lock":         []byte("\"left-pad@^1.3.0\":\n  version \"1.3.0\"\n"),
		"app/go.mod":            []byte("module example.com/app\nrequire github.com/google/uuid v1.6.0\n"),
		"app/pom.xml":           []byte("<project><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.13</version></dependency></dependencies></project>"),
		"app/Cargo.lock":        []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n"),
		"app/composer.lock":     []byte(`{"packages":[{"name":"symfony/console","version":"v7.1.0"}]}`),
		"app/packages.lock.json": []byte(`{"dependencies":{"Newtonsoft.Json":{"resolved":"13.0.3"}}}`),
		"app/requirements.txt":  []byte("requests==2.32.3\n"),
		"app/poetry.lock":       []byte("[[package]]\nname = \"fastapi\"\nversion = \"0.115.0\"\n"),
		"app/Pipfile.lock":      []byte(`{"default":{"urllib3":{"version":"==2.2.3"}}}`),
		"app/Gemfile.lock":      []byte("GEM\n  specs:\n    rack (3.1.7)\n\nPLATFORMS\n  ruby\n"),
	})

	if sbom.ImageRef != "ghcr.io/acme/api:1.0.0" {
		t.Fatalf("unexpected image ref %q", sbom.ImageRef)
	}
	if len(sbom.Packages) != 13 {
		t.Fatalf("expected 13 packages, got %+v", sbom.Packages)
	}
}

func TestApplyWhiteoutRemovesTrackedPackageDB(t *testing.T) {
	files := map[string][]byte{
		"lib/apk/db/installed": []byte("P:busybox\nV:1.36.1-r2\n\n"),
	}

	applyWhiteout(files, "lib/apk/db/.wh.installed")

	if _, ok := files["lib/apk/db/installed"]; ok {
		t.Fatalf("expected tracked file to be removed by whiteout")
	}
}

func TestParseRPMDatabase(t *testing.T) {
	for _, fixture := range []string{
		filepath.Join("github.com", "knqyf263", "go-rpmdb@v0.1.1", "pkg", "testdata", "centos5-plain", "Packages"),
		filepath.Join("github.com", "knqyf263", "go-rpmdb@v0.1.1", "pkg", "testdata", "sle15-bci", "Packages.db"),
		filepath.Join("github.com", "knqyf263", "go-rpmdb@v0.1.1", "pkg", "testdata", "fedora35", "rpmdb.sqlite"),
	} {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			moduleCache := goEnv(t, "GOMODCACHE")
			dbPath := filepath.Join(moduleCache, fixture)
			content, err := os.ReadFile(dbPath)
			if err != nil {
				t.Fatalf("ReadFile returned error: %v", err)
			}

			packages := parseRPMDatabase(content)
			if len(packages) == 0 {
				t.Fatalf("expected packages from rpmdb fixture, got %+v", packages)
			}
			if packages[0].Ecosystem != "rpm" {
				t.Fatalf("expected rpm ecosystem packages, got %+v", packages)
			}
		})
	}
}

func TestParseNPMLockfile(t *testing.T) {
	packages := parseNPMLockfile([]byte(`{
  "packages": {
    "": {"name":"demo","version":"1.0.0"},
    "node_modules/lodash": {"version":"4.17.21"},
    "node_modules/@types/node": {"version":"22.10.1"}
  }
}`))
	if len(packages) != 2 {
		t.Fatalf("expected 2 npm packages, got %+v", packages)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	packages := parseRequirementsTxt([]byte("requests==2.32.3\nuvicorn[standard]==0.32.0 ; python_version >= '3.11'\n-r extra.txt\n"))
	if len(packages) != 2 {
		t.Fatalf("expected 2 python packages, got %+v", packages)
	}
}

func TestParseGemfileLock(t *testing.T) {
	packages := parseGemfileLock([]byte("GEM\n  specs:\n    rack (3.1.7)\n    puma (6.4.2)\n\nPLATFORMS\n  ruby\n"))
	if len(packages) != 2 {
		t.Fatalf("expected 2 gem packages, got %+v", packages)
	}
}

func TestParseYarnLock(t *testing.T) {
	packages := parseYarnLock([]byte("\"left-pad@^1.3.0\", \"left-pad@~1.3.0\":\n  version \"1.3.0\"\n\"@types/node@^22.0.0\":\n  version \"22.10.1\"\n"))
	if len(packages) != 2 {
		t.Fatalf("expected 2 yarn packages, got %+v", packages)
	}
}

func TestParseGoMod(t *testing.T) {
	packages := parseGoMod([]byte("module example.com/app\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgolang.org/x/text v0.17.0\n)\n"))
	if len(packages) != 2 {
		t.Fatalf("expected 2 go packages, got %+v", packages)
	}
}

func TestParseMavenPOM(t *testing.T) {
	packages := parseMavenPOM([]byte("<project><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.13</version></dependency></dependencies></project>"))
	if len(packages) != 1 || packages[0].Name != "org.slf4j:slf4j-api" {
		t.Fatalf("unexpected maven packages %+v", packages)
	}
}

func TestParseCargoLock(t *testing.T) {
	packages := parseCargoLock([]byte("[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n"))
	if len(packages) != 1 || packages[0].Ecosystem != "cargo" {
		t.Fatalf("unexpected cargo packages %+v", packages)
	}
}

func TestParseComposerLock(t *testing.T) {
	packages := parseComposerLock([]byte(`{"packages":[{"name":"symfony/console","version":"v7.1.0"}]}`))
	if len(packages) != 1 || packages[0].Ecosystem != "composer" {
		t.Fatalf("unexpected composer packages %+v", packages)
	}
}

func TestParseNuGetPackagesLock(t *testing.T) {
	packages := parseNuGetPackagesLock([]byte(`{"dependencies":{"Newtonsoft.Json":{"resolved":"13.0.3"}}}`))
	if len(packages) != 1 || packages[0].Ecosystem != "nuget" {
		t.Fatalf("unexpected nuget packages %+v", packages)
	}
}

func TestParsePoetryLock(t *testing.T) {
	packages := parsePoetryLock([]byte("[[package]]\nname = \"fastapi\"\nversion = \"0.115.0\"\n\n[[package]]\nname = \"pydantic\"\nversion = \"2.9.2\"\n"))
	if len(packages) != 2 {
		t.Fatalf("expected 2 poetry packages, got %+v", packages)
	}
}

func TestParsePipfileLock(t *testing.T) {
	packages := parsePipfileLock([]byte(`{"default":{"urllib3":{"version":"==2.2.3"}},"develop":{"pytest":{"version":"==8.3.3"}}}`))
	if len(packages) != 2 {
		t.Fatalf("expected 2 pipfile packages, got %+v", packages)
	}
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	output, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Fatalf("go env %s returned error: %v", key, err)
	}
	return filepath.Clean(string(bytesTrimSpace(output)))
}

func bytesTrimSpace(value []byte) []byte {
	start := 0
	for start < len(value) && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	end := len(value)
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return value[start:end]
}
