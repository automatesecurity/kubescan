package imagescan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	_ "modernc.org/sqlite"

	"kubescan/pkg/vuln"
)

var gemSpecRegex = regexp.MustCompile(`^\s{4}([^\s(]+)\s+\(([^)]+)\)$`)

var trackedPackageDBPaths = map[string]string{
	"lib/apk/db/installed":              "apk",
	"var/lib/dpkg/status":               "deb",
	"var/lib/rpm/Packages":              "rpm",
	"var/lib/rpm/Packages.db":           "rpm",
	"var/lib/rpm/rpmdb.sqlite":          "rpm",
	"usr/lib/sysimage/rpm/Packages":     "rpm",
	"usr/lib/sysimage/rpm/Packages.db":  "rpm",
	"usr/lib/sysimage/rpm/rpmdb.sqlite": "rpm",
}

var trackedPackageFilenames = map[string]string{
	"package-lock.json":   "npm-lock",
	"npm-shrinkwrap.json": "npm-lock",
	"yarn.lock":           "yarn-lock",
	"go.mod":              "go-mod",
	"pom.xml":             "maven-pom",
	"cargo.lock":          "cargo-lock",
	"composer.lock":       "composer-lock",
	"packages.lock.json":  "nuget-lock",
	"requirements.txt":    "pypi-requirements",
	"poetry.lock":         "poetry-lock",
	"pipfile.lock":        "pipenv-lock",
	"gemfile.lock":        "gem-lock",
}

func ExtractRemoteSBOM(ctx context.Context, imageRef string) (vuln.SBOM, error) {
	return ExtractRemoteSBOMWithAuth(ctx, imageRef, AuthOptions{})
}

func ExtractRootFSSBOM(rootfsPath string, sourceRef string) (vuln.SBOM, error) {
	root := filepath.Clean(strings.TrimSpace(rootfsPath))
	if root == "" {
		return vuln.SBOM{}, fmt.Errorf("rootfs path is required")
	}
	info, err := os.Stat(root)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("stat rootfs: %w", err)
	}
	if !info.IsDir() {
		return vuln.SBOM{}, fmt.Errorf("rootfs path must be a directory")
	}

	files := map[string][]byte{}
	err = filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		normalized := normalizeLayerPath(relative)
		if normalized == "" {
			return nil
		}
		if _, ok := trackedPackageDBPaths[normalized]; !ok && !shouldTrackPackageFile(normalized) {
			return nil
		}
		content, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		files[normalized] = content
		return nil
	})
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("walk rootfs: %w", err)
	}
	sbom := extractSBOMFromFiles(sourceRef, files)
	sbom.ImageRef = sourceRef
	return sbom, nil
}

func ExtractRemoteSBOMWithAuth(ctx context.Context, imageRef string, auth AuthOptions) (vuln.SBOM, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("parse image reference: %w", err)
	}
	img, err := remote.Image(ref, remoteOptions(ctx, auth)...)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("fetch image: %w", err)
	}
	return extractImageSBOM(imageRef, img)
}

func extractImageSBOM(imageRef string, img v1.Image) (vuln.SBOM, error) {
	layers, err := img.Layers()
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("read image layers: %w", err)
	}

	files := map[string][]byte{}
	for _, layer := range layers {
		reader, err := layer.Uncompressed()
		if err != nil {
			return vuln.SBOM{}, fmt.Errorf("read image layer: %w", err)
		}

		tr := tar.NewReader(reader)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = reader.Close()
				return vuln.SBOM{}, fmt.Errorf("read layer tar: %w", err)
			}
			if header == nil {
				continue
			}
			name := normalizeLayerPath(header.Name)
			if name == "" {
				continue
			}

			base := path.Base(name)
			switch {
			case strings.HasPrefix(base, ".wh."):
				applyWhiteout(files, name)
				continue
			case header.Typeflag != tar.TypeReg:
				continue
			}
			if _, ok := trackedPackageDBPaths[name]; !ok && !shouldTrackPackageFile(name) {
				continue
			}

			content, err := io.ReadAll(tr)
			if err != nil {
				_ = reader.Close()
				return vuln.SBOM{}, fmt.Errorf("read package database %s: %w", name, err)
			}
			files[name] = bytes.Clone(content)
		}
		_ = reader.Close()
	}

	return extractSBOMFromFiles(imageRef, files), nil
}

func applyWhiteout(files map[string][]byte, whiteoutPath string) {
	base := path.Base(whiteoutPath)
	dir := path.Dir(whiteoutPath)
	if base == ".wh..wh..opq" {
		prefix := strings.TrimSuffix(dir, "/") + "/"
		for candidate := range files {
			if strings.HasPrefix(candidate, prefix) {
				delete(files, candidate)
			}
		}
		return
	}
	target := strings.TrimPrefix(base, ".wh.")
	if target == "" {
		return
	}
	candidate := path.Join(dir, target)
	candidate = normalizeLayerPath(candidate)
	delete(files, candidate)
}

func extractSBOMFromFiles(imageRef string, files map[string][]byte) vuln.SBOM {
	seen := map[string]vuln.Package{}
	for filePath, ecosystem := range trackedPackageDBPaths {
		content, ok := files[filePath]
		if !ok || len(content) == 0 {
			continue
		}
		var packages []vuln.Package
		switch ecosystem {
		case "apk":
			packages = parseAPKInstalled(content)
		case "deb":
			packages = parseDPKGStatus(content)
		case "rpm":
			packages = parseRPMDatabase(content)
		}
		for _, pkg := range packages {
			key := strings.Join([]string{pkg.Ecosystem, pkg.Name, pkg.Version}, "|")
			seen[key] = pkg
		}
	}
	for filePath, content := range files {
		ecosystem, ok := trackedPackageFilenames[strings.ToLower(path.Base(filePath))]
		if !ok || len(content) == 0 {
			continue
		}
		var packages []vuln.Package
		switch ecosystem {
		case "npm-lock":
			packages = parseNPMLockfile(content)
		case "yarn-lock":
			packages = parseYarnLock(content)
		case "go-mod":
			packages = parseGoMod(content)
		case "maven-pom":
			packages = parseMavenPOM(content)
		case "cargo-lock":
			packages = parseCargoLock(content)
		case "composer-lock":
			packages = parseComposerLock(content)
		case "nuget-lock":
			packages = parseNuGetPackagesLock(content)
		case "pypi-requirements":
			packages = parseRequirementsTxt(content)
		case "poetry-lock":
			packages = parsePoetryLock(content)
		case "pipenv-lock":
			packages = parsePipfileLock(content)
		case "gem-lock":
			packages = parseGemfileLock(content)
		}
		for _, pkg := range packages {
			key := strings.Join([]string{pkg.Ecosystem, pkg.Name, pkg.Version}, "|")
			seen[key] = pkg
		}
	}

	packages := make([]vuln.Package, 0, len(seen))
	for _, pkg := range seen {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		return packages[i].Version < packages[j].Version
	})

	return vuln.SBOM{
		ImageRef: imageRef,
		Packages: packages,
	}
}

func shouldTrackPackageFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	_, ok := trackedPackageFilenames[base]
	return ok
}

func parseAPKInstalled(content []byte) []vuln.Package {
	var packages []vuln.Package
	var currentName, currentVersion string

	flush := func() {
		if currentName == "" || currentVersion == "" {
			currentName = ""
			currentVersion = ""
			return
		}
		packages = append(packages, vuln.Package{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: "apk",
			PURL:      packagePURL("apk", currentName, currentVersion),
		})
		currentName = ""
		currentVersion = ""
	}

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "P:"):
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "P:"))
		case strings.HasPrefix(line, "V:"):
			currentVersion = strings.TrimSpace(strings.TrimPrefix(line, "V:"))
		}
	}
	flush()
	return packages
}

func parseDPKGStatus(content []byte) []vuln.Package {
	var packages []vuln.Package
	var currentName, currentVersion, currentStatus string

	flush := func() {
		if currentName == "" || currentVersion == "" {
			currentName = ""
			currentVersion = ""
			currentStatus = ""
			return
		}
		if currentStatus != "" && !strings.Contains(strings.ToLower(currentStatus), "install ok installed") {
			currentName = ""
			currentVersion = ""
			currentStatus = ""
			return
		}
		packages = append(packages, vuln.Package{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: "deb",
			PURL:      packagePURL("deb", currentName, currentVersion),
		})
		currentName = ""
		currentVersion = ""
		currentStatus = ""
	}

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package:"):
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			currentVersion = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Status:"):
			currentStatus = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		}
	}
	flush()
	return packages
}

func parseRPMDatabase(content []byte) []vuln.Package {
	tempFile, err := os.CreateTemp("", "kubescan-rpmdb-*")
	if err != nil {
		return nil
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if _, err := tempFile.Write(content); err != nil {
		_ = tempFile.Close()
		return nil
	}
	if err := tempFile.Close(); err != nil {
		return nil
	}

	db, err := rpmdb.Open(tempPath)
	if err != nil {
		return nil
	}
	defer db.Close()

	pkgList, err := db.ListPackages()
	if err != nil {
		return nil
	}

	var packages []vuln.Package
	for _, pkg := range pkgList {
		if pkg == nil {
			continue
		}
		fullVersion := rpmPackageVersion(pkg)
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(fullVersion) == "" {
			continue
		}
		packages = append(packages, vuln.Package{
			Name:      pkg.Name,
			Version:   fullVersion,
			Ecosystem: "rpm",
			PURL:      packagePURL("rpm", pkg.Name, fullVersion),
		})
	}
	return packages
}

func rpmPackageVersion(pkg *rpmdb.PackageInfo) string {
	version := strings.TrimSpace(pkg.Version)
	release := strings.TrimSpace(pkg.Release)
	if release != "" {
		version = version + "-" + release
	}
	if pkg.Epoch != nil && *pkg.Epoch != 0 {
		version = fmt.Sprintf("%d:%s", *pkg.Epoch, version)
	}
	return version
}

func parseNPMLockfile(content []byte) []vuln.Package {
	var lock npmLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil
	}

	seen := map[string]vuln.Package{}
	for pathKey, pkg := range lock.Packages {
		if pathKey == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			name = npmPackageNameFromPath(pathKey)
		}
		if name == "" {
			continue
		}
		addPackage(seen, vuln.Package{
			Name:      name,
			Version:   strings.TrimSpace(pkg.Version),
			Ecosystem: "npm",
			PURL:      packagePURL("npm", name, strings.TrimSpace(pkg.Version)),
		})
	}
	walkNPMDependencies(seen, lock.Dependencies)
	return packagesFromMap(seen)
}

type npmDependency struct {
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmLock struct {
	Packages     map[string]npmDependency `json:"packages"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

func walkNPMDependencies(seen map[string]vuln.Package, dependencies map[string]npmDependency) {
	for name, dependency := range dependencies {
		packageName := strings.TrimSpace(dependency.Name)
		if packageName == "" {
			packageName = strings.TrimSpace(name)
		}
		version := strings.TrimSpace(dependency.Version)
		if packageName != "" && version != "" {
			addPackage(seen, vuln.Package{
				Name:      packageName,
				Version:   version,
				Ecosystem: "npm",
				PURL:      packagePURL("npm", packageName, version),
			})
		}
		if len(dependency.Dependencies) > 0 {
			walkNPMDependencies(seen, dependency.Dependencies)
		}
	}
}

func npmPackageNameFromPath(pathKey string) string {
	pathKey = filepath.ToSlash(strings.TrimSpace(pathKey))
	if pathKey == "" {
		return ""
	}
	parts := strings.Split(pathKey, "node_modules/")
	name := parts[len(parts)-1]
	name = strings.Trim(name, "/")
	return name
}

func parseRequirementsTxt(content []byte) []vuln.Package {
	seen := map[string]vuln.Package{}
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, "==="); idx > 0 {
			name := normalizePythonPackageName(line[:idx])
			version := strings.TrimSpace(line[idx+3:])
			if name != "" && version != "" {
				addPackage(seen, vuln.Package{Name: name, Version: version, Ecosystem: "pypi", PURL: packagePURL("pypi", name, version)})
			}
			continue
		}
		if idx := strings.Index(line, "=="); idx > 0 {
			name := normalizePythonPackageName(line[:idx])
			version := strings.TrimSpace(line[idx+2:])
			if name != "" && version != "" {
				addPackage(seen, vuln.Package{Name: name, Version: version, Ecosystem: "pypi", PURL: packagePURL("pypi", name, version)})
			}
		}
	}
	return packagesFromMap(seen)
}

func parsePoetryLock(content []byte) []vuln.Package {
	seen := map[string]vuln.Package{}
	var currentName string
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		switch {
		case line == "[[package]]":
			currentName = ""
		case strings.HasPrefix(line, "name = "):
			currentName = trimQuotedValue(strings.TrimPrefix(line, "name = "))
		case strings.HasPrefix(line, "version = "):
			version := trimQuotedValue(strings.TrimPrefix(line, "version = "))
			if currentName != "" && version != "" {
				addPackage(seen, vuln.Package{
					Name:      currentName,
					Version:   version,
					Ecosystem: "pypi",
					PURL:      packagePURL("pypi", currentName, version),
				})
			}
		}
	}
	return packagesFromMap(seen)
}

func parsePipfileLock(content []byte) []vuln.Package {
	var payload struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return nil
	}
	seen := map[string]vuln.Package{}
	addPipfilePackages(seen, payload.Default)
	addPipfilePackages(seen, payload.Develop)
	return packagesFromMap(seen)
}

func addPipfilePackages(seen map[string]vuln.Package, entries map[string]struct {
	Version string `json:"version"`
}) {
	for name, entry := range entries {
		version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(entry.Version), "=="))
		name = strings.TrimSpace(name)
		if name == "" || version == "" {
			continue
		}
		addPackage(seen, vuln.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "pypi",
			PURL:      packagePURL("pypi", name, version),
		})
	}
}

func parseYarnLock(content []byte) []vuln.Package {
	seen := map[string]vuln.Package{}
	currentHeader := ""
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			currentHeader = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if currentHeader != "" && strings.HasPrefix(line, "  version ") {
			version := trimQuotedValue(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "version ")))
			for _, name := range yarnNamesFromEntryHeader(currentHeader) {
				if name == "" || version == "" {
					continue
				}
				addPackage(seen, vuln.Package{
					Name:      name,
					Version:   version,
					Ecosystem: "npm",
					PURL:      packagePURL("npm", name, version),
				})
			}
		}
	}
	return packagesFromMap(seen)
}

func parseGoMod(content []byte) []vuln.Package {
	seen := map[string]vuln.Package{}
	inRequireBlock := false
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if strings.HasPrefix(line, "replace ") || strings.HasPrefix(line, "exclude ") {
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequireBlock {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		version := strings.TrimSpace(fields[1])
		if name == "" || version == "" || version == "=>" {
			continue
		}
		addPackage(seen, vuln.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "golang",
			PURL:      packagePURL("golang", name, version),
		})
	}
	return packagesFromMap(seen)
}

type mavenProject struct {
	Dependencies []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"dependencies>dependency"`
}

func parseMavenPOM(content []byte) []vuln.Package {
	var project mavenProject
	if err := xml.Unmarshal(content, &project); err != nil {
		return nil
	}
	seen := map[string]vuln.Package{}
	for _, dep := range project.Dependencies {
		group := strings.TrimSpace(dep.GroupID)
		artifact := strings.TrimSpace(dep.ArtifactID)
		version := strings.TrimSpace(dep.Version)
		if group == "" || artifact == "" || version == "" || strings.Contains(version, "${") {
			continue
		}
		name := group + ":" + artifact
		addPackage(seen, vuln.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "maven",
			PURL:      packagePURL("maven", name, version),
		})
	}
	return packagesFromMap(seen)
}

func parseCargoLock(content []byte) []vuln.Package {
	seen := map[string]vuln.Package{}
	currentName := ""
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		switch {
		case line == "[[package]]":
			currentName = ""
		case strings.HasPrefix(line, "name = "):
			currentName = trimQuotedValue(strings.TrimPrefix(line, "name = "))
		case strings.HasPrefix(line, "version = "):
			version := trimQuotedValue(strings.TrimPrefix(line, "version = "))
			if currentName == "" || version == "" {
				continue
			}
			addPackage(seen, vuln.Package{
				Name:      currentName,
				Version:   version,
				Ecosystem: "cargo",
				PURL:      packagePURL("cargo", currentName, version),
			})
		}
	}
	return packagesFromMap(seen)
}

func parseComposerLock(content []byte) []vuln.Package {
	var payload struct {
		Packages    []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return nil
	}
	seen := map[string]vuln.Package{}
	for _, pkg := range append(payload.Packages, payload.PackagesDev...) {
		name := strings.TrimSpace(pkg.Name)
		version := strings.TrimSpace(strings.TrimPrefix(pkg.Version, "v"))
		if name == "" || version == "" {
			continue
		}
		addPackage(seen, vuln.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "composer",
			PURL:      packagePURL("composer", name, version),
		})
	}
	return packagesFromMap(seen)
}

func parseNuGetPackagesLock(content []byte) []vuln.Package {
	var payload map[string]any
	if err := json.Unmarshal(content, &payload); err != nil {
		return nil
	}
	seen := map[string]vuln.Package{}
	walkNuGetDependencies(seen, payload)
	return packagesFromMap(seen)
}

func walkNuGetDependencies(seen map[string]vuln.Package, value any) {
	switch typed := value.(type) {
	case map[string]any:
		if resolved, ok := typed["resolved"].(string); ok {
			name, ok := typed["__kubescan_name"].(string)
			if ok {
				version := strings.TrimSpace(resolved)
				if name != "" && version != "" {
					addPackage(seen, vuln.Package{
						Name:      name,
						Version:   version,
						Ecosystem: "nuget",
						PURL:      packagePURL("nuget", name, version),
					})
				}
			}
		}
		for key, child := range typed {
			switch nested := child.(type) {
			case map[string]any:
				if _, ok := nested["__kubescan_name"]; !ok {
					nested["__kubescan_name"] = key
				}
				walkNuGetDependencies(seen, nested)
			case []any:
				walkNuGetDependencies(seen, nested)
			}
		}
	case []any:
		for _, child := range typed {
			walkNuGetDependencies(seen, child)
		}
	}
}

func yarnNamesFromEntryHeader(header string) []string {
	var names []string
	for _, selector := range splitYarnSelectors(header) {
		selector = trimQuotedValue(selector)
		if selector == "" {
			continue
		}
		if strings.HasPrefix(selector, "@") {
			parts := strings.SplitN(selector[1:], "@", 2)
			if len(parts) == 2 {
				names = append(names, "@"+parts[0])
				continue
			}
		}
		if idx := strings.Index(selector, "@"); idx > 0 {
			names = append(names, selector[:idx])
			continue
		}
		names = append(names, selector)
	}
	return names
}

func splitYarnSelectors(header string) []string {
	var selectors []string
	var current strings.Builder
	inQuotes := false
	for _, r := range header {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case ',':
			if inQuotes {
				current.WriteRune(r)
				continue
			}
			selector := strings.TrimSpace(current.String())
			if selector != "" {
				selectors = append(selectors, selector)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	selector := strings.TrimSpace(current.String())
	if selector != "" {
		selectors = append(selectors, selector)
	}
	return selectors
}

func trimQuotedValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"'`)
}

func normalizePythonPackageName(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.Index(value, "["); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func parseGemfileLock(content []byte) []vuln.Package {
	seen := map[string]vuln.Package{}
	inSpecs := false
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		if !strings.HasPrefix(line, "    ") {
			if strings.ToUpper(trimmed) == trimmed {
				break
			}
			continue
		}
		match := gemSpecRegex.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		name := strings.TrimSpace(match[1])
		version := strings.TrimSpace(match[2])
		if name == "" || version == "" {
			continue
		}
		addPackage(seen, vuln.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "gem",
			PURL:      packagePURL("gem", name, version),
		})
	}
	return packagesFromMap(seen)
}

func addPackage(seen map[string]vuln.Package, pkg vuln.Package) {
	if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" || strings.TrimSpace(pkg.Ecosystem) == "" {
		return
	}
	key := strings.Join([]string{pkg.Ecosystem, pkg.Name, pkg.Version}, "|")
	seen[key] = pkg
}

func packagesFromMap(seen map[string]vuln.Package) []vuln.Package {
	packages := make([]vuln.Package, 0, len(seen))
	for _, pkg := range seen {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		return packages[i].Version < packages[j].Version
	})
	return packages
}

func packagePURL(ecosystem, name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return ""
	}
	switch ecosystem {
	case "apk":
		return fmt.Sprintf("pkg:apk/kubescan/%s@%s", name, version)
	case "deb":
		return fmt.Sprintf("pkg:deb/kubescan/%s@%s", name, version)
	case "golang":
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case "maven":
		if parts := strings.SplitN(name, ":", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", parts[0], parts[1], version)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", name, version)
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	case "composer":
		return fmt.Sprintf("pkg:composer/%s@%s", name, version)
	case "nuget":
		return fmt.Sprintf("pkg:nuget/%s@%s", name, version)
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", name, version)
	case "gem":
		return fmt.Sprintf("pkg:gem/%s@%s", name, version)
	case "rpm":
		return fmt.Sprintf("pkg:rpm/kubescan/%s@%s", name, version)
	default:
		return ""
	}
}
