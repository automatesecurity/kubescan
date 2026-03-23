package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"kubescan/pkg/policy"

	"sigs.k8s.io/yaml"
)

type cyclonedxBOM struct {
	Metadata struct {
		Component struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"component"`
	} `json:"metadata"`
	Components []cyclonedxComponent `json:"components"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type spdxBOM struct {
	SPDXVersion string `json:"spdxVersion"`
	Name        string `json:"name"`
	Packages    []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func LoadSBOM(path string) (SBOM, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return SBOM{}, fmt.Errorf("read sbom: %w", err)
	}
	return LoadSBOMBytes(content)
}

func LoadSBOMBytes(content []byte) (SBOM, error) {
	var envelope struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(content, &envelope); err != nil {
		return SBOM{}, fmt.Errorf("decode sbom envelope: %w", err)
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(envelope.BOMFormat), "CycloneDX"):
		return loadCycloneDXSBOM(content)
	case strings.TrimSpace(envelope.SPDXVersion) != "":
		return loadSPDXSBOM(content)
	default:
		return loadCycloneDXSBOM(content)
	}
}

func loadCycloneDXSBOM(content []byte) (SBOM, error) {
	var bom cyclonedxBOM
	if err := json.Unmarshal(content, &bom); err != nil {
		return SBOM{}, fmt.Errorf("decode cyclonedx sbom: %w", err)
	}
	sbom := SBOM{ImageRef: bom.Metadata.Component.Name}
	for _, component := range bom.Components {
		ecosystem := ecosystemFromPURL(component.PURL)
		if ecosystem == "" {
			continue
		}
		sbom.Packages = append(sbom.Packages, Package{
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: ecosystem,
			PURL:      component.PURL,
		})
	}
	if sbom.ImageRef == "" {
		return SBOM{}, fmt.Errorf("sbom metadata.component.name is required")
	}
	return sbom, nil
}

func loadSPDXSBOM(content []byte) (SBOM, error) {
	var bom spdxBOM
	if err := json.Unmarshal(content, &bom); err != nil {
		return SBOM{}, fmt.Errorf("decode spdx sbom: %w", err)
	}
	sbom := SBOM{ImageRef: strings.TrimSpace(bom.Name)}
	for _, pkg := range bom.Packages {
		purl := ""
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(strings.TrimSpace(ref.ReferenceType), "purl") {
				purl = strings.TrimSpace(ref.ReferenceLocator)
				break
			}
		}
		ecosystem := ecosystemFromPURL(purl)
		if ecosystem == "" {
			continue
		}
		sbom.Packages = append(sbom.Packages, Package{
			Name:      pkg.Name,
			Version:   pkg.VersionInfo,
			Ecosystem: ecosystem,
			PURL:      purl,
		})
	}
	if sbom.ImageRef == "" {
		return SBOM{}, fmt.Errorf("spdx name is required")
	}
	return sbom, nil
}

func LoadSBOMIndex(paths []string, load func(string) (SBOM, error)) (SBOMIndex, error) {
	index := SBOMIndex{}
	for _, path := range paths {
		sbom, err := load(path)
		if err != nil {
			return nil, err
		}
		key := normalizeImageRef(sbom.ImageRef)
		if key == "" {
			return nil, fmt.Errorf("sbom image reference is empty for %s", path)
		}
		index[key] = sbom
	}
	return index, nil
}

func LoadAdvisories(path string) (AdvisoryBundle, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return AdvisoryBundle{}, fmt.Errorf("read advisories: %w", err)
	}
	return LoadAdvisoriesBytes(content)
}

func LoadAdvisoriesBytes(content []byte) (AdvisoryBundle, error) {
	var bundle AdvisoryBundle
	if err := yaml.Unmarshal(content, &bundle); err != nil {
		return AdvisoryBundle{}, fmt.Errorf("decode advisories: %w", err)
	}
	bundle = normalizeAdvisoryBundle(bundle)
	if err := validateBundle(bundle); err != nil {
		return AdvisoryBundle{}, err
	}
	return bundle, nil
}

func validateBundle(bundle AdvisoryBundle) error {
	bundle = normalizeAdvisoryBundle(bundle)
	if bundle.APIVersion != AdvisoryBundleAPIVersion {
		return fmt.Errorf("unsupported advisory bundle apiVersion %q", bundle.APIVersion)
	}
	if bundle.Kind != AdvisoryBundleKind {
		return fmt.Errorf("advisory bundle kind must be %s", AdvisoryBundleKind)
	}
	for _, advisory := range bundle.Advisories {
		if advisory.ID == "" {
			return fmt.Errorf("advisory id is required")
		}
		if advisory.PackageName == "" {
			return fmt.Errorf("advisory %s packageName is required", advisory.ID)
		}
		if advisory.Ecosystem == "" {
			return fmt.Errorf("advisory %s ecosystem is required", advisory.ID)
		}
		if len(advisory.AffectedVersions) == 0 {
			return fmt.Errorf("advisory %s affectedVersions is required", advisory.ID)
		}
		for _, expression := range advisory.AffectedVersions {
			if err := validateAffectedVersionExpression(advisory.Ecosystem, expression); err != nil {
				return fmt.Errorf("advisory %s invalid affectedVersions entry %q: %w", advisory.ID, expression, err)
			}
		}
		if !policyMeetsSeverity(advisory.Severity) {
			return fmt.Errorf("advisory %s severity %q is invalid", advisory.ID, advisory.Severity)
		}
	}
	return nil
}

func normalizeAdvisoryBundle(bundle AdvisoryBundle) AdvisoryBundle {
	if strings.TrimSpace(bundle.APIVersion) == "" {
		bundle.APIVersion = AdvisoryBundleAPIVersion
	} else if bundle.APIVersion == "kubescan.io/v1alpha1" {
		bundle.APIVersion = AdvisoryBundleAPIVersion
	}
	if strings.TrimSpace(bundle.Kind) == "" {
		bundle.Kind = AdvisoryBundleKind
	}
	return bundle
}

func ecosystemFromPURL(purl string) string {
	if purl == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(purl, "pkg:apk/"):
		return "apk"
	case strings.HasPrefix(purl, "pkg:deb/"):
		return "deb"
	case strings.HasPrefix(purl, "pkg:golang/"):
		return "golang"
	case strings.HasPrefix(purl, "pkg:maven/"):
		return "maven"
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "npm"
	case strings.HasPrefix(purl, "pkg:cargo/"):
		return "cargo"
	case strings.HasPrefix(purl, "pkg:composer/"):
		return "composer"
	case strings.HasPrefix(purl, "pkg:nuget/"):
		return "nuget"
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "pypi"
	case strings.HasPrefix(purl, "pkg:gem/"):
		return "gem"
	case strings.HasPrefix(purl, "pkg:rpm/"):
		return "rpm"
	default:
		return ""
	}
}

func policyMeetsSeverity(severity policy.Severity) bool {
	_, err := policy.ParseSeverity(string(severity))
	return err == nil
}

func validateAffectedVersionExpression(ecosystem, expression string) error {
	for _, clause := range strings.Split(expression, ",") {
		if _, err := parseConstraint(clause); err != nil {
			return err
		}
	}
	if _, err := matchesAffectedVersion(ecosystem, "0", []string{expression}); err != nil {
		return err
	}
	return nil
}
