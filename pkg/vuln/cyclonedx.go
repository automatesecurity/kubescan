package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type cyclonedxDocument struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Metadata    cyclonedxBOMMetadata `json:"metadata"`
	Components  []cyclonedxComponent `json:"components,omitempty"`
}

type cyclonedxBOMMetadata struct {
	Component cyclonedxComponent `json:"component"`
}

func WriteCycloneDX(w io.Writer, sbom SBOM) error {
	document := cyclonedxDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cyclonedxBOMMetadata{
			Component: cyclonedxComponent{
				Type: "container",
				Name: sbom.ImageRef,
			},
		},
	}

	packages := append([]Package(nil), sbom.Packages...)
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		return packages[i].Version < packages[j].Version
	})
	for _, pkg := range packages {
		document.Components = append(document.Components, cyclonedxComponent{
			Type:    "library",
			Name:    pkg.Name,
			Version: pkg.Version,
			PURL:    packagePURL(pkg),
		})
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode cyclonedx sbom: %w", err)
	}
	return nil
}

func packagePURL(pkg Package) string {
	if pkg.PURL != "" {
		return pkg.PURL
	}
	switch pkg.Ecosystem {
	case "apk":
		return fmt.Sprintf("pkg:apk/kubescan/%s@%s", pkg.Name, pkg.Version)
	case "deb":
		return fmt.Sprintf("pkg:deb/kubescan/%s@%s", pkg.Name, pkg.Version)
	case "golang":
		return fmt.Sprintf("pkg:golang/%s@%s", pkg.Name, pkg.Version)
	case "maven":
		if parts := strings.SplitN(pkg.Name, ":", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", parts[0], parts[1], pkg.Version)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", pkg.Name, pkg.Version)
	case "rpm":
		return fmt.Sprintf("pkg:rpm/kubescan/%s@%s", pkg.Name, pkg.Version)
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", pkg.Name, pkg.Version)
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", pkg.Name, pkg.Version)
	case "composer":
		return fmt.Sprintf("pkg:composer/%s@%s", pkg.Name, pkg.Version)
	case "nuget":
		return fmt.Sprintf("pkg:nuget/%s@%s", pkg.Name, pkg.Version)
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", pkg.Name, pkg.Version)
	case "gem":
		return fmt.Sprintf("pkg:gem/%s@%s", pkg.Name, pkg.Version)
	default:
		return ""
	}
}
