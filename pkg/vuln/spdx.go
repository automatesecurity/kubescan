package vuln

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type spdxDocument struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	Packages          []spdxPackage `json:"packages,omitempty"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func WriteSPDX(w io.Writer, sbom SBOM) error {
	digest := sha1.Sum([]byte(strings.Join([]string{sbom.ImageRef, fmt.Sprint(len(sbom.Packages))}, "|")))
	document := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              sbom.ImageRef,
		DocumentNamespace: fmt.Sprintf("https://github.com/automatesecurity/kubescan/spdx/%x", digest),
	}
	for i, pkg := range sbom.Packages {
		entry := spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             pkg.Name,
			VersionInfo:      pkg.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}
		if purl := packagePURL(pkg); purl != "" {
			entry.ExternalRefs = append(entry.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}
		document.Packages = append(document.Packages, entry)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode spdx sbom: %w", err)
	}
	return nil
}
