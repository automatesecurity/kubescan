package vulndb

import (
	"encoding/json"
	"fmt"
	"strings"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

type alpineSecDBDocument struct {
	DistroVersion string `json:"distroversion"`
	RepoName      string `json:"reponame"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

type alpineVulnKey struct {
	pkg string
	id  string
}

func LoadAlpineSecDBSource(pathOrURL string) (vuln.AdvisoryBundle, error) {
	content, err := readPathOrURL(pathOrURL)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadAlpineSecDBBytes(content)
}

func LoadAlpineSecDBBytes(content []byte) (vuln.AdvisoryBundle, error) {
	content = trimBOM(content)

	var doc alpineSecDBDocument
	if err := json.Unmarshal(content, &doc); err != nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("decode alpine secdb source: %w", err)
	}

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	seen := map[alpineVulnKey]int{}

	for _, pkgEntry := range doc.Packages {
		packageName := strings.TrimSpace(pkgEntry.Pkg.Name)
		if packageName == "" || len(pkgEntry.Pkg.Secfixes) == 0 {
			continue
		}
		for fixedVersion, ids := range pkgEntry.Pkg.Secfixes {
			fixedVersion = strings.TrimSpace(fixedVersion)
			if fixedVersion == "" {
				continue
			}
			for _, id := range ids {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				advisory := vuln.Advisory{
					ID:               id,
					PackageName:      packageName,
					Ecosystem:        "apk",
					AffectedVersions: []string{"<" + fixedVersion},
					FixedVersion:     fixedVersion,
					Severity:         policy.SeverityMedium,
					Summary:          fmt.Sprintf("Alpine SecDB advisory for %s", packageName),
				}

				key := alpineVulnKey{pkg: packageName, id: id}
				if index, ok := seen[key]; ok {
					current := bundle.Advisories[index]
					if advisory.FixedVersion < current.FixedVersion {
						bundle.Advisories[index] = advisory
					}
					continue
				}

				seen[key] = len(bundle.Advisories)
				bundle.Advisories = append(bundle.Advisories, advisory)
			}
		}
	}

	return bundle, nil
}
