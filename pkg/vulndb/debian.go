package vulndb

import (
	"encoding/json"
	"fmt"
	"strings"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

type debianTrackerDocument map[string]map[string]debianTrackerEntry

type debianTrackerEntry struct {
	Description string                          `json:"description"`
	Releases    map[string]debianTrackerRelease `json:"releases"`
}

type debianTrackerRelease struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

func LoadDebianSecurityTrackerSource(pathOrURL, release string) (vuln.AdvisoryBundle, error) {
	content, err := readPathOrURL(pathOrURL)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadDebianSecurityTrackerBytes(content, release)
}

func LoadDebianSecurityTrackerBytes(content []byte, release string) (vuln.AdvisoryBundle, error) {
	content = trimBOM(content)
	release = strings.TrimSpace(release)
	if release == "" {
		return vuln.AdvisoryBundle{}, fmt.Errorf("debian security tracker release is required")
	}

	var doc debianTrackerDocument
	if err := json.Unmarshal(content, &doc); err != nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("decode debian security tracker source: %w", err)
	}

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	for packageName, advisories := range doc {
		packageName = strings.TrimSpace(packageName)
		if packageName == "" {
			continue
		}
		for id, entry := range advisories {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			releaseInfo, ok := entry.Releases[release]
			if !ok {
				continue
			}

			affected := debianAffectedVersions(releaseInfo)
			if len(affected) == 0 {
				continue
			}

			summary := strings.TrimSpace(entry.Description)
			if summary == "" {
				summary = fmt.Sprintf("Debian security tracker advisory for %s", packageName)
			}

			bundle.Advisories = append(bundle.Advisories, vuln.Advisory{
				ID:               id,
				PackageName:      packageName,
				Ecosystem:        "deb",
				AffectedVersions: affected,
				FixedVersion:     debianFixedVersion(releaseInfo),
				Severity:         debianUrgencySeverity(releaseInfo.Urgency),
				Summary:          summary,
			})
		}
	}
	return bundle, nil
}

func debianAffectedVersions(release debianTrackerRelease) []string {
	fixed := debianFixedVersion(release)
	if fixed != "" {
		return []string{"<" + fixed}
	}

	if strings.EqualFold(strings.TrimSpace(release.Status), "open") {
		var versions []string
		for _, version := range release.Repositories {
			version = strings.TrimSpace(version)
			if version == "" {
				continue
			}
			versions = append(versions, "="+version)
		}
		return dedupeStrings(versions)
	}

	return nil
}

func debianFixedVersion(release debianTrackerRelease) string {
	value := strings.TrimSpace(release.FixedVersion)
	if value == "" || value == "0" {
		return ""
	}
	return value
}

func debianUrgencySeverity(value string) policy.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return policy.SeverityCritical
	case "high":
		return policy.SeverityHigh
	case "medium", "moderate":
		return policy.SeverityMedium
	case "low", "unimportant", "not yet assigned":
		return policy.SeverityLow
	default:
		return policy.SeverityMedium
	}
}
