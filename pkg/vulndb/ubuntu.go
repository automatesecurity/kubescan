package vulndb

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

type ubuntuOSVEnvelope struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases"`
	Upstream      []string `json:"upstream"`
	Summary       string   `json:"summary"`
	Details       string   `json:"details"`
	Severity      []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []ubuntuOSVAffected `json:"affected"`
}

type ubuntuOSVAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
	Versions          []string `json:"versions"`
	EcosystemSpecific struct {
		Binaries []struct {
			BinaryName    string `json:"binary_name"`
			BinaryVersion string `json:"binary_version"`
		} `json:"binaries"`
	} `json:"ecosystem_specific"`
}

func LoadUbuntuSecurityNoticesSource(pathOrURL, release string) (vuln.AdvisoryBundle, error) {
	content, err := readPathOrURL(pathOrURL)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadUbuntuSecurityNoticesBytes(content, release)
}

func LoadUbuntuSecurityNoticesBytes(content []byte, release string) (vuln.AdvisoryBundle, error) {
	content = trimBOM(content)
	release = strings.TrimSpace(release)
	if release == "" {
		return vuln.AdvisoryBundle{}, fmt.Errorf("ubuntu security notices release is required")
	}

	if bundle, err := loadUbuntuSecurityArchive(content, release); err == nil {
		return bundle, nil
	}
	return loadUbuntuSecurityNoticesDocument(content, release)
}

func loadUbuntuSecurityArchive(content []byte, release string) (vuln.AdvisoryBundle, error) {
	readerAt := bytes.NewReader(content)
	zr, err := zip.NewReader(readerAt, int64(len(content)))
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	for _, file := range zr.File {
		name := strings.ReplaceAll(file.Name, "\\", "/")
		if !strings.Contains(name, "/osv/cve/") || !strings.HasSuffix(name, ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("open ubuntu notice %s: %w", name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("read ubuntu notice %s: %w", name, err)
		}
		docBundle, err := loadUbuntuSecurityNoticesDocument(content, release)
		if err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("parse ubuntu notice %s: %w", name, err)
		}
		bundle.Advisories = append(bundle.Advisories, docBundle.Advisories...)
	}
	return bundle, nil
}

func loadUbuntuSecurityNoticesDocument(content []byte, release string) (vuln.AdvisoryBundle, error) {
	var doc ubuntuOSVEnvelope
	if err := json.Unmarshal(content, &doc); err != nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("decode ubuntu security notice: %w", err)
	}

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	release = strings.ToLower(strings.TrimSpace(release))

	for _, affected := range doc.Affected {
		if !matchesUbuntuRelease(affected.Package.Ecosystem, release) {
			continue
		}
		affectedVersions, fixedVersion := normalizeUbuntuAffected(affected)
		if len(affectedVersions) == 0 {
			continue
		}

		names := ubuntuPackageNames(affected)
		for _, name := range names {
			bundle.Advisories = append(bundle.Advisories, vuln.Advisory{
				ID:               strings.TrimSpace(doc.ID),
				Aliases:          append(append([]string(nil), doc.Aliases...), doc.Upstream...),
				PackageName:      name,
				Ecosystem:        "deb",
				AffectedVersions: affectedVersions,
				FixedVersion:     fixedVersion,
				Severity:         deriveUbuntuSeverity(doc),
				Summary:          ubuntuSummary(doc, name),
			})
		}
	}
	return bundle, nil
}

func matchesUbuntuRelease(ecosystem, release string) bool {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if !strings.HasPrefix(ecosystem, "ubuntu:") {
		return false
	}
	return strings.Contains(ecosystem, release)
}

func ubuntuPackageNames(affected ubuntuOSVAffected) []string {
	var names []string
	for _, binary := range affected.EcosystemSpecific.Binaries {
		name := strings.TrimSpace(binary.BinaryName)
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 && strings.TrimSpace(affected.Package.Name) != "" {
		names = append(names, strings.TrimSpace(affected.Package.Name))
	}
	return dedupeStrings(names)
}

func normalizeUbuntuAffected(affected ubuntuOSVAffected) ([]string, string) {
	var expressions []string
	fixed := ""
	for _, rng := range affected.Ranges {
		rangeType := strings.TrimSpace(rng.Type)
		if rangeType != "ECOSYSTEM" && rangeType != "SEMVER" {
			continue
		}
		introduced := ""
		for _, event := range rng.Events {
			if value := strings.TrimSpace(event.Introduced); value != "" {
				if value == "0" {
					introduced = ""
				} else {
					introduced = value
				}
			}
			if value := strings.TrimSpace(event.Fixed); value != "" {
				expression := buildRangeExpression(introduced, value, false)
				if expression != "" {
					expressions = append(expressions, expression)
				}
				if fixed == "" {
					fixed = value
				}
				introduced = value
				continue
			}
			if value := strings.TrimSpace(event.LastAffected); value != "" {
				expression := buildRangeExpression(introduced, value, true)
				if expression != "" {
					expressions = append(expressions, expression)
				}
			}
		}
	}
	normalized := dedupeStrings(expressions)
	if len(normalized) > 0 {
		return normalized, fixed
	}

	var versions []string
	for _, version := range affected.Versions {
		version = strings.TrimSpace(version)
		if version == "" {
			continue
		}
		versions = append(versions, "="+version)
	}
	return dedupeStrings(versions), ""
}

func deriveUbuntuSeverity(doc ubuntuOSVEnvelope) policy.Severity {
	for _, severity := range doc.Severity {
		if strings.EqualFold(strings.TrimSpace(severity.Type), "Ubuntu") {
			if parsed, ok := parseSeverityLabel(severity.Score); ok {
				return parsed
			}
		}
		if parsed, ok := parseSeverityScore(severity.Score); ok {
			return parsed
		}
	}
	return policy.SeverityMedium
}

func ubuntuSummary(doc ubuntuOSVEnvelope, packageName string) string {
	summary := strings.TrimSpace(doc.Summary)
	if summary == "" {
		summary = strings.TrimSpace(doc.Details)
	}
	if summary == "" {
		summary = fmt.Sprintf("Ubuntu security notice for %s", packageName)
	}
	return summary
}
