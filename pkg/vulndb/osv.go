package vulndb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

type osvVulnerability struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

func LoadOSVSource(pathOrURL string) (vuln.AdvisoryBundle, error) {
	content, err := readPathOrURL(pathOrURL)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadOSVBytes(content)
}

func LoadOSVBytes(content []byte) (vuln.AdvisoryBundle, error) {
	content = trimBOM(content)

	var single osvVulnerability
	if err := json.Unmarshal(content, &single); err == nil && strings.TrimSpace(single.ID) != "" {
		return normalizeOSV([]osvVulnerability{single}), nil
	}

	var list []osvVulnerability
	if err := json.Unmarshal(content, &list); err != nil {
		var envelope struct {
			Vulns []osvVulnerability `json:"vulns"`
		}
		if envErr := json.Unmarshal(content, &envelope); envErr != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("decode osv source: %w", err)
		}
		list = envelope.Vulns
	}
	return normalizeOSV(list), nil
}

func normalizeOSV(records []osvVulnerability) vuln.AdvisoryBundle {
	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	for _, record := range records {
		for _, affected := range record.Affected {
			ecosystem := mapOSVEcosystem(affected.Package.Ecosystem)
			if ecosystem == "" || strings.TrimSpace(affected.Package.Name) == "" {
				continue
			}

			affectedVersions, fixedVersion := normalizeOSVRanges(affected)
			if len(affectedVersions) == 0 {
				continue
			}

			summary := strings.TrimSpace(record.Summary)
			if summary == "" {
				summary = strings.TrimSpace(record.Details)
			}
			if summary == "" {
				summary = fmt.Sprintf("%s vulnerability", record.ID)
			}

			bundle.Advisories = append(bundle.Advisories, vuln.Advisory{
				ID:               strings.TrimSpace(record.ID),
				Aliases:          append([]string(nil), record.Aliases...),
				PackageName:      strings.TrimSpace(affected.Package.Name),
				Ecosystem:        ecosystem,
				AffectedVersions: affectedVersions,
				FixedVersion:     fixedVersion,
				Severity:         deriveOSVSeverity(record, affected),
				Summary:          summary,
			})
		}
	}
	return bundle
}

func mapOSVEcosystem(value string) string {
	switch strings.TrimSpace(value) {
	case "Alpine":
		return "apk"
	case "Debian":
		return "deb"
	case "Kubernetes":
		return "kubernetes"
	case "Go", "Golang":
		return "golang"
	case "Maven":
		return "maven"
	case "npm":
		return "npm"
	case "crates.io":
		return "cargo"
	case "Packagist":
		return "composer"
	case "NuGet":
		return "nuget"
	case "PyPI":
		return "pypi"
	case "RubyGems":
		return "gem"
	default:
		if strings.HasPrefix(strings.TrimSpace(value), "Ubuntu:") {
			return "deb"
		}
		return ""
	}
}

func normalizeOSVRanges(affected osvAffected) ([]string, string) {
	var expressions []string
	fixedVersion := ""

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
				if fixedVersion == "" {
					fixedVersion = value
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

	for _, version := range affected.Versions {
		version = strings.TrimSpace(version)
		if version == "" {
			continue
		}
		expressions = append(expressions, "="+version)
	}

	return dedupeStrings(expressions), fixedVersion
}

func buildRangeExpression(introduced, end string, inclusiveEnd bool) string {
	end = strings.TrimSpace(end)
	if end == "" {
		return ""
	}
	parts := make([]string, 0, 2)
	if introduced != "" {
		parts = append(parts, ">="+introduced)
	}
	if inclusiveEnd {
		parts = append(parts, "<="+end)
	} else {
		parts = append(parts, "<"+end)
	}
	return strings.Join(parts, ",")
}

func deriveOSVSeverity(record osvVulnerability, affected osvAffected) policy.Severity {
	for _, candidate := range []string{
		affected.DatabaseSpecific.Severity,
		record.DatabaseSpecific.Severity,
	} {
		if severity, ok := parseSeverityLabel(candidate); ok {
			return severity
		}
	}
	for _, severity := range record.Severity {
		if parsed, ok := parseSeverityScore(severity.Score); ok {
			return parsed
		}
	}
	return policy.SeverityMedium
}

func parseSeverityLabel(value string) (policy.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return policy.SeverityCritical, true
	case "high":
		return policy.SeverityHigh, true
	case "medium", "moderate":
		return policy.SeverityMedium, true
	case "low":
		return policy.SeverityLow, true
	default:
		return "", false
	}
}

func parseSeverityScore(value string) (policy.Severity, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if strings.Contains(value, "/") {
		switch {
		case strings.Contains(value, "/C:H/I:H/A:H"):
			return policy.SeverityCritical, true
		case strings.Contains(value, "/C:H") || strings.Contains(value, "/I:H") || strings.Contains(value, "/A:H"):
			return policy.SeverityHigh, true
		default:
			return policy.SeverityMedium, true
		}
	}
	score, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return "", false
	}
	switch {
	case score >= 9.0:
		return policy.SeverityCritical, true
	case score >= 7.0:
		return policy.SeverityHigh, true
	case score >= 4.0:
		return policy.SeverityMedium, true
	default:
		return policy.SeverityLow, true
	}
}

func readPathOrURL(pathOrURL string) ([]byte, error) {
	if parsed, err := url.Parse(pathOrURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("unsupported osv source url scheme %q", parsed.Scheme)
		}
		resp, err := http.Get(parsed.String())
		if err != nil {
			return nil, fmt.Errorf("download osv source: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("download osv source: unexpected status %s", resp.Status)
		}
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read osv source: %w", err)
		}
		return content, nil
	}
	content, err := os.ReadFile(pathOrURL)
	if err != nil {
		return nil, fmt.Errorf("read osv source: %w", err)
	}
	return content, nil
}

func trimBOM(content []byte) []byte {
	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		return content[3:]
	}
	return content
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
