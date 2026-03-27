package vulndb

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

type kubernetesFeed struct {
	Items []kubernetesFeedItem `json:"items"`
}

type kubernetesFeedItem struct {
	ID          string `json:"id"`
	Summary     string `json:"summary"`
	ContentText string `json:"content_text"`
}

var (
	kubernetesOSVBlock = regexp.MustCompile("(?s)```json osv\\s*(\\{.*?\\})\\s*```")
	kubernetesLineExpr = regexp.MustCompile(`^\s*-?\s*([A-Za-z0-9._-]+)\s*:\s*([<>]=?|=)\s*v?([0-9][A-Za-z0-9.+~:_-]*)\s*$`)
	kubernetesRangeExp = regexp.MustCompile(`^\s*-?\s*([A-Za-z0-9._-]+)\s+v?([0-9][A-Za-z0-9.+~:_-]*)\s+to\s+v?([0-9][A-Za-z0-9.+~:_-]*)\s*$`)
)

func LoadKubernetesOfficialCVEFeedSource(pathOrURL string) (vuln.AdvisoryBundle, error) {
	content, err := readPathOrURL(pathOrURL)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadKubernetesOfficialCVEFeedBytes(content)
}

func LoadKubernetesOfficialCVEFeedBytes(content []byte) (vuln.AdvisoryBundle, error) {
	content = trimBOM(content)

	var feed kubernetesFeed
	if err := json.Unmarshal(content, &feed); err != nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("decode kubernetes official cve feed: %w", err)
	}

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	for _, item := range feed.Items {
		if advisories := loadKubernetesOSVBlock(item); len(advisories) > 0 {
			bundle.Advisories = append(bundle.Advisories, advisories...)
			continue
		}
		bundle.Advisories = append(bundle.Advisories, parseKubernetesTextItem(item)...)
	}
	return bundle, nil
}

func loadKubernetesOSVBlock(item kubernetesFeedItem) []vuln.Advisory {
	match := kubernetesOSVBlock.FindStringSubmatch(item.ContentText)
	if len(match) != 2 {
		return nil
	}
	bundle, err := LoadOSVBytes([]byte(match[1]))
	if err != nil {
		return nil
	}
	return bundle.Advisories
}

func parseKubernetesTextItem(item kubernetesFeedItem) []vuln.Advisory {
	affectedSection := sectionBody(item.ContentText, "Affected Versions")
	if strings.TrimSpace(affectedSection) == "" {
		return nil
	}
	fixedSection := sectionBody(item.ContentText, "Fixed Versions")
	components := kubernetesAffectedComponents(item.ContentText)
	severity := kubernetesSeverity(item.ContentText)

	affected := parseKubernetesVersionLines(affectedSection)
	fixed := parseKubernetesVersionLines(fixedSection)

	if strings.Contains(strings.ToLower(affectedSection), "all versions of kubernetes") && len(components) > 0 {
		for _, component := range components {
			affected = append(affected, kubernetesVersionLine{
				PackageName: component,
				Expression:  ">=0",
			})
		}
	}

	fixedByPackage := map[string][]string{}
	for _, line := range fixed {
		if line.FixedVersion != "" {
			fixedByPackage[line.PackageName] = append(fixedByPackage[line.PackageName], line.FixedVersion)
		}
	}

	var advisories []vuln.Advisory
	for _, line := range affected {
		advisory := vuln.Advisory{
			ID:               strings.TrimSpace(item.ID),
			PackageName:      line.PackageName,
			Ecosystem:        "kubernetes",
			AffectedVersions: []string{line.Expression},
			Severity:         severity,
			Summary:          strings.TrimSpace(item.Summary),
		}
		if advisory.Summary == "" {
			advisory.Summary = fmt.Sprintf("Kubernetes advisory for %s", line.PackageName)
		}
		if versions := fixedByPackage[line.PackageName]; len(versions) > 0 {
			advisory.FixedVersion = versions[0]
			fixedByPackage[line.PackageName] = versions[1:]
		}
		advisories = append(advisories, advisory)
	}
	return advisories
}

type kubernetesVersionLine struct {
	PackageName  string
	Expression   string
	FixedVersion string
}

func parseKubernetesVersionLines(section string) []kubernetesVersionLine {
	var results []kubernetesVersionLine
	for _, rawLine := range strings.Split(section, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if match := kubernetesLineExpr.FindStringSubmatch(line); len(match) == 4 {
			version := strings.TrimPrefix(strings.TrimSpace(match[3]), "v")
			item := kubernetesVersionLine{
				PackageName: strings.TrimSpace(match[1]),
				Expression:  match[2] + version,
			}
			if match[2] == ">=" {
				item.FixedVersion = version
			}
			results = append(results, item)
			continue
		}
		if match := kubernetesRangeExp.FindStringSubmatch(line); len(match) == 4 {
			results = append(results, kubernetesVersionLine{
				PackageName: strings.TrimSpace(match[1]),
				Expression:  fmt.Sprintf(">=%s,<=%s", strings.TrimPrefix(strings.TrimSpace(match[2]), "v"), strings.TrimPrefix(strings.TrimSpace(match[3]), "v")),
			})
		}
	}
	return results
}

func sectionBody(content, heading string) string {
	lines := strings.Split(content, "\n")
	inSection := false
	var section []string
	heading = strings.ToLower(strings.TrimSpace(heading))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lowered := strings.ToLower(trimmed)
		if strings.Contains(lowered, heading) {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(trimmed, "###") {
			break
		}
		if inSection {
			section = append(section, line)
		}
	}
	return strings.TrimSpace(strings.Join(section, "\n"))
}

func kubernetesAffectedComponents(content string) []string {
	section := sectionBody(content, "Affected Components")
	var components []string
	for _, rawLine := range strings.Split(section, "\n") {
		line := strings.Trim(strings.TrimSpace(rawLine), "-*` ")
		if line == "" {
			continue
		}
		components = append(components, line)
	}
	return dedupeStrings(components)
}

func kubernetesSeverity(content string) policy.Severity {
	match := regexp.MustCompile(`(?i)\b(Critical|High|Medium|Low)\b`).FindStringSubmatch(content)
	if len(match) == 2 {
		if severity, ok := parseSeverityLabel(match[1]); ok {
			return severity
		}
	}
	return policy.SeverityMedium
}
