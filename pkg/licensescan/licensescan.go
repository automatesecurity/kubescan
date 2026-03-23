package licensescan

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"kubescan/pkg/policy"
)

type Policy struct {
	Allowlist []string
	Denylist  []string
}

type Declaration struct {
	Ecosystem         string
	PackageName       string
	LicenseExpression string
	Identifiers       []string
}

var (
	cargoLicenseRegex     = regexp.MustCompile(`(?m)^\s*license\s*=\s*"([^"]+)"\s*$`)
	pyprojectLicenseRegex = regexp.MustCompile(`(?m)^\s*license\s*=\s*"([^"]+)"\s*$`)
	spdxTokenRegex        = regexp.MustCompile(`[A-Za-z][A-Za-z0-9.+-]*`)
)

func EvaluateFile(relativePath string, content []byte, cfg Policy, now time.Time) []policy.Finding {
	declarations := DetectDeclarations(relativePath, content)
	if len(declarations) == 0 {
		return nil
	}

	allow := normalizeList(cfg.Allowlist)
	deny := normalizeList(cfg.Denylist)
	var findings []policy.Finding
	for _, declaration := range declarations {
		if finding := disallowedLicenseFinding(relativePath, declaration, deny, now); finding != nil {
			findings = append(findings, *finding)
		}
		if finding := unapprovedLicenseFinding(relativePath, declaration, allow, now); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

func DetectDeclarations(relativePath string, content []byte) []Declaration {
	switch strings.ToLower(filepath.Base(relativePath)) {
	case "package.json":
		if declaration, ok := detectPackageJSON(content); ok {
			return []Declaration{declaration}
		}
	case "cargo.toml":
		if declaration, ok := detectRegexManifest("cargo", content, cargoLicenseRegex); ok {
			return []Declaration{declaration}
		}
	case "pyproject.toml":
		if declaration, ok := detectRegexManifest("python", content, pyprojectLicenseRegex); ok {
			return []Declaration{declaration}
		}
	}
	return nil
}

func detectPackageJSON(content []byte) (Declaration, bool) {
	var payload struct {
		Name    string `json:"name"`
		License any    `json:"license"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return Declaration{}, false
	}
	expression, ok := payload.License.(string)
	if !ok || strings.TrimSpace(expression) == "" {
		return Declaration{}, false
	}
	return Declaration{
		Ecosystem:         "npm",
		PackageName:       payload.Name,
		LicenseExpression: strings.TrimSpace(expression),
		Identifiers:       parseLicenseIdentifiers(expression),
	}, true
}

func detectRegexManifest(ecosystem string, content []byte, expressionRegex *regexp.Regexp) (Declaration, bool) {
	match := expressionRegex.FindSubmatch(content)
	if len(match) != 2 {
		return Declaration{}, false
	}
	expression := strings.TrimSpace(string(match[1]))
	if expression == "" {
		return Declaration{}, false
	}
	return Declaration{
		Ecosystem:         ecosystem,
		LicenseExpression: expression,
		Identifiers:       parseLicenseIdentifiers(expression),
	}, true
}

func parseLicenseIdentifiers(expression string) []string {
	if strings.TrimSpace(expression) == "" {
		return nil
	}
	var identifiers []string
	for _, token := range spdxTokenRegex.FindAllString(expression, -1) {
		normalized := strings.ToUpper(strings.TrimSpace(token))
		switch normalized {
		case "", "AND", "OR", "WITH":
			continue
		default:
			identifiers = append(identifiers, normalized)
		}
	}
	if len(identifiers) == 0 {
		identifiers = append(identifiers, strings.ToUpper(strings.TrimSpace(expression)))
	}
	slices.Sort(identifiers)
	return slices.Compact(identifiers)
}

func disallowedLicenseFinding(relativePath string, declaration Declaration, deny []string, now time.Time) *policy.Finding {
	if len(deny) == 0 {
		return nil
	}
	var matched []string
	for _, identifier := range declaration.Identifiers {
		if slices.Contains(deny, identifier) {
			matched = append(matched, identifier)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	message := fmt.Sprintf("File/%s declares disallowed license %s", relativePath, strings.Join(matched, ", "))
	if declaration.PackageName != "" {
		message = fmt.Sprintf("File/%s declares disallowed license %s for package %s", relativePath, strings.Join(matched, ", "), declaration.PackageName)
	}
	finding := makeFinding(
		"KL001",
		"Disallowed license detected",
		policy.SeverityHigh,
		relativePath,
		message,
		"Replace the disallowed license with an approved one or document a legal-policy exception before distributing the artifact.",
		declaration,
		now,
	)
	finding.Evidence["matchedLicenses"] = matched
	return &finding
}

func unapprovedLicenseFinding(relativePath string, declaration Declaration, allow []string, now time.Time) *policy.Finding {
	if len(allow) == 0 {
		return nil
	}
	var unapproved []string
	for _, identifier := range declaration.Identifiers {
		if !slices.Contains(allow, identifier) {
			unapproved = append(unapproved, identifier)
		}
	}
	if len(unapproved) == 0 {
		return nil
	}
	message := fmt.Sprintf("File/%s declares license %s that is not in the configured allowlist", relativePath, strings.Join(unapproved, ", "))
	if declaration.PackageName != "" {
		message = fmt.Sprintf("File/%s declares license %s for package %s that is not in the configured allowlist", relativePath, strings.Join(unapproved, ", "), declaration.PackageName)
	}
	finding := makeFinding(
		"KL002",
		"License not in allowlist",
		policy.SeverityMedium,
		relativePath,
		message,
		"Use an approved license or expand the allowlist only after legal review.",
		declaration,
		now,
	)
	finding.Evidence["unapprovedLicenses"] = unapproved
	finding.Evidence["allowlist"] = allow
	return &finding
}

func makeFinding(ruleID string, title string, severity policy.Severity, relativePath string, message string, remediation string, declaration Declaration, now time.Time) policy.Finding {
	sum := sha1.Sum([]byte(strings.Join([]string{
		ruleID,
		relativePath,
		declaration.Ecosystem,
		declaration.PackageName,
		declaration.LicenseExpression,
		message,
	}, "|")))
	return policy.Finding{
		ID:          hex.EncodeToString(sum[:8]),
		Category:    policy.CategorySupplyChain,
		RuleID:      ruleID,
		Title:       title,
		Severity:    severity,
		RuleVersion: "license/v1alpha1",
		Resource: policy.ResourceRef{
			Kind: "File",
			Name: relativePath,
		},
		Message: message,
		Evidence: map[string]any{
			"ecosystem":         declaration.Ecosystem,
			"packageName":       declaration.PackageName,
			"licenseExpression": declaration.LicenseExpression,
			"identifiers":       declaration.Identifiers,
		},
		Remediation: remediation,
		Timestamp:   now.UTC(),
	}
}

func normalizeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	slices.Sort(normalized)
	return slices.Compact(normalized)
}
