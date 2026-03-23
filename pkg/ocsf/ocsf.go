package ocsf

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"kubescan/pkg/policy"
	"kubescan/pkg/report"
)

const (
	SchemaVersion  = "1.8.0"
	findingsUID    = 2
	productName    = "kubescan"
	productVendor  = "kubescan"
	productVersion = "dev"
)

type Event map[string]any

func WriteJSON(w io.Writer, result report.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(BuildEvents(result))
}

func BuildEvents(result report.ScanResult) []Event {
	events := make([]Event, 0, len(result.Findings))
	for _, finding := range result.Findings {
		switch finding.Category {
		case policy.CategoryVuln:
			events = append(events, vulnerabilityEvent(finding))
		default:
			events = append(events, postureEvent(finding, result.Compliance))
		}
	}
	if result.Compliance != nil {
		events = append(events, complianceEvents(*result.Compliance, result.Findings)...)
	}
	return events
}

func postureEvent(finding policy.Finding, compliance *policy.ComplianceReport) Event {
	resource := resourceMap(finding.Resource, finding.Evidence)
	event := baseFindingEvent(7, "Application Security Posture Finding", finding)
	event["application"] = applicationMap(finding.Resource)
	event["resources"] = []map[string]any{resource}
	event["remediation"] = remediationMap(finding.Remediation)
	if mappedCompliance := complianceContextForFinding(finding.RuleID, compliance); len(mappedCompliance) > 0 {
		event["compliance"] = mappedCompliance
	}
	event["unmapped"] = compactMap(map[string]any{
		"rule_id":           finding.RuleID,
		"rule_version":      finding.RuleVersion,
		"category":          finding.Category,
		"original_severity": finding.OriginalSeverity,
		"evidence":          finding.Evidence,
	})
	return event
}

func vulnerabilityEvent(finding policy.Finding) Event {
	resource := resourceMap(finding.Resource, finding.Evidence)
	event := baseFindingEvent(2, "Vulnerability Finding", finding)
	event["resources"] = []map[string]any{resource}
	event["vulnerabilities"] = []map[string]any{vulnerabilityMap(finding)}
	event["remediation"] = remediationMap(finding.Remediation)
	event["unmapped"] = compactMap(map[string]any{
		"rule_id":           finding.RuleID,
		"rule_version":      finding.RuleVersion,
		"category":          finding.Category,
		"original_severity": finding.OriginalSeverity,
		"evidence":          finding.Evidence,
	})
	return event
}

func complianceEvents(report policy.ComplianceReport, findings []policy.Finding) []Event {
	byRule := make(map[string][]policy.Finding)
	for _, finding := range findings {
		byRule[finding.RuleID] = append(byRule[finding.RuleID], finding)
	}

	events := make([]Event, 0, len(report.Controls))
	for _, control := range report.Controls {
		timestamp := time.Now().UTC()
		if len(findings) > 0 {
			timestamp = latestTimestamp(findings)
		}
		severity := severityForComplianceControl(control, byRule)
		message := fmt.Sprintf("%s compliance control %s is %s", report.Profile, control.ID, control.Status)
		event := baseFindingEvent(3, "Compliance Finding", policy.Finding{
			ID:          report.Profile + ":" + control.ID,
			Title:       control.Title,
			Severity:    severity,
			Message:     message,
			Remediation: complianceRemediation(control),
			Timestamp:   timestamp,
		})
		event["finding_info"] = findingInfoMap(policy.Finding{
			ID:          report.Profile + ":" + control.ID,
			Title:       control.Title,
			Message:     message,
			Timestamp:   timestamp,
			Severity:    severity,
			Remediation: complianceRemediation(control),
		}, []string{report.Profile, control.ID})
		event["compliance"] = complianceMap(report, control)
		if resources := complianceResources(control, byRule); len(resources) > 0 {
			event["resources"] = resources
		}
		event["remediation"] = remediationMap(complianceRemediation(control))
		event["unmapped"] = compactMap(map[string]any{
			"profile":          report.Profile,
			"profile_title":    report.Title,
			"rule_ids":         control.RuleIDs,
			"failing_findings": control.FailingFindings,
		})
		events = append(events, event)
	}
	return events
}

func baseFindingEvent(classUID int, className string, finding policy.Finding) Event {
	severityID, severityName := severityMap(finding.Severity)
	activityID := 1
	activityName := "Create"
	typeUID := classUID*100 + activityID
	typeName := fmt.Sprintf("%s: %s", className, activityName)
	statusID := 1
	statusName := "New"
	statusCode := "new"
	statusDetail := "Reported by kubescan in the current scan."
	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now().UTC()
	}

	return Event{
		"activity_id":   activityID,
		"activity_name": activityName,
		"category_uid":  findingsUID,
		"category_name": "Findings",
		"class_uid":     classUID,
		"class_name":    className,
		"type_uid":      typeUID,
		"type_name":     typeName,
		"severity_id":   severityID,
		"severity":      severityName,
		"time":          toTimestampMillis(finding.Timestamp),
		"message":       finding.Message,
		"metadata":      metadataMap(finding),
		"finding_info":  findingInfoMap(finding, nil),
		"status_id":     statusID,
		"status":        statusName,
		"status_code":   statusCode,
		"status_detail": statusDetail,
	}
}

func metadataMap(finding policy.Finding) map[string]any {
	return compactMap(map[string]any{
		"uid":           finding.ID,
		"version":       SchemaVersion,
		"log_name":      productName,
		"source":        "kubescan-scan",
		"original_time": toTimestampMillis(nonZeroTime(finding.Timestamp)),
		"product": map[string]any{
			"name":        productName,
			"uid":         productName,
			"vendor_name": productVendor,
			"version":     productVersion,
		},
	})
}

func findingInfoMap(finding policy.Finding, extraTypes []string) map[string]any {
	types := []string{}
	if finding.RuleID != "" {
		types = append(types, finding.RuleID)
	}
	if finding.Category != "" {
		types = append(types, string(finding.Category))
	}
	types = append(types, extraTypes...)
	sort.Strings(types)
	types = uniqueStrings(types)

	return compactMap(map[string]any{
		"uid":             finding.ID,
		"title":           finding.Title,
		"desc":            finding.Message,
		"created_time":    toTimestampMillis(nonZeroTime(finding.Timestamp)),
		"modified_time":   toTimestampMillis(nonZeroTime(finding.Timestamp)),
		"first_seen_time": toTimestampMillis(nonZeroTime(finding.Timestamp)),
		"last_seen_time":  toTimestampMillis(nonZeroTime(finding.Timestamp)),
		"product_uid":     productName,
		"product": map[string]any{
			"name":        productName,
			"uid":         productName,
			"vendor_name": productVendor,
			"version":     productVersion,
		},
		"types": types,
	})
}

func remediationMap(desc string) map[string]any {
	if strings.TrimSpace(desc) == "" {
		return nil
	}
	return map[string]any{"desc": desc}
}

func resourceMap(resource policy.ResourceRef, evidence map[string]any) map[string]any {
	data := compactMap(map[string]any{
		"api_version": resource.APIVersion,
		"namespace":   resource.Namespace,
		"kind":        resource.Kind,
		"name":        resource.Name,
	})
	if len(evidence) > 0 {
		data["evidence"] = evidence
	}
	return compactMap(map[string]any{
		"uid":  resourceURI(resource),
		"name": resource.Name,
		"type": resource.Kind,
		"data": data,
	})
}

func applicationMap(resource policy.ResourceRef) map[string]any {
	if resource.Kind == "" || resource.Name == "" {
		return nil
	}
	return compactMap(map[string]any{
		"uid":   resourceURI(resource),
		"name":  resource.Name,
		"type":  resource.Kind,
		"group": resource.Namespace,
		"data": compactMap(map[string]any{
			"api_version": resource.APIVersion,
			"namespace":   resource.Namespace,
		}),
	})
}

func vulnerabilityMap(finding policy.Finding) map[string]any {
	evidence := finding.Evidence
	vulnerability := compactMap(map[string]any{
		"title":       finding.Title,
		"desc":        finding.Message,
		"severity":    string(finding.Severity),
		"category":    stringValue(evidence["ecosystem"]),
		"vendor_name": productName,
		"references":  aliasReferences(evidence["aliases"]),
		"affected_packages": []map[string]any{
			compactMap(map[string]any{
				"name":    stringValue(evidence["packageName"]),
				"version": stringValue(evidence["packageVersion"]),
				"type":    stringValue(evidence["ecosystem"]),
			}),
		},
		"remediation":      remediationMap(finding.Remediation),
		"is_fix_available": strings.TrimSpace(stringValue(evidence["fixedVersion"])) != "",
	})
	if strings.HasPrefix(strings.ToUpper(finding.RuleID), "CVE-") {
		vulnerability["cve"] = map[string]any{"uid": finding.RuleID}
	} else {
		vulnerability["advisory"] = map[string]any{
			"uid":    finding.RuleID,
			"title":  finding.Title,
			"vendor": productName,
		}
	}
	return vulnerability
}

func aliasReferences(value any) []map[string]any {
	aliases, ok := value.([]string)
	if !ok || len(aliases) == 0 {
		return nil
	}
	references := make([]map[string]any, 0, len(aliases))
	for _, alias := range aliases {
		if strings.TrimSpace(alias) == "" {
			continue
		}
		references = append(references, map[string]any{
			"description": alias,
		})
	}
	if len(references) == 0 {
		return nil
	}
	return references
}

func complianceContextForFinding(ruleID string, compliance *policy.ComplianceReport) map[string]any {
	if compliance == nil {
		return nil
	}
	var checks []map[string]any
	for _, control := range compliance.Controls {
		for _, candidate := range control.RuleIDs {
			if candidate == ruleID {
				checks = append(checks, map[string]any{
					"uid":    control.ID,
					"name":   control.Title,
					"status": string(control.Status),
				})
				break
			}
		}
	}
	if len(checks) == 0 {
		return nil
	}
	return compactMap(map[string]any{
		"standards": []string{compliance.Title},
		"checks":    checks,
	})
}

func complianceMap(report policy.ComplianceReport, control policy.ComplianceControlResult) map[string]any {
	statusID := 1
	status := "Pass"
	if control.Status == policy.ComplianceStatusFail {
		statusID = 3
		status = "Fail"
	}
	return compactMap(map[string]any{
		"standards":    []string{report.Title},
		"control":      control.ID,
		"desc":         control.Title,
		"requirements": control.RuleIDs,
		"status_id":    statusID,
		"status":       status,
		"status_details": []string{
			fmt.Sprintf("%d failing findings", control.FailingFindings),
		},
		"checks": []map[string]any{
			{
				"uid":  control.ID,
				"name": control.Title,
			},
		},
	})
}

func complianceResources(control policy.ComplianceControlResult, byRule map[string][]policy.Finding) []map[string]any {
	seen := map[string]struct{}{}
	var resources []map[string]any
	for _, ruleID := range control.RuleIDs {
		for _, finding := range byRule[ruleID] {
			uri := resourceURI(finding.Resource)
			if _, ok := seen[uri]; ok {
				continue
			}
			seen[uri] = struct{}{}
			resources = append(resources, resourceMap(finding.Resource, nil))
		}
	}
	return resources
}

func severityForComplianceControl(control policy.ComplianceControlResult, byRule map[string][]policy.Finding) policy.Severity {
	if control.Status == policy.ComplianceStatusPass {
		return policy.SeverityLow
	}
	highest := policy.SeverityLow
	for _, ruleID := range control.RuleIDs {
		for _, finding := range byRule[ruleID] {
			if policy.MeetsOrExceedsSeverity(finding.Severity, highest) {
				highest = finding.Severity
			}
		}
	}
	return highest
}

func complianceRemediation(control policy.ComplianceControlResult) string {
	if control.Status == policy.ComplianceStatusPass {
		return "No remediation required; the control currently passes."
	}
	return "Review the mapped failing Kubescan rules and remediate the affected Kubernetes resources."
}

func severityMap(severity policy.Severity) (int, string) {
	switch severity {
	case policy.SeverityLow:
		return 2, "Low"
	case policy.SeverityMedium:
		return 3, "Medium"
	case policy.SeverityHigh:
		return 4, "High"
	case policy.SeverityCritical:
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}

func toTimestampMillis(value time.Time) int64 {
	return value.UTC().UnixMilli()
}

func resourceURI(resource policy.ResourceRef) string {
	if resource.Namespace != "" {
		return "k8s://" + resource.Namespace + "/" + resource.Kind + "/" + resource.Name
	}
	return "k8s://cluster/" + resource.Kind + "/" + resource.Name
}

func latestTimestamp(findings []policy.Finding) time.Time {
	latest := time.Time{}
	for _, finding := range findings {
		if finding.Timestamp.After(latest) {
			latest = finding.Timestamp
		}
	}
	return nonZeroTime(latest)
}

func nonZeroTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func compactMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	compact := map[string]any{}
	for key, value := range values {
		switch typed := value.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
		case []string:
			if len(typed) == 0 {
				continue
			}
		case []map[string]any:
			if len(typed) == 0 {
				continue
			}
		case map[string]any:
			if len(typed) == 0 {
				continue
			}
		}
		compact[key] = value
	}
	if len(compact) == 0 {
		return nil
	}
	return compact
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:0]
	var last string
	for i, value := range values {
		if i == 0 || value != last {
			result = append(result, value)
			last = value
		}
	}
	return result
}

func stringValue(value any) string {
	typed, ok := value.(string)
	if !ok {
		return ""
	}
	return typed
}
