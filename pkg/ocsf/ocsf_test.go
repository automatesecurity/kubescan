package ocsf

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/policy"
	"kubescan/pkg/report"
)

func TestBuildEventsMapsFindingsAndCompliance(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	result := report.ScanResult{
		GeneratedAt: now,
		Findings: []policy.Finding{
			{
				ID:          "finding-1",
				RuleID:      "KS010",
				Title:       "Mutable image tag",
				Category:    policy.CategorySupplyChain,
				Severity:    policy.SeverityHigh,
				Resource:    policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Message:     "Deployment/api container \"api\" uses a mutable image tag",
				Remediation: "Pin by digest.",
				Timestamp:   now,
			},
			{
				ID:          "finding-2",
				RuleID:      "CVE-2026-0001",
				Title:       "OpenSSL vulnerable package",
				Category:    policy.CategoryVuln,
				Severity:    policy.SeverityCritical,
				Resource:    policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Message:     "Deployment/api container \"api\" image \"ghcr.io/acme/api:1.0.0\" contains vulnerable package openssl 1.1.1-r0 (CVE-2026-0001)",
				Remediation: "Upgrade openssl.",
				Timestamp:   now,
				Evidence: map[string]any{
					"container":      "api",
					"image":          "ghcr.io/acme/api:1.0.0",
					"packageName":    "openssl",
					"packageVersion": "1.1.1-r0",
					"ecosystem":      "apk",
					"aliases":        []string{"GHSA-demo-0001"},
					"fixedVersion":   "1.1.1-r1",
				},
			},
		},
		Compliance: &policy.ComplianceReport{
			Profile:        "k8s-cis",
			Title:          "Kubernetes CIS Aligned Checks",
			PassedControls: 0,
			FailedControls: 1,
			Controls: []policy.ComplianceControlResult{
				{
					ID:              "CIS-5.7.3",
					Title:           "Apply namespace network policy",
					Status:          policy.ComplianceStatusFail,
					RuleIDs:         []string{"KS030", "KS031"},
					FailingFindings: 2,
				},
			},
		},
	}

	events := BuildEvents(result)
	if len(events) != 3 {
		t.Fatalf("expected 3 OCSF events, got %d", len(events))
	}

	posture := events[0]
	if posture["class_uid"] != 7 {
		t.Fatalf("expected posture class_uid 7, got %#v", posture["class_uid"])
	}
	if posture["category_uid"] != 2 {
		t.Fatalf("expected findings category_uid 2, got %#v", posture["category_uid"])
	}
	if posture["severity_id"] != 4 {
		t.Fatalf("expected high severity_id 4, got %#v", posture["severity_id"])
	}
	if posture["class_name"] != "Application Security Posture Finding" {
		t.Fatalf("unexpected posture class_name %#v", posture["class_name"])
	}

	vuln := events[1]
	if vuln["class_uid"] != 2 {
		t.Fatalf("expected vulnerability class_uid 2, got %#v", vuln["class_uid"])
	}
	vulnerabilities, ok := vuln["vulnerabilities"].([]map[string]any)
	if !ok || len(vulnerabilities) != 1 {
		t.Fatalf("expected one vulnerability object, got %#v", vuln["vulnerabilities"])
	}
	if _, ok := vulnerabilities[0]["cve"]; !ok {
		t.Fatalf("expected CVE mapping in vulnerability object, got %#v", vulnerabilities[0])
	}

	compliance := events[2]
	if compliance["class_uid"] != 3 {
		t.Fatalf("expected compliance class_uid 3, got %#v", compliance["class_uid"])
	}
	complianceObj, ok := compliance["compliance"].(map[string]any)
	if !ok {
		t.Fatalf("expected compliance object, got %#v", compliance["compliance"])
	}
	if complianceObj["status"] != "Fail" {
		t.Fatalf("expected compliance status Fail, got %#v", complianceObj["status"])
	}
}

func TestWriteJSON(t *testing.T) {
	result := report.ScanResult{
		Findings: []policy.Finding{
			{
				ID:          "finding-1",
				RuleID:      "KS011",
				Title:       "Public service exposure",
				Category:    policy.CategoryExposure,
				Severity:    policy.SeverityHigh,
				Resource:    policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
				Message:     "Service/api is publicly exposed through LoadBalancer",
				Remediation: "Use ClusterIP.",
				Timestamp:   time.Unix(1710000000, 0).UTC(),
			},
		},
	}

	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, result); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "\"class_name\": \"Application Security Posture Finding\"") {
		t.Fatalf("expected posture class name in OCSF output, got %s", output)
	}
	if !strings.Contains(output, "\"version\": \"1.8.0\"") {
		t.Fatalf("expected OCSF schema version 1.8.0, got %s", output)
	}
	if !strings.Contains(output, "\"category_name\": \"Findings\"") {
		t.Fatalf("expected findings category in OCSF output, got %s", output)
	}
}
