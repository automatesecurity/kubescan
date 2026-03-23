package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/attackpath"
	"kubescan/pkg/policy"
)

func TestBuildScanResult(t *testing.T) {
	result := BuildScanResult([]policy.Finding{
		{
			ID:        "1",
			RuleID:    "KS001",
			Severity:  policy.SeverityCritical,
			Message:   "critical finding",
			Timestamp: time.Now(),
		},
		{
			ID:        "2",
			RuleID:    "KS002",
			Severity:  policy.SeverityMedium,
			Message:   "medium finding",
			Timestamp: time.Now(),
		},
	})

	if result.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 findings, got %d", result.Summary.TotalFindings)
	}
	if result.Summary.TotalBySeverity[policy.SeverityCritical] != 1 {
		t.Fatalf("expected 1 critical finding")
	}
	if len(result.Summary.ByRule) != 2 {
		t.Fatalf("expected rule summary entries, got %d", len(result.Summary.ByRule))
	}
	if result.APIVersion != ScanResultAPIVersion {
		t.Fatalf("expected apiVersion %q, got %q", ScanResultAPIVersion, result.APIVersion)
	}
	if result.Kind != ScanResultKind {
		t.Fatalf("expected kind %q, got %q", ScanResultKind, result.Kind)
	}
	if result.SchemaVersion != ScanResultVersion {
		t.Fatalf("expected schemaVersion %q, got %q", ScanResultVersion, result.SchemaVersion)
	}
}

func TestWriteJSONAndTable(t *testing.T) {
	result := ScanResult{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Summary: Summary{
			TotalFindings:   1,
			TotalBySeverity: map[policy.Severity]int{policy.SeverityHigh: 1},
			ByRule:          []SummaryEntry{{Name: "KS010", Count: 1}},
			ByNamespace:     []SummaryEntry{{Name: "payments", Count: 1}},
			AttackPaths: AttackPathSummary{
				TotalPaths:      1,
				TotalBySeverity: map[policy.Severity]int{policy.SeverityCritical: 1},
				ByID:            []SummaryEntry{{Name: "AP001", Count: 1}},
			},
		},
		Compliance: &policy.ComplianceReport{
			Profile:        "k8s-cis",
			PassedControls: 1,
			FailedControls: 1,
			Controls: []policy.ComplianceControlResult{
				{ID: "CIS-1", Status: policy.ComplianceStatusFail, FailingFindings: 1},
			},
		},
		Findings: []policy.Finding{
			{
				ID:       "finding-1",
				RuleID:   "KS010",
				Severity: policy.SeverityHigh,
				Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Message:  "Deployment/api container \"api\" uses a mutable image tag",
			},
		},
		AttackPaths: []attackpath.Result{
			{
				ID:       "AP001",
				Title:    "Public entry reaches node-compromise preconditions",
				Severity: policy.SeverityCritical,
				Entry:    policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
				Target:   "Node compromise preconditions",
				Path:     "Internet -> Service/payments/api -> Deployment/payments/api -> Node compromise preconditions",
			},
		},
	}

	var jsonBuffer bytes.Buffer
	if err := WriteJSON(&jsonBuffer, result); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	if !strings.Contains(jsonBuffer.String(), "\"ruleId\": \"KS010\"") {
		t.Fatalf("expected JSON output to contain rule ID, got %s", jsonBuffer.String())
	}
	if !strings.Contains(jsonBuffer.String(), "\"apiVersion\": \""+ScanResultAPIVersion+"\"") {
		t.Fatalf("expected JSON output to contain apiVersion, got %s", jsonBuffer.String())
	}
	if !strings.Contains(jsonBuffer.String(), "\"kind\": \""+ScanResultKind+"\"") {
		t.Fatalf("expected JSON output to contain kind, got %s", jsonBuffer.String())
	}
	if !strings.Contains(jsonBuffer.String(), "\"schemaVersion\": \""+ScanResultVersion+"\"") {
		t.Fatalf("expected JSON output to contain schemaVersion, got %s", jsonBuffer.String())
	}
	if !strings.Contains(jsonBuffer.String(), "\"profile\": \"k8s-cis\"") {
		t.Fatalf("expected JSON output to contain compliance profile, got %s", jsonBuffer.String())
	}
	if !strings.Contains(jsonBuffer.String(), "\"attackPaths\"") {
		t.Fatalf("expected JSON output to contain attack paths, got %s", jsonBuffer.String())
	}

	var tableBuffer bytes.Buffer
	if err := WriteTable(&tableBuffer, result); err != nil {
		t.Fatalf("WriteTable returned error: %v", err)
	}
	if !strings.Contains(tableBuffer.String(), "payments/Deployment/api") {
		t.Fatalf("expected table output to contain resource path, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "CIS-1") {
		t.Fatalf("expected table output to contain compliance section, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "Kubescan Scan Report") {
		t.Fatalf("expected report title, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "Kubescan (c) 2026 Daniel Wood https://www.github.com/automatesecurity/kubescan") {
		t.Fatalf("expected full branding line, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "_  ___   _ ____  _____ ____   ____") {
		t.Fatalf("expected ASCII header, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "OVERVIEW") {
		t.Fatalf("expected overview section, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "Top Rules") {
		t.Fatalf("expected top rules section, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "SEV") {
		t.Fatalf("expected compact severity column, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "CONTROL") {
		t.Fatalf("expected compliance controls table, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "status") {
		t.Fatalf("expected compliance status line, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "HIGH") {
		t.Fatalf("expected compact severity label, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "Attack Paths") {
		t.Fatalf("expected attack paths section, got %s", tableBuffer.String())
	}
	if !strings.Contains(tableBuffer.String(), "AP001") {
		t.Fatalf("expected attack path ID, got %s", tableBuffer.String())
	}
}

func TestWriteSARIF(t *testing.T) {
	result := ScanResult{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Summary: Summary{
			TotalFindings:   1,
			TotalBySeverity: map[policy.Severity]int{policy.SeverityHigh: 1},
		},
		Findings: []policy.Finding{
			{
				ID:               "finding-1",
				RuleID:           "KS010",
				Title:            "Mutable image tag",
				Severity:         policy.SeverityHigh,
				OriginalSeverity: policy.SeverityMedium,
				Category:         policy.CategorySupplyChain,
				Resource:         policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Message:          "Deployment/api container \"api\" uses a mutable image tag",
				Remediation:      "Pin by digest.",
			},
		},
	}

	var sarifBuffer bytes.Buffer
	if err := WriteSARIF(&sarifBuffer, result); err != nil {
		t.Fatalf("WriteSARIF returned error: %v", err)
	}

	output := sarifBuffer.String()
	if !strings.Contains(output, "\"version\": \"2.1.0\"") {
		t.Fatalf("expected SARIF version, got %s", output)
	}
	if !strings.Contains(output, "\"ruleId\": \"KS010\"") {
		t.Fatalf("expected SARIF rule ID, got %s", output)
	}
	if !strings.Contains(output, "\"level\": \"error\"") {
		t.Fatalf("expected SARIF level error, got %s", output)
	}
	if !strings.Contains(output, "\"uri\": \"k8s://payments/Deployment/api\"") {
		t.Fatalf("expected SARIF resource URI, got %s", output)
	}
}

func TestWriteSummaryTable(t *testing.T) {
	result := BuildScanResult([]policy.Finding{
		{
			ID:       "finding-1",
			RuleID:   "KS010",
			Severity: policy.SeverityHigh,
			Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
			Message:  "message",
		},
	})

	var buffer bytes.Buffer
	if err := WriteSummaryTable(&buffer, result); err != nil {
		t.Fatalf("WriteSummaryTable returned error: %v", err)
	}
	if !strings.Contains(buffer.String(), "KS010") {
		t.Fatalf("expected rule summary, got %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "Kubescan Scan Summary") {
		t.Fatalf("expected summary title, got %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "Kubescan (c) 2026 Daniel Wood https://www.github.com/automatesecurity/kubescan") {
		t.Fatalf("expected full branding line, got %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "Namespaces") {
		t.Fatalf("expected namespaces section, got %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "severity mix") {
		t.Fatalf("expected severity mix line, got %s", buffer.String())
	}
}

func TestWriteHTML(t *testing.T) {
	result := ScanResult{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Summary: Summary{
			TotalFindings:   1,
			TotalBySeverity: map[policy.Severity]int{policy.SeverityHigh: 1},
			ByRule:          []SummaryEntry{{Name: "KS010", Count: 1}},
			ByNamespace:     []SummaryEntry{{Name: "payments", Count: 1}},
			ByCategory:      []SummaryEntry{{Name: "supply-chain", Count: 1}},
			AttackPaths: AttackPathSummary{
				TotalPaths:      1,
				TotalBySeverity: map[policy.Severity]int{policy.SeverityCritical: 1},
				ByID:            []SummaryEntry{{Name: "AP001", Count: 1}},
			},
		},
		Compliance: &policy.ComplianceReport{
			Profile:        "k8s-cis",
			PassedControls: 3,
			FailedControls: 1,
			Controls: []policy.ComplianceControlResult{
				{ID: "CIS-1", Status: policy.ComplianceStatusFail, FailingFindings: 1},
			},
		},
		Findings: []policy.Finding{
			{
				ID:          "finding-1",
				RuleID:      "KS010",
				Title:       "Mutable image tag",
				Severity:    policy.SeverityHigh,
				Category:    policy.CategorySupplyChain,
				RuleVersion: "v1",
				Resource:    policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Message:     "Deployment/api container \"api\" uses a mutable image tag",
				Remediation: "Pin the image by digest.",
				Evidence:    map[string]any{"container": "api"},
				Timestamp:   time.Unix(0, 0).UTC(),
			},
		},
		AttackPaths: []attackpath.Result{
			{
				ID:              "AP001",
				Title:           "Public entry reaches node-compromise preconditions",
				Severity:        policy.SeverityCritical,
				Summary:         "An exposed service reaches a risky workload.",
				Entry:           policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
				Target:          "Node compromise preconditions",
				Path:            "Internet -> Service/payments/api -> Deployment/payments/api -> Node compromise preconditions",
				SupportingRules: []string{"KS001", "KS024"},
				Remediation:     "Reduce exposure and remove risky workload settings.",
				Steps: []attackpath.Step{
					{Label: "Internet"},
					{Label: "Service/payments/api", Relationship: "CAN_REACH"},
				},
			},
		},
	}

	var buffer bytes.Buffer
	if err := WriteHTML(&buffer, result); err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	output := buffer.String()
	for _, expected := range []string{
		"<html",
		"Kubescan HTML Report",
		"Mutable image tag",
		"Public entry reaches node-compromise preconditions",
		"Raw Result",
		"finding-search",
		"attack-search",
		`href="https://www.github.com/automatesecurity/kubescan"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected HTML output to contain %q, got %s", expected, output)
		}
	}
	if !strings.Contains(output, "&#34;ruleId&#34;: &#34;KS010&#34;") {
		t.Fatalf("expected embedded raw JSON in HTML output, got %s", output)
	}
}

func TestBuildScanResultWithAttackPaths(t *testing.T) {
	result := BuildScanResultWithAttackPaths([]policy.Finding{}, []attackpath.Result{
		{
			ID:       "AP002",
			Severity: policy.SeverityCritical,
			Entry:    policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
			Target:   "Wildcard RBAC",
		},
	})

	if result.Summary.AttackPaths.TotalPaths != 1 {
		t.Fatalf("expected 1 attack path, got %d", result.Summary.AttackPaths.TotalPaths)
	}
	if result.Summary.AttackPaths.TotalBySeverity[policy.SeverityCritical] != 1 {
		t.Fatalf("expected 1 critical attack path")
	}
	if len(result.AttackPaths) != 1 {
		t.Fatalf("expected attack paths in result, got %d", len(result.AttackPaths))
	}
}

func TestWriteTableWithColor(t *testing.T) {
	result := ScanResult{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Summary: Summary{
			TotalFindings:   1,
			TotalBySeverity: map[policy.Severity]int{policy.SeverityCritical: 1},
			ByRule:          []SummaryEntry{{Name: "KS001", Count: 1}},
			ByNamespace:     []SummaryEntry{{Name: "payments", Count: 1}},
		},
		Findings: []policy.Finding{
			{
				ID:       "finding-1",
				RuleID:   "KS001",
				Severity: policy.SeverityCritical,
				Category: policy.CategoryMisconfig,
				Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Message:  "critical finding",
			},
		},
	}

	var buffer bytes.Buffer
	if err := WriteTableWithOptions(&buffer, result, TableOptions{Color: true}); err != nil {
		t.Fatalf("WriteTableWithOptions returned error: %v", err)
	}
	if !strings.Contains(buffer.String(), "\x1b[") {
		t.Fatalf("expected ANSI color sequences, got %q", buffer.String())
	}
}
