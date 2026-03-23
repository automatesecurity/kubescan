package policy

import "testing"

func TestParseComplianceProfile(t *testing.T) {
	profile, err := ParseComplianceProfile("k8s-cis")
	if err != nil {
		t.Fatalf("ParseComplianceProfile returned error: %v", err)
	}
	if profile.Name != "k8s-cis" {
		t.Fatalf("expected k8s-cis profile, got %q", profile.Name)
	}
}

func TestEvaluateCompliance(t *testing.T) {
	profile, err := ParseComplianceProfile("pss-restricted")
	if err != nil {
		t.Fatalf("ParseComplianceProfile returned error: %v", err)
	}

	report := EvaluateCompliance(profile, []Finding{
		{RuleID: "KS001"},
		{RuleID: "KS003"},
	})

	if report.FailedControls != 2 {
		t.Fatalf("expected 2 failed controls, got %d", report.FailedControls)
	}
	if report.PassedControls != 3 {
		t.Fatalf("expected 3 passed controls, got %d", report.PassedControls)
	}
	if report.Controls[0].Status != ComplianceStatusFail {
		t.Fatalf("expected first control to fail, got %s", report.Controls[0].Status)
	}
}
