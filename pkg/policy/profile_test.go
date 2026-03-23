package policy

import "testing"

func TestParseRuleProfile(t *testing.T) {
	profile, err := ParseRuleProfile("hardening")
	if err != nil {
		t.Fatalf("ParseRuleProfile returned error: %v", err)
	}
	if profile != RuleProfileHardening {
		t.Fatalf("expected hardening profile, got %q", profile)
	}
}

func TestParseRuleProfileRejectsUnknownProfile(t *testing.T) {
	if _, err := ParseRuleProfile("strict"); err == nil {
		t.Fatalf("expected unknown rule profile to fail")
	}
}
