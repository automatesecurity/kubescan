package policy

import "testing"

func TestParseSeverity(t *testing.T) {
	severity, err := ParseSeverity("HIGH")
	if err != nil {
		t.Fatalf("ParseSeverity returned error: %v", err)
	}
	if severity != SeverityHigh {
		t.Fatalf("expected high, got %s", severity)
	}
}

func TestMeetsOrExceedsSeverity(t *testing.T) {
	if !MeetsOrExceedsSeverity(SeverityCritical, SeverityHigh) {
		t.Fatalf("expected critical to exceed high")
	}
	if MeetsOrExceedsSeverity(SeverityMedium, SeverityHigh) {
		t.Fatalf("expected medium not to exceed high")
	}
}
