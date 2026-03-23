package licensescan

import (
	"testing"
	"time"
)

func TestEvaluateFileFindsDeniedPackageJSONLicense(t *testing.T) {
	findings := EvaluateFile("package.json", []byte(`{"name":"demo","license":"GPL-3.0-only"}`), Policy{
		Denylist: []string{"GPL-3.0-only"},
	}, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].RuleID != "KL001" {
		t.Fatalf("expected KL001, got %+v", findings[0])
	}
}

func TestEvaluateFileFindsUnapprovedLicense(t *testing.T) {
	findings := EvaluateFile("Cargo.toml", []byte("license = \"GPL-3.0-only\"\n"), Policy{
		Allowlist: []string{"MIT", "APACHE-2.0"},
	}, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].RuleID != "KL002" {
		t.Fatalf("expected KL002, got %+v", findings[0])
	}
}

func TestDetectDeclarationsParsesSPDXExpression(t *testing.T) {
	declarations := DetectDeclarations("package.json", []byte(`{"name":"demo","license":"MIT OR Apache-2.0"}`))
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	if got := declarations[0].Identifiers; len(got) != 2 || got[0] != "APACHE-2.0" || got[1] != "MIT" {
		t.Fatalf("unexpected identifiers %+v", got)
	}
}
