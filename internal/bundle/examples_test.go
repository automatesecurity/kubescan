package bundle

import (
	"path/filepath"
	"testing"
)

func TestExampleBundlesLoad(t *testing.T) {
	examples := filepath.Join("..", "..", "examples")
	key := filepath.Join(examples, "bundle.pub.pem")

	if _, err := LoadSignedPolicyControls(filepath.Join(examples, "policy.bundle.yaml"), key); err != nil {
		t.Fatalf("LoadSignedPolicyControls returned error: %v", err)
	}
	ruleBundle, err := LoadSignedRuleBundle(filepath.Join(examples, "rules.bundle.yaml"), key)
	if err != nil {
		t.Fatalf("LoadSignedRuleBundle returned error: %v", err)
	}
	if got := len(ruleBundle.CustomRules); got != 1 {
		t.Fatalf("expected 1 custom rule, got %d", got)
	}
	advisories, err := LoadSignedAdvisories(filepath.Join(examples, "advisories.bundle.yaml"), key)
	if err != nil {
		t.Fatalf("LoadSignedAdvisories returned error: %v", err)
	}
	if got := len(advisories.Advisories); got != 2 {
		t.Fatalf("expected 2 advisories, got %d", got)
	}
}
