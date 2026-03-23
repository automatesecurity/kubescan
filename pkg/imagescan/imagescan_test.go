package imagescan

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"kubescan/pkg/policy"
)

func TestEvaluate(t *testing.T) {
	findings := Evaluate(Metadata{
		Reference: "nginx:latest",
		Tag:       "latest",
		Registry:  "docker.io",
		User:      "",
		Env: []string{
			"API_TOKEN=super-secret",
			"LOG_LEVEL=info",
		},
	}, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))

	if got := len(findings); got != 4 {
		t.Fatalf("expected 4 findings, got %d", got)
	}
	assertRulePresent(t, findings, "KI001")
	assertRulePresent(t, findings, "KI002")
	assertRulePresent(t, findings, "KI003")
	assertRulePresent(t, findings, "KI004")
}

func TestEvaluateDigestPinnedImage(t *testing.T) {
	findings := Evaluate(Metadata{
		Reference: "ghcr.io/acme/api@sha256:1234",
		Registry:  "ghcr.io",
		User:      "1000",
	}, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))

	for _, finding := range findings {
		if finding.RuleID == "KI001" {
			t.Fatalf("did not expect mutable tag finding for digest-pinned image")
		}
		if finding.RuleID == "KI003" {
			t.Fatalf("did not expect root-user finding for non-root image")
		}
	}
}

func TestEvaluateFindsKnownSecretPatternsInImageEnv(t *testing.T) {
	findings := Evaluate(Metadata{
		Reference: "ghcr.io/acme/api:1.0.0",
		Tag:       "1.0.0",
		Registry:  "ghcr.io",
		User:      "1000",
		Env: []string{
			"APP_CONFIG=ghp_0123456789abcdef0123456789abcdef0123",
		},
	}, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))

	assertRulePresent(t, findings, "KI004")
}

func TestAuthOptionsAuthenticatorUsesRegistryToken(t *testing.T) {
	authenticator := (AuthOptions{Token: "token-123"}).authenticator()
	if authenticator == nil {
		t.Fatalf("expected authenticator")
	}
	config, err := authn.Authorization(context.Background(), authenticator)
	if err != nil {
		t.Fatalf("Authorization returned error: %v", err)
	}
	if config.RegistryToken != "token-123" {
		t.Fatalf("expected registry token to be forwarded, got %+v", config)
	}
}

func TestAuthOptionsAuthenticatorUsesUsernamePassword(t *testing.T) {
	authenticator := (AuthOptions{Username: "robot$kubescan", Password: "secret-pass"}).authenticator()
	if authenticator == nil {
		t.Fatalf("expected authenticator")
	}
	config, err := authn.Authorization(context.Background(), authenticator)
	if err != nil {
		t.Fatalf("Authorization returned error: %v", err)
	}
	if config.Username != "robot$kubescan" || config.Password != "secret-pass" {
		t.Fatalf("expected username/password to be forwarded, got %+v", config)
	}
}

func assertRulePresent(t *testing.T, findings []policy.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to be present, got %+v", ruleID, findings)
}
