package secretscan

import "testing"

func TestScanTextFindsKnownTokenPatterns(t *testing.T) {
	matches := ScanText("github_token=ghp_0123456789abcdef0123456789abcdef0123\n")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", matches)
	}
	if matches[0].Detector != "github-token" {
		t.Fatalf("expected github-token detector, got %+v", matches[0])
	}
	if matches[0].Line != 1 {
		t.Fatalf("expected line 1, got %+v", matches[0])
	}
}

func TestScanTextFindsPrivateKeyBlocks(t *testing.T) {
	matches := ScanText("before\n-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", matches)
	}
	if matches[0].Detector != "private-key" {
		t.Fatalf("expected private-key detector, got %+v", matches[0])
	}
	if matches[0].Line != 2 {
		t.Fatalf("expected line 2, got %+v", matches[0])
	}
}

func TestDetectNamedValueFindsGenericSecret(t *testing.T) {
	match := DetectNamedValue("API_TOKEN", "super-secret")
	if match == nil {
		t.Fatalf("expected match")
	}
	if match.Detector != "plaintext-credential" {
		t.Fatalf("expected plaintext-credential, got %+v", match)
	}
}

func TestDetectNamedValueIgnoresTemplatedAndPlaceholderValues(t *testing.T) {
	for _, candidate := range []string{"${TOKEN}", "{{ .Values.token }}", "placeholder"} {
		if match := DetectNamedValue("API_TOKEN", candidate); match != nil {
			t.Fatalf("expected no match for %q, got %+v", candidate, match)
		}
	}
}

func TestDetectNamedValueIgnoresBenignTokenMetrics(t *testing.T) {
	for _, name := range []string{"completion_tokens", "prompt_tokens", "total_tokens", "tokenizer_name"} {
		if match := DetectNamedValue(name, "123456789012"); match != nil {
			t.Fatalf("expected no match for %s, got %+v", name, match)
		}
	}
}

func TestDetectNamedValueIgnoresSafeScalarValues(t *testing.T) {
	if match := DetectNamedValue("id-token", "write"); match != nil {
		t.Fatalf("expected no match for id-token permission, got %+v", match)
	}
	if match := DetectNamedValue("api_key", "str"); match != nil {
		t.Fatalf("expected no match for type annotation, got %+v", match)
	}
}
