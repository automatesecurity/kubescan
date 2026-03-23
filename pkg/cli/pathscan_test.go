package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/filescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/reposcan"
)

func TestRunFSRequiresPath(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("fs", "", nil, &stdout, &stderr, pathScanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--path is required") {
		t.Fatalf("expected path requirement error, got %s", stderr.String())
	}
}

func TestRunFSOutputsFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("fs", "", []string{"--path", "./examples/fs-demo", "--format", "json"}, &stdout, &stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			if path != "./examples/fs-demo" {
				t.Fatalf("unexpected scan path %q", path)
			}
			if profile != policy.RuleProfileDefault {
				t.Fatalf("unexpected profile %s", profile)
			}
			if len(options.LicensePolicy.Allowlist) != 0 || len(options.LicensePolicy.Denylist) != 0 {
				t.Fatalf("did not expect license policy, got %+v", options.LicensePolicy)
			}
			if len(options.ExcludePaths) != 0 {
				t.Fatalf("did not expect exclude paths, got %+v", options.ExcludePaths)
			}
			if options.SecretScanMode != "balanced" {
				t.Fatalf("expected balanced secret scan mode, got %q", options.SecretScanMode)
			}
			return []policy.Finding{
				{
					ID:        "f1",
					RuleID:    "KF001",
					Severity:  policy.SeverityHigh,
					Category:  policy.CategoryExposure,
					Resource:  policy.ResourceRef{Kind: "File", Name: ".env"},
					Message:   "File/.env defines a plaintext credential-like value for API_TOKEN",
					Timestamp: now,
				},
			}, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 3 {
		t.Fatalf("expected exit code 3, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"ruleId\": \"KF001\"") {
		t.Fatalf("expected KF001 in output, got %s", stdout.String())
	}
}

func TestRunRepoDefaultsToCurrentDirectory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	exitCode := runPathScan("repo", ".", []string{"--format", "json"}, &stdout, &stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			called = true
			if path != "." {
				t.Fatalf("expected default repo path '.', got %q", path)
			}
			return nil, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !called {
		t.Fatalf("expected scanPath to be called")
	}
}

func TestRunRepoClonesRemoteURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	cleanupCalled := false

	exitCode := runPathScan("repo", ".", []string{
		"--url", "https://example.com/demo.git",
		"--ref", "main",
		"--format", "json",
	}, &stdout, &stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			called = true
			if path != "./tmp/clone" {
				t.Fatalf("expected cloned path, got %q", path)
			}
			return nil, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
		cloneRepo: func(url string, options reposcan.CloneOptions) (string, func(), error) {
			if url != "https://example.com/demo.git" {
				t.Fatalf("unexpected url %q", url)
			}
			if options.Ref != "main" {
				t.Fatalf("unexpected ref %q", options.Ref)
			}
			return "./tmp/clone", func() { cleanupCalled = true }, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
	if !called {
		t.Fatalf("expected scanPath to be called")
	}
	if !cleanupCalled {
		t.Fatalf("expected clone cleanup to be called")
	}
}

func TestRunRepoRejectsRefWithoutURL(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("repo", ".", []string{"--ref", "main"}, &stdout, &stderr, pathScanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--ref requires --url") {
		t.Fatalf("expected ref/url validation error, got %s", stderr.String())
	}
}

func TestRunRepoForwardsGitAuthOptions(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("repo", ".", []string{
		"--url", "git@github.com:owner/private.git",
		"--git-http-header", "Authorization: Bearer token-1",
		"--git-http-header", "X-Test: value",
		"--git-ssh-command", "ssh -i /tmp/id_ed25519 -o IdentitiesOnly=yes",
		"--format", "json",
	}, &stdout, &stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			if path != "./tmp/private-clone" {
				t.Fatalf("unexpected scan path %q", path)
			}
			return nil, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
		cloneRepo: func(url string, options reposcan.CloneOptions) (string, func(), error) {
			if url != "git@github.com:owner/private.git" {
				t.Fatalf("unexpected url %q", url)
			}
			if len(options.HTTPHeaders) != 2 || options.HTTPHeaders[0] != "Authorization: Bearer token-1" || options.HTTPHeaders[1] != "X-Test: value" {
				t.Fatalf("unexpected headers %+v", options.HTTPHeaders)
			}
			if options.SSHCommand != "ssh -i /tmp/id_ed25519 -o IdentitiesOnly=yes" {
				t.Fatalf("unexpected ssh command %q", options.SSHCommand)
			}
			if options.ProviderNative {
				t.Fatalf("did not expect provider-native option")
			}
			return "./tmp/private-clone", func() {}, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunRepoRejectsGitHTTPHeaderWithoutURL(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("repo", ".", []string{"--git-http-header", "Authorization: Bearer test"}, &stdout, &stderr, pathScanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--git-http-header requires --url") {
		t.Fatalf("expected git-http-header validation error, got %s", stderr.String())
	}
}

func TestRunRepoForwardsProviderNativeAndSparsePaths(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("repo", ".", []string{
		"--url", "https://github.com/owner/repo.git",
		"--provider-native",
		"--sparse-path", "cmd/kubescan",
		"--sparse-path", "*.md",
		"--format", "json",
	}, &stdout, &stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			if path != "./tmp/provider-clone" {
				t.Fatalf("unexpected scan path %q", path)
			}
			return nil, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
		cloneRepo: func(url string, options reposcan.CloneOptions) (string, func(), error) {
			if !options.ProviderNative {
				t.Fatalf("expected provider-native option")
			}
			if len(options.SparsePaths) != 2 || options.SparsePaths[0] != "cmd/kubescan" || options.SparsePaths[1] != "*.md" {
				t.Fatalf("unexpected sparse paths %+v", options.SparsePaths)
			}
			return "./tmp/provider-clone", func() {}, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunRepoRejectsSparsePathWithoutURL(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("repo", ".", []string{"--sparse-path", "cmd/**"}, &stdout, &stderr, pathScanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--sparse-path requires --url") {
		t.Fatalf("expected sparse-path/url validation error, got %s", stderr.String())
	}
}

func TestRunFSPassesLicensePolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("fs", "", []string{
		"--path", "./examples/license-demo",
		"--format", "json",
		"--license-allow", "MIT",
		"--license-deny", "GPL-3.0-only",
		"--exclude-path", ".plans/**",
		"--exclude-path", "docs/",
		"--secret-scan", "patterns",
	}, &stdout, &stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			if got := options.LicensePolicy.Allowlist; len(got) != 1 || got[0] != "MIT" {
				t.Fatalf("unexpected allowlist %+v", got)
			}
			if got := options.LicensePolicy.Denylist; len(got) != 1 || got[0] != "GPL-3.0-only" {
				t.Fatalf("unexpected denylist %+v", got)
			}
			if got := options.ExcludePaths; len(got) != 2 || got[0] != ".plans/**" || got[1] != "docs/" {
				t.Fatalf("unexpected exclude paths %+v", got)
			}
			if options.SecretScanMode != "patterns" {
				t.Fatalf("unexpected secret scan mode %q", options.SecretScanMode)
			}
			return nil, nil
		},
		openOutput: func(string) (io.WriteCloser, error) {
			t.Fatalf("openOutput should not be called")
			return nil, nil
		},
	})
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%s", exitCode, stderr.String())
	}
}

func TestRunFSRejectsInvalidSecretScanMode(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := runPathScan("fs", "", []string{"--path", "./examples/fs-demo", "--secret-scan", "invalid"}, &stdout, &stderr, pathScanDeps{})
	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "parse secret scan mode") {
		t.Fatalf("expected secret mode parse error, got %s", stderr.String())
	}
}
