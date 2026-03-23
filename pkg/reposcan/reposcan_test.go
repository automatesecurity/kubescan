package reposcan

import "testing"

func TestValidateRemoteURL(t *testing.T) {
	valid := []string{
		"https://github.com/owner/repo.git",
		"http://example.com/repo.git",
		"ssh://git@example.com/owner/repo.git",
		"git@example.com:owner/repo.git",
	}
	for _, raw := range valid {
		if err := validateRemoteURL(raw); err != nil {
			t.Fatalf("expected %q to be valid, got %v", raw, err)
		}
	}

	invalid := []string{
		"",
		"../repo",
		"C:\\repo",
		"/tmp/repo",
		"file:///tmp/repo.git",
		"ext::sh -c touch /tmp/pwned",
	}
	for _, raw := range invalid {
		if err := validateRemoteURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestGitCommandSetsSafeDefaults(t *testing.T) {
	cmd := gitCommand(CloneOptions{}, "clone", "https://github.com/owner/repo.git", "out")
	foundPrompt := false
	foundGCM := false
	for _, env := range cmd.Env {
		if env == "GIT_TERMINAL_PROMPT=0" {
			foundPrompt = true
		}
		if env == "GCM_INTERACTIVE=never" {
			foundGCM = true
		}
	}
	if !foundPrompt {
		t.Fatalf("expected GIT_TERMINAL_PROMPT=0, got %v", cmd.Env)
	}
	if !foundGCM {
		t.Fatalf("expected GCM_INTERACTIVE=never, got %v", cmd.Env)
	}
	wantPrefix := []string{"git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "clone"}
	got := cmd.Args
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("expected args prefix %v, got %v", wantPrefix, got)
		}
	}
}

func TestGitCommandIncludesAuthOptions(t *testing.T) {
	cmd := gitCommand(CloneOptions{
		HTTPHeaders: []string{"Authorization: Bearer token-1", "X-Test: value"},
		SSHCommand:  "ssh -i /tmp/id_ed25519 -o IdentitiesOnly=yes",
	}, "clone", "git@github.com:owner/private.git", "out")

	if len(cmd.Args) < 10 {
		t.Fatalf("unexpected args %v", cmd.Args)
	}
	if cmd.Args[1] != "-c" || cmd.Args[2] != "http.extraHeader=Authorization: Bearer token-1" {
		t.Fatalf("expected first extra header config, got %v", cmd.Args)
	}
	if cmd.Args[3] != "-c" || cmd.Args[4] != "http.extraHeader=X-Test: value" {
		t.Fatalf("expected second extra header config, got %v", cmd.Args)
	}

	foundSSH := false
	for _, env := range cmd.Env {
		if env == "GIT_SSH_COMMAND=ssh -i /tmp/id_ed25519 -o IdentitiesOnly=yes" {
			foundSSH = true
			break
		}
	}
	if !foundSSH {
		t.Fatalf("expected GIT_SSH_COMMAND in env, got %v", cmd.Env)
	}
}

func TestParseGitHubRepoURL(t *testing.T) {
	owner, repo, err := parseGitHubRepoURL("https://github.com/automatesecurity/kubescan.git")
	if err != nil {
		t.Fatalf("parseGitHubRepoURL returned error: %v", err)
	}
	if owner != "automatesecurity" || repo != "kubescan" {
		t.Fatalf("unexpected owner/repo %q/%q", owner, repo)
	}
	if _, _, err := parseGitHubRepoURL("ssh://github.com/automatesecurity/kubescan.git"); err == nil {
		t.Fatalf("expected non-https GitHub URL to be rejected")
	}
}

func TestShouldIncludeSparsePath(t *testing.T) {
	if !shouldIncludeSparsePath("cmd/kubescan/main.go", []string{"cmd/kubescan"}) {
		t.Fatalf("expected directory sparse path match")
	}
	if !shouldIncludeSparsePath("README.md", []string{"*.md"}) {
		t.Fatalf("expected glob sparse path match")
	}
	if shouldIncludeSparsePath("pkg/report/report.go", []string{"cmd/**"}) {
		t.Fatalf("did not expect unrelated sparse path match")
	}
}
