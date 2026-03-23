package reposcan

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var scpLikeURL = regexp.MustCompile(`^[^@/\s]+@[^:/\s]+:.+$`)

type CloneOptions struct {
	Ref            string
	HTTPHeaders    []string
	SSHCommand     string
	SparsePaths    []string
	ProviderNative bool
}

func CloneShallow(url string, options CloneOptions) (string, func(), error) {
	if err := validateRemoteURL(url); err != nil {
		return "", nil, err
	}
	if options.ProviderNative {
		return cloneProviderNative(url, options)
	}
	dir, err := os.MkdirTemp("", "kubescan-repo-")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}

	cloneArgs := []string{"clone", "--depth", "1", "--no-tags"}
	if len(options.SparsePaths) > 0 {
		cloneArgs = append(cloneArgs, "--filter=blob:none", "--sparse")
	}
	cloneArgs = append(cloneArgs, url, dir)
	clone := gitCommand(options, cloneArgs...)
	if output, err := clone.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone: %w: %s", err, strings.TrimSpace(string(output)))
	}

	if len(options.SparsePaths) > 0 {
		if err := configureSparseCheckout(dir, options); err != nil {
			cleanup()
			return "", nil, err
		}
	}

	if strings.TrimSpace(options.Ref) != "" {
		fetch := gitCommand(options, "-C", dir, "fetch", "--depth", "1", "origin", options.Ref)
		if output, err := fetch.CombinedOutput(); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("git fetch %s: %w: %s", options.Ref, err, strings.TrimSpace(string(output)))
		}
		checkout := gitCommand(options, "-C", dir, "checkout", "--detach", "FETCH_HEAD")
		if output, err := checkout.CombinedOutput(); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("git checkout %s: %w: %s", options.Ref, err, strings.TrimSpace(string(output)))
		}
	}

	return dir, cleanup, nil
}

func configureSparseCheckout(dir string, options CloneOptions) error {
	args := []string{"-C", dir, "sparse-checkout", "set", "--no-cone"}
	args = append(args, options.SparsePaths...)
	set := gitCommand(options, args...)
	if output, err := set.CombinedOutput(); err != nil {
		return fmt.Errorf("git sparse-checkout set: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func cloneProviderNative(rawURL string, options CloneOptions) (string, func(), error) {
	owner, repo, err := parseGitHubRepoURL(rawURL)
	if err != nil {
		return "", nil, err
	}
	ref := strings.TrimSpace(options.Ref)
	if ref == "" {
		ref, err = fetchGitHubDefaultBranch(owner, repo, options.HTTPHeaders)
		if err != nil {
			return "", nil, err
		}
	}

	dir, err := os.MkdirTemp("", "kubescan-repo-")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}

	if err := extractGitHubArchive(owner, repo, ref, options, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

func parseGitHubRepoURL(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse repository URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") || !strings.EqualFold(parsed.Host, "github.com") {
		return "", "", fmt.Errorf("provider-native repository retrieval currently supports https://github.com/<owner>/<repo>[.git] URLs only")
	}
	trimmed := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("repository URL must include owner and repo")
	}
	owner := strings.TrimSpace(parts[0])
	repo := strings.TrimSuffix(strings.TrimSpace(parts[1]), ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("repository URL must include owner and repo")
	}
	return owner, repo, nil
}

func fetchGitHubDefaultBranch(owner, repo string, headers []string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		return "", fmt.Errorf("build GitHub repository request: %w", err)
	}
	applyHTTPHeaders(req, headers)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kubescan")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch GitHub repository metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("fetch GitHub repository metadata: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode GitHub repository metadata: %w", err)
	}
	if strings.TrimSpace(payload.DefaultBranch) == "" {
		return "", fmt.Errorf("GitHub repository metadata did not include default_branch")
	}
	return strings.TrimSpace(payload.DefaultBranch), nil
}

func extractGitHubArchive(owner, repo, ref string, options CloneOptions, dir string) error {
	archiveURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball/%s", owner, repo, url.PathEscape(ref))
	req, err := http.NewRequest(http.MethodGet, archiveURL, nil)
	if err != nil {
		return fmt.Errorf("build GitHub archive request: %w", err)
	}
	applyHTTPHeaders(req, options.HTTPHeaders)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kubescan")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch GitHub archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("fetch GitHub archive: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("open GitHub archive: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read GitHub archive: %w", err)
		}
		rel := archiveRelativePath(header.Name)
		if rel == "" || !shouldIncludeSparsePath(rel, options.SparsePaths) {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("create archive directory %s: %w", rel, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("create archive parent %s: %w", rel, err)
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("create archive file %s: %w", rel, err)
			}
			if _, err := io.Copy(file, tr); err != nil {
				_ = file.Close()
				return fmt.Errorf("extract archive file %s: %w", rel, err)
			}
			if err := file.Close(); err != nil {
				return fmt.Errorf("close archive file %s: %w", rel, err)
			}
		}
	}
	return nil
}

func archiveRelativePath(value string) string {
	cleaned := path.Clean(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")))
	if cleaned == "." || cleaned == "" {
		return ""
	}
	parts := strings.Split(cleaned, "/")
	if len(parts) <= 1 {
		return ""
	}
	rel := path.Clean(strings.Join(parts[1:], "/"))
	if rel == "." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return ""
	}
	return rel
}

func shouldIncludeSparsePath(rel string, sparsePaths []string) bool {
	if len(sparsePaths) == 0 {
		return true
	}
	normalized := path.Clean(strings.ReplaceAll(strings.TrimSpace(rel), "\\", "/"))
	for _, raw := range sparsePaths {
		pattern := path.Clean(strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/"))
		if pattern == "." || pattern == "" {
			continue
		}
		if normalized == pattern || strings.HasPrefix(normalized, strings.TrimSuffix(pattern, "/")+"/") {
			return true
		}
		if ok, _ := path.Match(pattern, normalized); ok {
			return true
		}
	}
	return false
}

func applyHTTPHeaders(req *http.Request, headers []string) {
	for _, header := range headers {
		parts := strings.SplitN(strings.TrimSpace(header), ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" || value == "" {
			continue
		}
		req.Header.Add(name, value)
	}
}

func validateRemoteURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("repository URL is required")
	}
	if scpLikeURL.MatchString(trimmed) {
		return nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("parse repository URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "ssh":
		return nil
	case "http":
		if parsed.Host == "" {
			return fmt.Errorf("repository URL must include a host")
		}
		return nil
	case "":
		return fmt.Errorf("repository URL must use https://, ssh://, or scp-style syntax")
	default:
		return fmt.Errorf("repository URL scheme %q is not allowed", parsed.Scheme)
	}
}

func gitCommand(options CloneOptions, args ...string) *exec.Cmd {
	prefix := []string{}
	for _, header := range options.HTTPHeaders {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		prefix = append(prefix, "-c", "http.extraHeader="+header)
	}
	fullArgs := append(prefix, []string{
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
	}...)
	fullArgs = append(fullArgs, args...)
	cmd := exec.Command("git", fullArgs...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never")
	if strings.TrimSpace(options.SSHCommand) != "" {
		cmd.Env = append(cmd.Env, "GIT_SSH_COMMAND="+strings.TrimSpace(options.SSHCommand))
	}
	return cmd
}
