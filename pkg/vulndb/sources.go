package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"kubescan/internal/bundle"
	"kubescan/pkg/vuln"

	"sigs.k8s.io/yaml"
)

const (
	SourceManifestAPIVersion = "kubescan.automatesecurity.github.io/v1alpha1"
	SourceManifestKind       = "VulnDBSources"
)

type SourceManifest struct {
	APIVersion string       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string       `json:"kind" yaml:"kind"`
	Sources    []SourceSpec `json:"sources" yaml:"sources"`
}

type SourceSpec struct {
	Name          string `json:"name" yaml:"name"`
	Kind          string `json:"kind" yaml:"kind"`
	Path          string `json:"path,omitempty" yaml:"path,omitempty"`
	URL           string `json:"url,omitempty" yaml:"url,omitempty"`
	Release       string `json:"release,omitempty" yaml:"release,omitempty"`
	Asset         string `json:"asset,omitempty" yaml:"asset,omitempty"`
	Format        string `json:"format,omitempty" yaml:"format,omitempty"`
	PublicKeyPath string `json:"publicKeyPath,omitempty" yaml:"publicKeyPath,omitempty"`
	Priority      int    `json:"priority,omitempty" yaml:"priority,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

type SourceResolver struct {
	LoadAdvisories     func(string) (vuln.AdvisoryBundle, error)
	LoadAdvisoryBundle func(string, string) (vuln.AdvisoryBundle, error)
	LoadOSVSource      func(string) (vuln.AdvisoryBundle, error)
	LoadAlpineSecDB    func(string) (vuln.AdvisoryBundle, error)
	LoadDebianTracker  func(string, string) (vuln.AdvisoryBundle, error)
	LoadUbuntuNotices  func(string, string) (vuln.AdvisoryBundle, error)
	LoadKubernetesFeed func(string) (vuln.AdvisoryBundle, error)
	FetchGitHubAsset   func(context.Context, string, string) ([]byte, error)
}

func LoadSourceManifest(path string) (SourceManifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return SourceManifest{}, fmt.Errorf("read source manifest: %w", err)
	}
	var manifest SourceManifest
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		return SourceManifest{}, fmt.Errorf("decode source manifest: %w", err)
	}
	if err := validateSourceManifest(manifest); err != nil {
		return SourceManifest{}, err
	}
	return manifest, nil
}

func ResolveSources(ctx context.Context, manifest SourceManifest, resolver SourceResolver) (vuln.AdvisoryBundle, error) {
	if resolver.LoadAdvisories == nil || resolver.LoadAdvisoryBundle == nil || resolver.LoadOSVSource == nil || resolver.LoadAlpineSecDB == nil || resolver.LoadDebianTracker == nil || resolver.LoadUbuntuNotices == nil || resolver.LoadKubernetesFeed == nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("source resolver is not fully configured")
	}
	if resolver.FetchGitHubAsset == nil {
		resolver.FetchGitHubAsset = loadGitHubReleaseAssetBytes
	}

	merged := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	for _, source := range manifest.Sources {
		if source.Enabled != nil && !*source.Enabled {
			continue
		}
		loaded, err := resolveSource(ctx, source, resolver)
		if err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("resolve source %q: %w", source.Name, err)
		}
		for _, advisory := range loaded.Advisories {
			advisory.Source = source.Name
			advisory.SourcePriority = sourcePriority(source)
			merged.Advisories = mergeAdvisory(merged.Advisories, advisory)
		}
	}
	return merged, nil
}

func resolveSource(ctx context.Context, source SourceSpec, resolver SourceResolver) (vuln.AdvisoryBundle, error) {
	switch source.Kind {
	case "AdvisoryBundle":
		return resolver.LoadAdvisories(strings.TrimSpace(source.Path))
	case "SignedAdvisoryBundle":
		return resolver.LoadAdvisoryBundle(strings.TrimSpace(source.Path), strings.TrimSpace(source.PublicKeyPath))
	case "OSV":
		location := strings.TrimSpace(source.Path)
		if location == "" {
			location = strings.TrimSpace(source.URL)
		}
		return resolver.LoadOSVSource(location)
	case "AlpineSecDB":
		location := strings.TrimSpace(source.Path)
		if location == "" {
			location = strings.TrimSpace(source.URL)
		}
		return resolver.LoadAlpineSecDB(location)
	case "DebianSecurityTracker":
		location := strings.TrimSpace(source.Path)
		if location == "" {
			location = strings.TrimSpace(source.URL)
		}
		return resolver.LoadDebianTracker(location, strings.TrimSpace(source.Release))
	case "UbuntuSecurityNotices":
		location := strings.TrimSpace(source.Path)
		if location == "" {
			location = strings.TrimSpace(source.URL)
		}
		return resolver.LoadUbuntuNotices(location, strings.TrimSpace(source.Release))
	case "KubernetesOfficialCVEFeed":
		location := strings.TrimSpace(source.Path)
		if location == "" {
			location = strings.TrimSpace(source.URL)
		}
		return resolver.LoadKubernetesFeed(location)
	case "GitHubReleaseAsset":
		if resolver.FetchGitHubAsset == nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("github release asset fetching is not configured")
		}
		content, err := resolver.FetchGitHubAsset(ctx, strings.TrimSpace(source.URL), strings.TrimSpace(source.Asset))
		if err != nil {
			return vuln.AdvisoryBundle{}, err
		}
		switch strings.ToLower(strings.TrimSpace(source.Format)) {
		case "", "osv":
			return LoadOSVBytes(content)
		case "alpine-secdb":
			return LoadAlpineSecDBBytes(content)
		case "advisory-bundle":
			return vuln.LoadAdvisoriesBytes(content)
		case "signed-advisory-bundle":
			if strings.TrimSpace(source.PublicKeyPath) == "" {
				return vuln.AdvisoryBundle{}, fmt.Errorf("publicKeyPath is required for signed-advisory-bundle github assets")
			}
			publicKey, err := os.ReadFile(source.PublicKeyPath)
			if err != nil {
				return vuln.AdvisoryBundle{}, fmt.Errorf("read public key: %w", err)
			}
			return bundle.LoadSignedAdvisoriesBytes(content, publicKey)
		default:
			return vuln.AdvisoryBundle{}, fmt.Errorf("unsupported github release asset format %q", source.Format)
		}
	default:
		return vuln.AdvisoryBundle{}, fmt.Errorf("unsupported source kind %q", source.Kind)
	}
}

func validateSourceManifest(manifest SourceManifest) error {
	if strings.TrimSpace(manifest.APIVersion) == "" {
		manifest.APIVersion = SourceManifestAPIVersion
	}
	if manifest.APIVersion != SourceManifestAPIVersion {
		return fmt.Errorf("unsupported source manifest apiVersion %q", manifest.APIVersion)
	}
	if strings.TrimSpace(manifest.Kind) == "" {
		manifest.Kind = SourceManifestKind
	}
	if manifest.Kind != SourceManifestKind {
		return fmt.Errorf("source manifest kind must be %s", SourceManifestKind)
	}
	if len(manifest.Sources) == 0 {
		return fmt.Errorf("source manifest requires at least one source")
	}
	for _, source := range manifest.Sources {
		if strings.TrimSpace(source.Name) == "" {
			return fmt.Errorf("source name is required")
		}
		switch source.Kind {
		case "AdvisoryBundle", "SignedAdvisoryBundle":
			if strings.TrimSpace(source.Path) == "" {
				return fmt.Errorf("source %q path is required", source.Name)
			}
		case "OSV", "AlpineSecDB", "KubernetesOfficialCVEFeed":
			if strings.TrimSpace(source.Path) == "" && strings.TrimSpace(source.URL) == "" {
				return fmt.Errorf("source %q requires path or url", source.Name)
			}
		case "DebianSecurityTracker", "UbuntuSecurityNotices":
			if strings.TrimSpace(source.Path) == "" && strings.TrimSpace(source.URL) == "" {
				return fmt.Errorf("source %q requires path or url", source.Name)
			}
			if strings.TrimSpace(source.Release) == "" {
				return fmt.Errorf("source %q requires release", source.Name)
			}
		case "GitHubReleaseAsset":
			if strings.TrimSpace(source.URL) == "" || strings.TrimSpace(source.Asset) == "" {
				return fmt.Errorf("source %q requires url and asset", source.Name)
			}
		default:
			return fmt.Errorf("source %q uses unsupported kind %q", source.Name, source.Kind)
		}
		if source.Kind == "SignedAdvisoryBundle" && strings.TrimSpace(source.PublicKeyPath) == "" {
			return fmt.Errorf("source %q publicKeyPath is required", source.Name)
		}
	}
	return nil
}

func sourcePriority(source SourceSpec) int {
	if source.Priority != 0 {
		return source.Priority
	}
	switch source.Kind {
	case "SignedAdvisoryBundle":
		return 100
	case "AdvisoryBundle":
		return 90
	case "DebianSecurityTracker", "UbuntuSecurityNotices":
		return 85
	case "AlpineSecDB":
		return 80
	case "KubernetesOfficialCVEFeed":
		return 78
	case "GitHubReleaseAsset":
		return 75
	case "OSV":
		return 60
	default:
		return 50
	}
}

func mergeAdvisory(existing []vuln.Advisory, advisory vuln.Advisory) []vuln.Advisory {
	for i, current := range existing {
		if current.Ecosystem != advisory.Ecosystem || vulnNormalizePackageName(current.Ecosystem, current.PackageName) != vulnNormalizePackageName(advisory.Ecosystem, advisory.PackageName) {
			continue
		}
		if !sharesIdentifier(current, advisory) {
			continue
		}
		if advisory.SourcePriority > current.SourcePriority {
			existing[i] = advisory
		}
		return existing
	}
	return append(existing, advisory)
}

func vulnNormalizePackageName(ecosystem, name string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi":
		replacer := strings.NewReplacer("_", "-", ".", "-")
		value := replacer.Replace(strings.TrimSpace(name))
		for strings.Contains(value, "--") {
			value = strings.ReplaceAll(value, "--", "-")
		}
		return strings.ToLower(value)
	case "npm", "gem", "composer", "cargo", "nuget", "apk", "deb", "rpm":
		return strings.ToLower(strings.TrimSpace(name))
	default:
		return strings.TrimSpace(name)
	}
}

func sharesIdentifier(a, b vuln.Advisory) bool {
	left := identifiers(a)
	for id := range identifiers(b) {
		if _, ok := left[id]; ok {
			return true
		}
	}
	return false
}

func identifiers(advisory vuln.Advisory) map[string]struct{} {
	values := map[string]struct{}{}
	if id := strings.TrimSpace(advisory.ID); id != "" {
		values[id] = struct{}{}
	}
	for _, alias := range advisory.Aliases {
		if alias = strings.TrimSpace(alias); alias != "" {
			values[alias] = struct{}{}
		}
	}
	return values
}

func loadGitHubReleaseAssetBytes(ctx context.Context, releaseRef, assetName string) ([]byte, error) {
	owner, repo, tag, err := parseGitHubReleaseAssetRef(releaseRef)
	if err != nil {
		return nil, err
	}
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build github release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch github release metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch github release metadata: unexpected status %s", resp.Status)
	}
	var payload struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode github release metadata: %w", err)
	}
	for _, asset := range payload.Assets {
		if strings.TrimSpace(asset.Name) != strings.TrimSpace(assetName) {
			continue
		}
		return fetchHTTPBytes(ctx, asset.BrowserDownloadURL)
	}
	return nil, fmt.Errorf("github release asset %q not found in %s", assetName, releaseRef)
}

func parseGitHubReleaseAssetRef(value string) (string, string, string, error) {
	trimmed := strings.TrimSpace(value)
	parts := strings.SplitN(trimmed, "@", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", "", fmt.Errorf("github release asset source must use owner/repo@tag")
	}
	repoParts := strings.Split(strings.TrimSpace(parts[0]), "/")
	if len(repoParts) != 2 || strings.TrimSpace(repoParts[0]) == "" || strings.TrimSpace(repoParts[1]) == "" {
		return "", "", "", fmt.Errorf("github release asset source must use owner/repo@tag")
	}
	return strings.TrimSpace(repoParts[0]), strings.TrimSpace(repoParts[1]), strings.TrimSpace(parts[1]), nil
}

func fetchHTTPBytes(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch remote source: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch remote source: unexpected status %s", resp.Status)
	}
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read remote source: %w", err)
	}
	return content, nil
}
