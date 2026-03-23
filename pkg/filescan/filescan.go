package filescan

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"

	"kubescan/pkg/k8s"
	"kubescan/pkg/licensescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/secretscan"
)

type Result struct {
	Findings []policy.Finding
}

type Options struct {
	LicensePolicy  licensescan.Policy
	ExcludePaths   []string
	SecretScanMode secretscan.Mode
}

func ScanPath(root string, profile policy.RuleProfile, now time.Time) (Result, error) {
	return ScanPathWithOptions(root, profile, now, Options{})
}

func ScanPathWithOptions(root string, profile policy.RuleProfile, now time.Time, options Options) (Result, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return Result{}, fmt.Errorf("stat path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Result{}, fmt.Errorf("scan root must not be a symlink")
	}

	var findings []policy.Finding
	if !info.IsDir() {
		base := filepath.Dir(root)
		relativePath := relativeName(base, root)
		if pathExcluded(relativePath, false, options.ExcludePaths) {
			return Result{}, nil
		}
		fileFindings, err := scanFile(root, base, profile, now, options)
		if err != nil {
			return Result{}, err
		}
		return Result{Findings: fileFindings}, nil
	}

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		relativePath := relativeName(root, path)
		if relativePath != "." && pathExcluded(relativePath, entry.IsDir(), options.ExcludePaths) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if shouldSkipDir(entry.Name()) && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		fileFindings, err := scanFile(path, root, profile, now, options)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("walk path: %w", err)
	}

	return Result{Findings: findings}, nil
}

func scanFile(path string, root string, profile policy.RuleProfile, now time.Time, options Options) ([]policy.Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}
	if len(content) == 0 || len(content) > 1024*1024 || looksBinary(content) {
		return nil, nil
	}

	relativePath := relativeName(root, path)
	var findings []policy.Finding
	findings = append(findings, secretFindings(relativePath, string(content), options.SecretScanMode, now)...)
	findings = append(findings, licensescan.EvaluateFile(relativePath, content, options.LicensePolicy, now)...)

	if !isManifestCandidate(path) {
		return findings, nil
	}
	inventory, err := k8s.LoadInventory(strings.NewReader(string(content)))
	if err != nil || isEmptyInventory(inventory) {
		return findings, nil
	}
	findings = append(findings, policy.EvaluateWithProfile(inventory, profile)...)
	return findings, nil
}

func secretFindings(relativePath string, content string, mode secretscan.Mode, now time.Time) []policy.Finding {
	if shouldSkipSecretScanFile(relativePath) {
		return nil
	}

	matches := secretscan.ScanTextWithMode(content, normalizeSecretScanMode(mode), shouldUseGenericSecretAssignments(relativePath))

	var findings []policy.Finding
	for _, match := range matches {
		message := fileSecretMessage(relativePath, match)
		sum := sha1.Sum([]byte(strings.Join([]string{"KF001", relativePath, match.Detector, match.Name, strconvLine(match.Line), match.Fingerprint}, "|")))
		findings = append(findings, policy.Finding{
			ID:          hex.EncodeToString(sum[:8]),
			Category:    policy.CategoryExposure,
			RuleID:      "KF001",
			Title:       "Sensitive value detected in file",
			Severity:    policy.SeverityHigh,
			RuleVersion: "fs/v1alpha2",
			Resource: policy.ResourceRef{
				Kind: "File",
				Name: relativePath,
			},
			Message: message,
			Evidence: map[string]any{
				"detector":    match.Detector,
				"description": match.Description,
				"key":         match.Name,
				"line":        match.Line,
				"confidence":  string(match.Confidence),
			},
			Remediation: "Remove secrets from source files and inject them at runtime with a secret manager or environment-specific secret store.",
			Timestamp:   now.UTC(),
		})
	}
	return findings
}

func normalizeSecretScanMode(mode secretscan.Mode) secretscan.Mode {
	if mode == "" {
		return secretscan.ModeBalanced
	}
	return mode
}

func isManifestCandidate(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func shouldUseGenericSecretAssignments(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, ".env") {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties":
		return true
	default:
		return false
	}
}

func shouldSkipSecretScanFile(path string) bool {
	switch strings.ToLower(filepath.Base(path)) {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock", "pipfile.lock", "composer.lock", "gemfile.lock":
		return true
	default:
		return false
	}
}

func pathExcluded(relativePath string, isDir bool, patterns []string) bool {
	relativePath = strings.TrimPrefix(filepath.ToSlash(relativePath), "./")
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(filepath.ToSlash(pattern))
		pattern = strings.TrimPrefix(pattern, "./")
		if pattern == "" {
			continue
		}
		switch {
		case strings.HasSuffix(pattern, "/**"):
			prefix := strings.TrimSuffix(pattern, "/**")
			if relativePath == prefix || strings.HasPrefix(relativePath, prefix+"/") {
				return true
			}
		case strings.HasSuffix(pattern, "/"):
			prefix := strings.TrimSuffix(pattern, "/")
			if relativePath == prefix || strings.HasPrefix(relativePath, prefix+"/") {
				return true
			}
		case strings.ContainsAny(pattern, "*?["):
			if ok, _ := pathpkg.Match(pattern, relativePath); ok {
				return true
			}
		default:
			if relativePath == pattern || strings.HasPrefix(relativePath, pattern+"/") {
				return true
			}
		}
		if isDir {
			if ok, _ := pathpkg.Match(pattern, relativePath+"/"); ok {
				return true
			}
		}
	}
	return false
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", ".terraform", "vendor", "dist", "build", "bin", ".next":
		return true
	default:
		return false
	}
}

func looksBinary(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}

func relativeName(root string, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(relative)
}

func isEmptyInventory(inventory policy.Inventory) bool {
	return len(inventory.Workloads) == 0 &&
		len(inventory.Services) == 0 &&
		len(inventory.ConfigMaps) == 0 &&
		len(inventory.Roles) == 0 &&
		len(inventory.Bindings) == 0 &&
		len(inventory.NetworkPolicies) == 0 &&
		len(inventory.Namespaces) == 0
}

func strconvLine(line int) string {
	return fmt.Sprintf("%d", line)
}

func fileSecretMessage(relativePath string, match secretscan.Match) string {
	switch match.Detector {
	case "private-key":
		return fmt.Sprintf("File/%s contains private key material", relativePath)
	case "aws-access-key-id", "github-token", "slack-token", "jwt":
		return fmt.Sprintf("File/%s contains %s", relativePath, article(match.Description))
	default:
		if match.Name != "" {
			return fmt.Sprintf("File/%s defines %s for %s", relativePath, article(match.Description), match.Name)
		}
		return fmt.Sprintf("File/%s contains %s", relativePath, article(match.Description))
	}
}

func article(value string) string {
	if value == "" {
		return "a sensitive value"
	}
	first := strings.ToLower(value[:1])
	switch first {
	case "a", "e", "i", "o", "u":
		return "an " + value
	default:
		return "a " + value
	}
}
