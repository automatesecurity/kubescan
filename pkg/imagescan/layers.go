package imagescan

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"kubescan/pkg/licensescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/secretscan"
)

type LayerScanOptions struct {
	LicensePolicy  licensescan.Policy
	SecretScanMode secretscan.Mode
	MaxFileBytes   int64
	MaxFiles       int
}

func ScanRemoteLayers(ctx context.Context, imageRef string, options LayerScanOptions, now time.Time) ([]policy.Finding, error) {
	return ScanRemoteLayersWithAuth(ctx, imageRef, AuthOptions{}, options, now)
}

func ScanRemoteLayersWithAuth(ctx context.Context, imageRef string, auth AuthOptions, options LayerScanOptions, now time.Time) ([]policy.Finding, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}
	img, err := remote.Image(ref, remoteOptions(ctx, auth)...)
	if err != nil {
		return nil, fmt.Errorf("fetch image: %w", err)
	}
	return scanImageLayers(imageRef, img, options, now)
}

func scanImageLayers(imageRef string, img v1.Image, options LayerScanOptions, now time.Time) ([]policy.Finding, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}

	resource := policy.ResourceRef{Kind: "Image", Name: imageRef}
	maxFileBytes := options.MaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = 256 * 1024
	}
	maxFiles := options.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 1000
	}
	mode := options.SecretScanMode
	if mode == "" {
		mode = secretscan.ModeBalanced
	}

	seen := map[string]policy.Finding{}
	scannedFiles := 0
	for _, layer := range layers {
		if scannedFiles >= maxFiles {
			break
		}
		reader, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("read image layer: %w", err)
		}

		tr := tar.NewReader(reader)
		for scannedFiles < maxFiles {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = reader.Close()
				return nil, fmt.Errorf("read layer tar: %w", err)
			}
			if header == nil || header.Typeflag != tar.TypeReg {
				continue
			}
			scannedFiles++
			path := normalizeLayerPath(header.Name)
			if path == "" || header.Size <= 0 || header.Size > maxFileBytes {
				continue
			}

			content, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
			if err != nil {
				_ = reader.Close()
				return nil, fmt.Errorf("read layer file %s: %w", path, err)
			}
			if int64(len(content)) > maxFileBytes || looksBinary(content) {
				continue
			}

			for _, finding := range scanLayerFile(resource, imageRef, path, content, options.LicensePolicy, mode, now) {
				seen[finding.ID] = finding
			}
		}
		_ = reader.Close()
	}

	findings := make([]policy.Finding, 0, len(seen))
	for _, finding := range seen {
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		if findings[i].Message != findings[j].Message {
			return findings[i].Message < findings[j].Message
		}
		return findings[i].ID < findings[j].ID
	})
	return findings, nil
}

func scanLayerFile(resource policy.ResourceRef, imageRef string, path string, content []byte, licensePolicy licensescan.Policy, mode secretscan.Mode, now time.Time) []policy.Finding {
	var findings []policy.Finding

	if !shouldSkipSecretScanFile(path) {
		for _, match := range secretscan.ScanTextWithMode(string(content), mode, shouldUseGenericSecretAssignments(path)) {
			findings = append(findings, makeLayerFinding(
				"KI005",
				policy.CategoryExposure,
				"Image layer contains sensitive file content",
				policy.SeverityHigh,
				resource,
				imageLayerSecretMessage(imageRef, path, match),
				"Remove secrets from image layers and provide them at runtime through a scoped secret mechanism.",
				now,
				map[string]any{
					"image":       imageRef,
					"path":        path,
					"detector":    match.Detector,
					"description": match.Description,
					"line":        match.Line,
					"confidence":  string(match.Confidence),
				},
			))
		}
	}

	for _, declaration := range licensescan.DetectDeclarations(path, content) {
		if matched := matchedLicenses(declaration.Identifiers, licensePolicy.Denylist); len(matched) > 0 {
			findings = append(findings, makeLayerFinding(
				"KI006",
				policy.CategorySupplyChain,
				"Image layer declares a disallowed license",
				policy.SeverityHigh,
				resource,
				fmt.Sprintf("Image/%s file %s declares disallowed license %s", imageRef, path, strings.Join(matched, ", ")),
				"Replace the disallowed license with an approved one or document a legal-policy exception before distributing the image.",
				now,
				map[string]any{
					"image":             imageRef,
					"path":              path,
					"ecosystem":         declaration.Ecosystem,
					"packageName":       declaration.PackageName,
					"licenseExpression": declaration.LicenseExpression,
					"identifiers":       declaration.Identifiers,
					"matchedLicenses":   matched,
				},
			))
		}
		if len(licensePolicy.Allowlist) > 0 {
			if unapproved := unapprovedLicenses(declaration.Identifiers, licensePolicy.Allowlist); len(unapproved) > 0 {
				findings = append(findings, makeLayerFinding(
					"KI007",
					policy.CategorySupplyChain,
					"Image layer declares a license outside the allowlist",
					policy.SeverityMedium,
					resource,
					fmt.Sprintf("Image/%s file %s declares license %s outside the configured allowlist", imageRef, path, strings.Join(unapproved, ", ")),
					"Use an approved license in image-bundled application code or expand the allowlist only after legal review.",
					now,
					map[string]any{
						"image":              imageRef,
						"path":               path,
						"ecosystem":          declaration.Ecosystem,
						"packageName":        declaration.PackageName,
						"licenseExpression":  declaration.LicenseExpression,
						"identifiers":        declaration.Identifiers,
						"unapprovedLicenses": unapproved,
						"allowlist":          licensePolicy.Allowlist,
					},
				))
			}
		}
	}

	return findings
}

func makeLayerFinding(ruleID string, category policy.Category, title string, severity policy.Severity, resource policy.ResourceRef, message string, remediation string, now time.Time, evidence map[string]any) policy.Finding {
	sum := sha1.Sum([]byte(strings.Join([]string{
		string(category),
		ruleID,
		resource.Name,
		message,
	}, "|")))
	return policy.Finding{
		ID:          hex.EncodeToString(sum[:8]),
		Category:    category,
		RuleID:      ruleID,
		Title:       title,
		Severity:    severity,
		RuleVersion: "image-layer/v1alpha1",
		Resource:    resource,
		Message:     message,
		Evidence:    evidence,
		Remediation: remediation,
		Timestamp:   now.UTC(),
	}
}

func normalizeLayerPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "/")
	return path
}

func imageLayerSecretMessage(imageRef string, path string, match secretscan.Match) string {
	switch match.Detector {
	case "private-key":
		return fmt.Sprintf("Image/%s file %s contains private key material", imageRef, path)
	case "aws-access-key-id", "github-token", "slack-token", "jwt":
		return fmt.Sprintf("Image/%s file %s contains %s", imageRef, path, article(match.Description))
	default:
		if match.Name != "" {
			return fmt.Sprintf("Image/%s file %s defines %s for %s", imageRef, path, article(match.Description), match.Name)
		}
		return fmt.Sprintf("Image/%s file %s contains %s", imageRef, path, article(match.Description))
	}
}

func matchedLicenses(identifiers []string, denylist []string) []string {
	deny := normalizeLicenseList(denylist)
	var matched []string
	for _, identifier := range identifiers {
		if containsString(deny, identifier) {
			matched = append(matched, identifier)
		}
	}
	return matched
}

func unapprovedLicenses(identifiers []string, allowlist []string) []string {
	allow := normalizeLicenseList(allowlist)
	var unapproved []string
	for _, identifier := range identifiers {
		if !containsString(allow, identifier) {
			unapproved = append(unapproved, identifier)
		}
	}
	return unapproved
}

func normalizeLicenseList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "" {
			normalized = append(normalized, value)
		}
	}
	sort.Strings(normalized)
	return normalized
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
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

func looksBinary(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}
