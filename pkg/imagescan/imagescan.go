package imagescan

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"kubescan/pkg/policy"
	"kubescan/pkg/secretscan"
)

type Metadata struct {
	Reference    string
	Registry     string
	Repository   string
	Tag          string
	Digest       string
	User         string
	OS           string
	Architecture string
	Env          []string
	ExposedPorts []string
}

type AuthOptions struct {
	Username string
	Password string
	Token    string
}

func InspectRemote(ctx context.Context, imageRef string) (Metadata, error) {
	return InspectRemoteWithAuth(ctx, imageRef, AuthOptions{})
}

func InspectRemoteWithAuth(ctx context.Context, imageRef string, auth AuthOptions) (Metadata, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return Metadata{}, fmt.Errorf("parse image reference: %w", err)
	}

	img, err := remote.Image(ref, remoteOptions(ctx, auth)...)
	if err != nil {
		return Metadata{}, fmt.Errorf("fetch image: %w", err)
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return Metadata{}, fmt.Errorf("read image config: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return Metadata{}, fmt.Errorf("read image digest: %w", err)
	}

	metadata := Metadata{
		Reference:    imageRef,
		Registry:     ref.Context().RegistryStr(),
		Repository:   ref.Context().RepositoryStr(),
		Digest:       digest.String(),
		User:         configFile.Config.User,
		OS:           configFile.OS,
		Architecture: configFile.Architecture,
		Env:          append([]string(nil), configFile.Config.Env...),
	}

	if tag, ok := ref.(name.Tag); ok {
		metadata.Tag = tag.TagStr()
	}

	for port := range configFile.Config.ExposedPorts {
		metadata.ExposedPorts = append(metadata.ExposedPorts, string(port))
	}
	sort.Strings(metadata.ExposedPorts)

	return metadata, nil
}

func remoteOptions(ctx context.Context, auth AuthOptions) []remote.Option {
	options := []remote.Option{remote.WithContext(ctx)}
	if authenticator := auth.authenticator(); authenticator != nil {
		return append(options, remote.WithAuth(authenticator))
	}
	return append(options, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

func (auth AuthOptions) authenticator() authn.Authenticator {
	if strings.TrimSpace(auth.Token) != "" {
		return authn.FromConfig(authn.AuthConfig{
			RegistryToken: strings.TrimSpace(auth.Token),
		})
	}
	if strings.TrimSpace(auth.Username) != "" || auth.Password != "" {
		return authn.FromConfig(authn.AuthConfig{
			Username: strings.TrimSpace(auth.Username),
			Password: auth.Password,
		})
	}
	return nil
}

func Evaluate(metadata Metadata, now time.Time) []policy.Finding {
	resource := policy.ResourceRef{
		Kind: "Image",
		Name: metadata.Reference,
	}

	var findings []policy.Finding
	if usesMutableTag(metadata.Reference) {
		findings = append(findings, makeFinding(
			"KI001",
			policy.CategorySupplyChain,
			"Mutable image tag",
			policy.SeverityHigh,
			resource,
			"Image/"+metadata.Reference+" uses a mutable image tag",
			"Pin image references by digest or immutable version tags instead of latest or floating tags.",
			now,
			map[string]any{
				"image":  metadata.Reference,
				"tag":    metadata.Tag,
				"digest": metadata.Digest,
			},
		))
	}

	registry, implicit := imageRegistry(metadata.Reference)
	if implicit || isPublicRegistry(registry) {
		findings = append(findings, makeFinding(
			"KI002",
			policy.CategorySupplyChain,
			"Image sourced from a public or implicit registry",
			policy.SeverityMedium,
			resource,
			"Image/"+metadata.Reference+" pulls from a public or implicit registry",
			"Pull images from approved private registries or document an explicit exception for public registry usage.",
			now,
			map[string]any{
				"image":            metadata.Reference,
				"registry":         registry,
				"implicitRegistry": implicit,
			},
		))
	}

	if isRootUser(metadata.User) {
		findings = append(findings, makeFinding(
			"KI003",
			policy.CategoryMisconfig,
			"Image may run as root",
			policy.SeverityHigh,
			resource,
			"Image/"+metadata.Reference+" may run as root by default",
			"Set a non-root image user in the image config and run the workload with a non-root UID.",
			now,
			map[string]any{
				"image":        metadata.Reference,
				"user":         metadata.User,
				"os":           metadata.OS,
				"architecture": metadata.Architecture,
			},
		))
	}

	for _, envEntry := range metadata.Env {
		name, value, ok := splitEnv(envEntry)
		if !ok {
			continue
		}
		match := secretscan.DetectNamedValue(name, value)
		if match == nil {
			continue
		}
		findings = append(findings, makeFinding(
			"KI004",
			policy.CategoryExposure,
			"Image config contains sensitive environment variable",
			policy.SeverityHigh,
			resource,
			imageSecretMessage(metadata.Reference, name, *match),
			"Remove secrets from the image config and inject them at runtime with a scoped secret mechanism instead.",
			now,
			map[string]any{
				"image":       metadata.Reference,
				"envVar":      name,
				"detector":    match.Detector,
				"description": match.Description,
				"confidence":  string(match.Confidence),
			},
		))
	}

	return findings
}

func makeFinding(ruleID string, category policy.Category, title string, severity policy.Severity, resource policy.ResourceRef, message string, remediation string, now time.Time, evidence map[string]any) policy.Finding {
	sum := sha1.Sum([]byte(strings.Join([]string{
		string(category),
		ruleID,
		resource.Kind,
		resource.Name,
		message,
	}, "|")))

	return policy.Finding{
		ID:          hex.EncodeToString(sum[:12]),
		Category:    category,
		RuleID:      ruleID,
		Title:       title,
		Severity:    severity,
		RuleVersion: "image/v1alpha1",
		Resource:    resource,
		Message:     message,
		Evidence:    evidence,
		Remediation: remediation,
		Timestamp:   now.UTC(),
	}
}

func usesMutableTag(image string) bool {
	if at := strings.Index(image, "@"); at >= 0 {
		return false
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon <= lastSlash {
		return true
	}
	tag := image[lastColon+1:]
	return tag == "" || tag == "latest"
}

func imageRegistry(image string) (string, bool) {
	return policy.ImageRegistry(image)
}

func isPublicRegistry(registry string) bool {
	return policy.IsPublicRegistry(registry)
}

func isRootUser(user string) bool {
	trimmed := strings.TrimSpace(user)
	switch trimmed {
	case "", "0", "0:0", "root", "root:root":
		return true
	default:
		return false
	}
}

func splitEnv(value string) (string, string, bool) {
	index := strings.Index(value, "=")
	if index <= 0 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

func imageSecretMessage(imageRef, name string, match secretscan.Match) string {
	switch match.Detector {
	case "private-key":
		return "Image/" + imageRef + " embeds private key material in environment variable " + name
	case "aws-access-key-id", "github-token", "slack-token", "jwt":
		return "Image/" + imageRef + " defines environment variable " + name + " containing " + article(match.Description)
	default:
		return "Image/" + imageRef + " defines environment variable " + name + " containing " + article(match.Description)
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
