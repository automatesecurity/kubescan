package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"kubescan/internal/signing"
	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"

	"sigs.k8s.io/yaml"
)

type SignedBundle struct {
	APIVersion string         `json:"apiVersion,omitempty" yaml:"apiVersion"`
	Kind       string         `json:"kind,omitempty" yaml:"kind"`
	Metadata   BundleMetadata `json:"metadata" yaml:"metadata"`
	Payload    string         `json:"payload" yaml:"payload"`
	Signature  string         `json:"signature" yaml:"signature"`
}

const (
	SignedBundleAPIVersion        = "kubescan.automatesecurity.github.io/v1alpha1"
	LegacySignedBundleAPIVersion  = "kubescan.io/v1alpha1"
	LegacySignedBundleAPIVersion2 = "security.kubescan.io/v1alpha1"
	SignedBundleKind              = "SignedBundle"
)

type BundleMetadata struct {
	Type      string `json:"type" yaml:"type"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
}

func LoadSignedAdvisories(bundlePath, keyPath string) (vuln.AdvisoryBundle, error) {
	bundle, err := LoadSignedBundle(bundlePath)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	publicKey, err := signing.LoadEd25519PublicKey(keyPath)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadSignedAdvisoriesBundle(bundle, publicKey)
}

func LoadSignedPolicyControls(bundlePath, keyPath string) (policy.Controls, error) {
	bundle, err := LoadSignedBundle(bundlePath)
	if err != nil {
		return policy.Controls{}, err
	}
	publicKey, err := signing.LoadEd25519PublicKey(keyPath)
	if err != nil {
		return policy.Controls{}, err
	}
	return LoadSignedPolicyControlsBundle(bundle, publicKey)
}

func LoadSignedRuleBundle(bundlePath, keyPath string) (policy.RuleBundle, error) {
	bundle, err := LoadSignedBundle(bundlePath)
	if err != nil {
		return policy.RuleBundle{}, err
	}
	publicKey, err := signing.LoadEd25519PublicKey(keyPath)
	if err != nil {
		return policy.RuleBundle{}, err
	}
	return LoadSignedRuleBundleFromBundle(bundle, publicKey)
}

func LoadSignedBundle(path string) (SignedBundle, error) {
	content, err := osReadFile(path)
	if err != nil {
		return SignedBundle{}, fmt.Errorf("read bundle: %w", err)
	}

	var bundle SignedBundle
	if err := yaml.Unmarshal(content, &bundle); err != nil {
		return SignedBundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := validateBundle(bundle); err != nil {
		return SignedBundle{}, err
	}
	return bundle, nil
}

func VerifyBundle(bundle SignedBundle, keyPath string) error {
	publicKey, err := signing.LoadEd25519PublicKey(keyPath)
	if err != nil {
		return err
	}
	return VerifyBundleWithPublicKey(bundle, publicKey)
}

func VerifyBundleWithPublicKey(bundle SignedBundle, publicKey ed25519.PublicKey) error {
	if bundle.Metadata.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported bundle algorithm %q", bundle.Metadata.Algorithm)
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	signedContent, err := signedBundleContent(bundle)
	if err != nil {
		return err
	}
	if err := signing.VerifyEd25519(publicKey, signedContent, signature); err != nil {
		return err
	}
	return nil
}

func LoadSignedBundleBytes(content []byte) (SignedBundle, error) {
	var bundle SignedBundle
	if err := yaml.Unmarshal(content, &bundle); err != nil {
		return SignedBundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := validateBundle(bundle); err != nil {
		return SignedBundle{}, err
	}
	return bundle, nil
}

func LoadSignedAdvisoriesBytes(bundleContent, publicKeyPEM []byte) (vuln.AdvisoryBundle, error) {
	bundle, err := LoadSignedBundleBytes(bundleContent)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	publicKey, err := signing.LoadEd25519PublicKeyBytes(publicKeyPEM)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	return LoadSignedAdvisoriesBundle(bundle, publicKey)
}

func LoadSignedPolicyControlsBytes(bundleContent, publicKeyPEM []byte) (policy.Controls, error) {
	bundle, err := LoadSignedBundleBytes(bundleContent)
	if err != nil {
		return policy.Controls{}, err
	}
	publicKey, err := signing.LoadEd25519PublicKeyBytes(publicKeyPEM)
	if err != nil {
		return policy.Controls{}, err
	}
	return LoadSignedPolicyControlsBundle(bundle, publicKey)
}

func LoadSignedRuleBundleBytes(bundleContent, publicKeyPEM []byte) (policy.RuleBundle, error) {
	bundle, err := LoadSignedBundleBytes(bundleContent)
	if err != nil {
		return policy.RuleBundle{}, err
	}
	publicKey, err := signing.LoadEd25519PublicKeyBytes(publicKeyPEM)
	if err != nil {
		return policy.RuleBundle{}, err
	}
	return LoadSignedRuleBundleFromBundle(bundle, publicKey)
}

func LoadSignedAdvisoriesBundle(bundle SignedBundle, publicKey ed25519.PublicKey) (vuln.AdvisoryBundle, error) {
	if err := VerifyBundleWithPublicKey(bundle, publicKey); err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	if bundle.Metadata.Type != "advisories" {
		return vuln.AdvisoryBundle{}, fmt.Errorf("bundle type %q is not supported for advisory loading", bundle.Metadata.Type)
	}
	return vuln.LoadAdvisoriesBytes([]byte(bundle.Payload))
}

func LoadSignedPolicyControlsBundle(bundle SignedBundle, publicKey ed25519.PublicKey) (policy.Controls, error) {
	if err := VerifyBundleWithPublicKey(bundle, publicKey); err != nil {
		return policy.Controls{}, err
	}
	if bundle.Metadata.Type != "policy-controls" {
		return policy.Controls{}, fmt.Errorf("bundle type %q is not supported for policy control loading", bundle.Metadata.Type)
	}
	return policy.LoadControlsBytes([]byte(bundle.Payload))
}

func LoadSignedRuleBundleFromBundle(bundle SignedBundle, publicKey ed25519.PublicKey) (policy.RuleBundle, error) {
	if err := VerifyBundleWithPublicKey(bundle, publicKey); err != nil {
		return policy.RuleBundle{}, err
	}
	if bundle.Metadata.Type != "rules" {
		return policy.RuleBundle{}, fmt.Errorf("bundle type %q is not supported for rule bundle loading", bundle.Metadata.Type)
	}
	return policy.LoadRuleBundleBytes([]byte(bundle.Payload))
}

func validateBundle(bundle SignedBundle) error {
	if bundle.APIVersion != "" &&
		bundle.APIVersion != SignedBundleAPIVersion &&
		bundle.APIVersion != LegacySignedBundleAPIVersion &&
		bundle.APIVersion != LegacySignedBundleAPIVersion2 {
		return fmt.Errorf("unsupported signed bundle apiVersion %q", bundle.APIVersion)
	}
	if bundle.Kind != SignedBundleKind {
		return fmt.Errorf("bundle kind must be %s", SignedBundleKind)
	}
	if bundle.Metadata.Type == "" {
		return fmt.Errorf("bundle metadata.type is required")
	}
	if bundle.Metadata.Algorithm == "" {
		return fmt.Errorf("bundle metadata.algorithm is required")
	}
	if bundle.Payload == "" {
		return fmt.Errorf("bundle payload is required")
	}
	if bundle.Signature == "" {
		return fmt.Errorf("bundle signature is required")
	}
	return nil
}

func signedBundleContent(bundle SignedBundle) ([]byte, error) {
	envelope := struct {
		APIVersion string         `json:"apiVersion,omitempty"`
		Kind       string         `json:"kind"`
		Metadata   BundleMetadata `json:"metadata"`
		Payload    string         `json:"payload"`
	}{
		APIVersion: bundle.APIVersion,
		Kind:       bundle.Kind,
		Metadata:   bundle.Metadata,
		Payload:    bundle.Payload,
	}
	content, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode signed bundle envelope: %w", err)
	}
	return content, nil
}

var osReadFile = func(path string) ([]byte, error) {
	return os.ReadFile(path)
}
