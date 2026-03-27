package vulndb

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kubescan/internal/signing"

	sigstorebundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sigstoreroot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoretuf "github.com/sigstore/sigstore-go/pkg/tuf"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

const ArtifactMetadataVersion = "1.0.0"

const (
	OfficialDBCertificateIdentityRegexp = `^https://github\.com/automatesecurity/kubescan/\.github/workflows/vulndb\.yaml@.*$`
	OfficialDBCertificateOIDCIssuer     = "https://token.actions.githubusercontent.com"
)

var verifySigstoreBundleFunc = verifySigstoreBundle

type ArtifactMetadata struct {
	Schema             string    `json:"schema"`
	SchemaVersion      string    `json:"schemaVersion"`
	GeneratedAt        time.Time `json:"generatedAt"`
	DBSchema           string    `json:"dbSchema"`
	DBSchemaVersion    string    `json:"dbSchemaVersion"`
	DBAdvisoryCount    int       `json:"dbAdvisoryCount"`
	DBBuiltAt          time.Time `json:"dbBuiltAt"`
	DBBundleAPIVersion string    `json:"dbBundleApiVersion"`
	DBBundleKind       string    `json:"dbBundleKind"`
	DBSHA256           string    `json:"dbSha256"`
}

type SigstoreVerifyOptions struct {
	BundlePath                  string
	TrustedRootPath             string
	TUFCachePath                string
	TUFMirror                   string
	CertificateIdentity         string
	CertificateIdentityRegexp   string
	CertificateOIDCIssuer       string
	CertificateOIDCIssuerRegexp string
}

type VerifyOptions struct {
	DBPath        string
	MetadataPath  string
	SignaturePath string
	KeyPath       string
	Sigstore      SigstoreVerifyOptions
}

type DownloadOptions struct {
	DBURL        string
	MetadataURL  string
	SignatureURL string
	KeyPath      string
	BundleURL    string
	OutPath      string
	Client       *http.Client
	Sigstore     SigstoreVerifyOptions
}

func BuildMetadata(dbPath string, info Info) (ArtifactMetadata, error) {
	checksum, err := fileSHA256(dbPath)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	return ArtifactMetadata{
		Schema:             "kubescan-vulndb-artifact",
		SchemaVersion:      ArtifactMetadataVersion,
		GeneratedAt:        time.Now().UTC(),
		DBSchema:           info.Schema,
		DBSchemaVersion:    info.SchemaVersion,
		DBAdvisoryCount:    info.AdvisoryCount,
		DBBuiltAt:          info.BuiltAt,
		DBBundleAPIVersion: info.BundleAPIVersion,
		DBBundleKind:       info.BundleKind,
		DBSHA256:           checksum,
	}, nil
}

func WriteMetadata(path string, metadata ArtifactMetadata) error {
	content, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

func LoadMetadata(path string) (ArtifactMetadata, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return ArtifactMetadata{}, fmt.Errorf("read metadata: %w", err)
	}
	var metadata ArtifactMetadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		return ArtifactMetadata{}, fmt.Errorf("decode metadata: %w", err)
	}
	if err := validateMetadata(metadata); err != nil {
		return ArtifactMetadata{}, err
	}
	return metadata, nil
}

func WriteSignature(path, dbPath, privateKeyPath string) error {
	privateKey, err := signing.LoadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(dbPath)
	if err != nil {
		return fmt.Errorf("read db for signing: %w", err)
	}
	signature := signing.SignEd25519(privateKey, content)
	encoded := base64.StdEncoding.EncodeToString(signature) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}

func VerifyArtifact(options VerifyOptions) error {
	if options.MetadataPath != "" {
		metadata, err := LoadMetadata(options.MetadataPath)
		if err != nil {
			return err
		}
		if err := verifyChecksum(options.DBPath, metadata.DBSHA256); err != nil {
			return err
		}
	}
	if options.Sigstore.BundlePath != "" {
		options.Sigstore = defaultedSigstoreVerifyOptions(options.Sigstore)
		if err := verifySigstoreBundleFunc(options.DBPath, options.Sigstore); err != nil {
			return err
		}
	}
	if options.SignaturePath != "" || options.KeyPath != "" {
		if options.SignaturePath == "" || options.KeyPath == "" {
			return fmt.Errorf("both signature and key are required for signature verification")
		}
		if err := verifySignature(options.DBPath, options.SignaturePath, options.KeyPath); err != nil {
			return err
		}
	}
	return nil
}

func Download(options DownloadOptions) error {
	if strings.TrimSpace(options.DBURL) == "" {
		return fmt.Errorf("db url is required")
	}
	if strings.TrimSpace(options.OutPath) == "" {
		return fmt.Errorf("out path is required")
	}
	if (options.SignatureURL != "" || options.KeyPath != "") && (options.SignatureURL == "" || options.KeyPath == "") {
		return fmt.Errorf("signature-url and key-path must be provided together")
	}
	client := options.Client
	if client == nil {
		client = http.DefaultClient
	}

	if err := downloadFile(client, options.DBURL, options.OutPath); err != nil {
		return err
	}

	metadataPath := ""
	if options.MetadataURL != "" {
		metadataPath = options.OutPath + ".metadata.json"
		if err := downloadFile(client, options.MetadataURL, metadataPath); err != nil {
			return err
		}
	}

	signaturePath := ""
	if options.SignatureURL != "" {
		signaturePath = options.OutPath + ".sig"
		if err := downloadFile(client, options.SignatureURL, signaturePath); err != nil {
			return err
		}
	}

	bundlePath := ""
	if options.BundleURL != "" {
		bundlePath = options.OutPath + ".sigstore.json"
		if err := downloadFile(client, options.BundleURL, bundlePath); err != nil {
			return err
		}
	}

	verifyOptions := VerifyOptions{
		DBPath:        options.OutPath,
		MetadataPath:  metadataPath,
		SignaturePath: signaturePath,
		KeyPath:       options.KeyPath,
		Sigstore:      options.Sigstore,
	}
	verifyOptions.Sigstore.BundlePath = bundlePath

	if err := VerifyArtifact(verifyOptions); err != nil {
		return err
	}
	return nil
}

func verifySigstoreBundle(dbPath string, options SigstoreVerifyOptions) error {
	if strings.TrimSpace(options.BundlePath) == "" {
		return fmt.Errorf("sigstore bundle path is required")
	}

	var trustedRoot *sigstoreroot.TrustedRoot
	var err error
	if options.TrustedRootPath != "" {
		trustedRoot, err = sigstoreroot.NewTrustedRootFromPath(options.TrustedRootPath)
	} else {
		tufOptions := sigstoretuf.DefaultOptions()
		if options.TUFCachePath != "" {
			tufOptions.CachePath = options.TUFCachePath
		}
		if options.TUFMirror != "" {
			tufOptions.RepositoryBaseURL = options.TUFMirror
		}
		trustedRoot, err = sigstoreroot.FetchTrustedRootWithOptions(tufOptions)
	}
	if err != nil {
		return fmt.Errorf("load sigstore trusted root: %w", err)
	}

	entity, err := sigstorebundle.LoadJSONFromPath(options.BundlePath)
	if err != nil {
		return fmt.Errorf("load sigstore bundle: %w", err)
	}

	verifier, err := sigstoreverify.NewVerifier(
		trustedRoot,
		sigstoreverify.WithSignedCertificateTimestamps(1),
		sigstoreverify.WithObserverTimestamps(1),
		sigstoreverify.WithTransparencyLog(1),
	)
	if err != nil {
		return fmt.Errorf("create sigstore verifier: %w", err)
	}

	identity, err := sigstoreverify.NewShortCertificateIdentity(
		options.CertificateOIDCIssuer,
		options.CertificateOIDCIssuerRegexp,
		options.CertificateIdentity,
		options.CertificateIdentityRegexp,
	)
	if err != nil {
		return fmt.Errorf("build sigstore identity policy: %w", err)
	}

	file, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db for sigstore verification: %w", err)
	}
	defer file.Close()

	if _, err := verifier.Verify(
		entity,
		sigstoreverify.NewPolicy(
			sigstoreverify.WithArtifact(file),
			sigstoreverify.WithCertificateIdentity(identity),
		),
	); err != nil {
		return fmt.Errorf("verify sigstore bundle: %w", err)
	}

	return nil
}

func defaultedSigstoreVerifyOptions(options SigstoreVerifyOptions) SigstoreVerifyOptions {
	if options.CertificateIdentity == "" && options.CertificateIdentityRegexp == "" {
		options.CertificateIdentityRegexp = OfficialDBCertificateIdentityRegexp
	}
	if options.CertificateOIDCIssuer == "" && options.CertificateOIDCIssuerRegexp == "" {
		options.CertificateOIDCIssuer = OfficialDBCertificateOIDCIssuer
	}
	return options
}

func verifySignature(dbPath, signaturePath, keyPath string) error {
	publicKey, err := signing.LoadEd25519PublicKey(keyPath)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(dbPath)
	if err != nil {
		return fmt.Errorf("read db for verification: %w", err)
	}
	signatureContent, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureContent)))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if err := signing.VerifyEd25519(publicKey, content, signature); err != nil {
		return err
	}
	return nil
}

func verifyChecksum(dbPath, expected string) error {
	actual, err := fileSHA256(dbPath)
	if err != nil {
		return err
	}
	if actual != strings.ToLower(strings.TrimSpace(expected)) {
		return fmt.Errorf("db checksum mismatch: expected %s got %s", expected, actual)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for checksum: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validateMetadata(metadata ArtifactMetadata) error {
	if metadata.Schema != "kubescan-vulndb-artifact" {
		return fmt.Errorf("unsupported artifact metadata schema %q", metadata.Schema)
	}
	if metadata.SchemaVersion != ArtifactMetadataVersion {
		return fmt.Errorf("unsupported artifact metadata schema version %q", metadata.SchemaVersion)
	}
	if metadata.DBSchema != SchemaName {
		return fmt.Errorf("unsupported database schema %q", metadata.DBSchema)
	}
	if metadata.DBSchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported database schema version %q", metadata.DBSchemaVersion)
	}
	if strings.TrimSpace(metadata.DBSHA256) == "" {
		return fmt.Errorf("artifact metadata dbSha256 is required")
	}
	return nil
}

func downloadFile(client *http.Client, rawURL, outPath string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse url %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}

	resp, err := client.Get(parsed.String())
	if err != nil {
		return fmt.Errorf("download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download %s: unexpected status %s", rawURL, resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer file.Close()
	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("write downloaded file: %w", err)
	}
	return nil
}

func VerifyArtifactBytes(dbContent []byte, metadata ArtifactMetadata, signature []byte, publicKey ed25519.PublicKey) error {
	if err := validateMetadata(metadata); err != nil {
		return err
	}
	sum := sha256.Sum256(dbContent)
	if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(metadata.DBSHA256)) {
		return fmt.Errorf("db checksum mismatch")
	}
	if len(signature) > 0 {
		if err := signing.VerifyEd25519(publicKey, dbContent, signature); err != nil {
			return err
		}
	}
	return nil
}
