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
)

const ArtifactMetadataVersion = "1.0.0"

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

type DownloadOptions struct {
	DBURL        string
	MetadataURL  string
	SignatureURL string
	KeyPath      string
	OutPath      string
	Client       *http.Client
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

func VerifyArtifact(dbPath, metadataPath, signaturePath, keyPath string) error {
	if metadataPath != "" {
		metadata, err := LoadMetadata(metadataPath)
		if err != nil {
			return err
		}
		if err := verifyChecksum(dbPath, metadata.DBSHA256); err != nil {
			return err
		}
	}
	if signaturePath != "" || keyPath != "" {
		if signaturePath == "" || keyPath == "" {
			return fmt.Errorf("both signature and key are required for signature verification")
		}
		if err := verifySignature(dbPath, signaturePath, keyPath); err != nil {
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

	if err := VerifyArtifact(options.OutPath, metadataPath, signaturePath, options.KeyPath); err != nil {
		return err
	}
	return nil
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
