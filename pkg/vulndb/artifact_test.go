package vulndb

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kubescan/internal/signing"
	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

func TestMetadataAndVerification(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "advisories.db")
	metadataPath := filepath.Join(dir, "advisories.db.metadata.json")
	signaturePath := filepath.Join(dir, "advisories.db.sig")
	publicKeyPath, privateKeyPath := writeEd25519Keypair(t, dir)

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
		Advisories: []vuln.Advisory{{
			ID:               "CVE-2026-0001",
			PackageName:      "openssl",
			Ecosystem:        "apk",
			AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
			Severity:         policy.SeverityHigh,
			Summary:          "OpenSSL vulnerability",
		}},
	}
	if err := Write(dbPath, bundle); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	info, err := Inspect(dbPath)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	metadata, err := BuildMetadata(dbPath, info)
	if err != nil {
		t.Fatalf("BuildMetadata returned error: %v", err)
	}
	if err := WriteMetadata(metadataPath, metadata); err != nil {
		t.Fatalf("WriteMetadata returned error: %v", err)
	}
	if err := WriteSignature(signaturePath, dbPath, privateKeyPath); err != nil {
		t.Fatalf("WriteSignature returned error: %v", err)
	}
	if err := VerifyArtifact(VerifyOptions{
		DBPath:        dbPath,
		MetadataPath:  metadataPath,
		SignaturePath: signaturePath,
		KeyPath:       publicKeyPath,
	}); err != nil {
		t.Fatalf("VerifyArtifact returned error: %v", err)
	}
}

func TestVerifyArtifactWithSigstoreBundle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "advisories.db")
	metadataPath := filepath.Join(dir, "advisories.db.metadata.json")
	bundlePath := filepath.Join(dir, "advisories.db.sigstore.json")

	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
		Advisories: []vuln.Advisory{{
			ID:               "CVE-2026-0001",
			PackageName:      "openssl",
			Ecosystem:        "apk",
			AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
			Severity:         policy.SeverityHigh,
			Summary:          "OpenSSL vulnerability",
		}},
	}
	if err := Write(dbPath, bundle); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	info, err := Inspect(dbPath)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	metadata, err := BuildMetadata(dbPath, info)
	if err != nil {
		t.Fatalf("BuildMetadata returned error: %v", err)
	}
	if err := WriteMetadata(metadataPath, metadata); err != nil {
		t.Fatalf("WriteMetadata returned error: %v", err)
	}
	if err := os.WriteFile(bundlePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	original := verifySigstoreBundleFunc
	t.Cleanup(func() { verifySigstoreBundleFunc = original })
	verifySigstoreBundleFunc = func(gotDBPath string, options SigstoreVerifyOptions) error {
		if gotDBPath != dbPath {
			t.Fatalf("unexpected db path %q", gotDBPath)
		}
		if options.BundlePath != bundlePath {
			t.Fatalf("unexpected bundle path %q", options.BundlePath)
		}
		if options.CertificateIdentityRegexp != OfficialDBCertificateIdentityRegexp {
			t.Fatalf("unexpected default certificate identity regex %q", options.CertificateIdentityRegexp)
		}
		if options.CertificateOIDCIssuer != OfficialDBCertificateOIDCIssuer {
			t.Fatalf("unexpected default OIDC issuer %q", options.CertificateOIDCIssuer)
		}
		return nil
	}

	if err := VerifyArtifact(VerifyOptions{
		DBPath:       dbPath,
		MetadataPath: metadataPath,
		Sigstore: SigstoreVerifyOptions{
			BundlePath: bundlePath,
		},
	}); err != nil {
		t.Fatalf("VerifyArtifact returned error: %v", err)
	}
}

func TestDownloadAndVerifyLegacySignature(t *testing.T) {
	dir := t.TempDir()
	srcDBPath := filepath.Join(dir, "source.db")
	publicKeyPath, privateKeyPath := writeEd25519Keypair(t, dir)
	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
		Advisories: []vuln.Advisory{{
			ID:               "CVE-2026-0001",
			PackageName:      "openssl",
			Ecosystem:        "apk",
			AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
			Severity:         policy.SeverityHigh,
			Summary:          "OpenSSL vulnerability",
		}},
	}
	if err := Write(srcDBPath, bundle); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	info, err := Inspect(srcDBPath)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	metadata, err := BuildMetadata(srcDBPath, info)
	if err != nil {
		t.Fatalf("BuildMetadata returned error: %v", err)
	}
	metadataBytes, err := jsonMarshal(metadata)
	if err != nil {
		t.Fatalf("jsonMarshal returned error: %v", err)
	}
	dbBytes, err := os.ReadFile(srcDBPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	privateKey, err := signing.LoadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey returned error: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(signing.SignEd25519(privateKey, dbBytes))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/advisories.db":
			_, _ = w.Write(dbBytes)
		case "/advisories.db.metadata.json":
			_, _ = w.Write(append(metadataBytes, '\n'))
		case "/advisories.db.sig":
			_, _ = w.Write([]byte(signature))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	outPath := filepath.Join(dir, "downloaded.db")
	if err := Download(DownloadOptions{
		DBURL:        server.URL + "/advisories.db",
		MetadataURL:  server.URL + "/advisories.db.metadata.json",
		SignatureURL: server.URL + "/advisories.db.sig",
		KeyPath:      publicKeyPath,
		OutPath:      outPath,
	}); err != nil {
		t.Fatalf("Download returned error: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected downloaded db to exist: %v", err)
	}
}

func TestDownloadAndVerifySigstoreBundle(t *testing.T) {
	dir := t.TempDir()
	srcDBPath := filepath.Join(dir, "source.db")
	bundle := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
		Advisories: []vuln.Advisory{{
			ID:               "CVE-2026-0001",
			PackageName:      "openssl",
			Ecosystem:        "apk",
			AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
			Severity:         policy.SeverityHigh,
			Summary:          "OpenSSL vulnerability",
		}},
	}
	if err := Write(srcDBPath, bundle); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	info, err := Inspect(srcDBPath)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	metadata, err := BuildMetadata(srcDBPath, info)
	if err != nil {
		t.Fatalf("BuildMetadata returned error: %v", err)
	}
	metadataBytes, err := jsonMarshal(metadata)
	if err != nil {
		t.Fatalf("jsonMarshal returned error: %v", err)
	}
	dbBytes, err := os.ReadFile(srcDBPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/advisories.db":
			_, _ = w.Write(dbBytes)
		case "/advisories.db.metadata.json":
			_, _ = w.Write(append(metadataBytes, '\n'))
		case "/advisories.db.sigstore.json":
			_, _ = w.Write([]byte("{}\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	original := verifySigstoreBundleFunc
	t.Cleanup(func() { verifySigstoreBundleFunc = original })
	verifySigstoreBundleFunc = func(gotDBPath string, options SigstoreVerifyOptions) error {
		if options.BundlePath == "" {
			t.Fatalf("expected bundle path to be populated")
		}
		if gotDBPath == "" {
			t.Fatalf("expected db path to be populated")
		}
		return nil
	}

	outPath := filepath.Join(dir, "downloaded.db")
	if err := Download(DownloadOptions{
		DBURL:       server.URL + "/advisories.db",
		MetadataURL: server.URL + "/advisories.db.metadata.json",
		BundleURL:   server.URL + "/advisories.db.sigstore.json",
		OutPath:     outPath,
	}); err != nil {
		t.Fatalf("Download returned error: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected downloaded db to exist: %v", err)
	}
}

func writeEd25519Keypair(t *testing.T, dir string) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey returned error: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey returned error: %v", err)
	}

	publicKeyPath := filepath.Join(dir, "bundle.pub.pem")
	privateKeyPath := filepath.Join(dir, "bundle.key.pem")
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return publicKeyPath, privateKeyPath
}

func jsonMarshal(metadata ArtifactMetadata) ([]byte, error) { return json.Marshal(metadata) }
