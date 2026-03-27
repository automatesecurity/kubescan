package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"kubescan/internal/bundle"
	"kubescan/pkg/vuln"
	"kubescan/pkg/vulndb"
)

type dbDeps struct {
	loadAdvisories     func(string) (vuln.AdvisoryBundle, error)
	loadAdvisoryBundle func(string, string) (vuln.AdvisoryBundle, error)
	loadOSVSource      func(string) (vuln.AdvisoryBundle, error)
	loadAlpineSecDB    func(string) (vuln.AdvisoryBundle, error)
	loadDebianTracker  func(string, string) (vuln.AdvisoryBundle, error)
	loadUbuntuNotices  func(string, string) (vuln.AdvisoryBundle, error)
	loadKubernetesFeed func(string) (vuln.AdvisoryBundle, error)
	loadSourceManifest func(string) (vulndb.SourceManifest, error)
	resolveSources     func(context.Context, vulndb.SourceManifest, vulndb.SourceResolver) (vuln.AdvisoryBundle, error)
	writeDB            func(string, vuln.AdvisoryBundle) error
	inspectDB          func(string) (vulndb.Info, error)
	buildMetadata      func(string, vulndb.Info) (vulndb.ArtifactMetadata, error)
	writeMetadata      func(string, vulndb.ArtifactMetadata) error
	verifyArtifact     func(vulndb.VerifyOptions) error
	downloadDB         func(vulndb.DownloadOptions) error
}

func RunDB(args []string, stdout, stderr io.Writer) int {
	return runDB(args, stdout, stderr, dbDeps{
		loadAdvisories:     vuln.LoadAdvisories,
		loadAdvisoryBundle: bundle.LoadSignedAdvisories,
		loadOSVSource:      vulndb.LoadOSVSource,
		loadAlpineSecDB:    vulndb.LoadAlpineSecDBSource,
		loadDebianTracker:  vulndb.LoadDebianSecurityTrackerSource,
		loadUbuntuNotices:  vulndb.LoadUbuntuSecurityNoticesSource,
		loadKubernetesFeed: vulndb.LoadKubernetesOfficialCVEFeedSource,
		loadSourceManifest: vulndb.LoadSourceManifest,
		resolveSources:     vulndb.ResolveSources,
		writeDB:            vulndb.Write,
		inspectDB:          vulndb.Inspect,
		buildMetadata:      vulndb.BuildMetadata,
		writeMetadata:      vulndb.WriteMetadata,
		verifyArtifact:     vulndb.VerifyArtifact,
		downloadDB:         vulndb.Download,
	})
}

func runDB(args []string, stdout, stderr io.Writer, deps dbDeps) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kubescan db build [--source-manifest <file> | --advisories <file> | --advisories-bundle <file> --bundle-key <file>] [--osv <file-or-url> ...] --out <file>")
		fmt.Fprintln(stderr, "       kubescan db info --db <file> [--format table|json]")
		return 2
	}

	switch args[0] {
	case "build":
		return runDBBuild(args[1:], stdout, stderr, deps)
	case "info":
		return runDBInfo(args[1:], stdout, stderr, deps)
	case "verify":
		return runDBVerify(args[1:], stdout, stderr, deps)
	case "update":
		return runDBUpdate(args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "unknown db subcommand %q\n", args[0])
		return 2
	}
}

func runDBBuild(args []string, stdout, stderr io.Writer, deps dbDeps) int {
	fs := flag.NewFlagSet("db build", flag.ContinueOnError)
	fs.SetOutput(stderr)

	advisoriesFile := fs.String("advisories", "", "path to an advisory bundle file")
	advisoriesBundleFile := fs.String("advisories-bundle", "", "path to a signed advisory bundle file")
	bundleKeyFile := fs.String("bundle-key", "", "path to an Ed25519 public key for signed advisory bundle verification")
	out := fs.String("out", "", "output sqlite database path")
	sourceManifestPath := fs.String("source-manifest", "", "path to a vulnerability DB source manifest")
	var osvSources multiStringFlag
	fs.Var(&osvSources, "osv", "path or URL for an OSV JSON source; repeat for multiple sources")
	metadataOut := fs.String("metadata-out", "", "write artifact metadata JSON to this path")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "--out is required")
		return 2
	}
	if *sourceManifestPath != "" && (*advisoriesFile != "" || *advisoriesBundleFile != "" || len(osvSources) > 0) {
		fmt.Fprintln(stderr, "--source-manifest cannot be combined with --advisories, --advisories-bundle, or --osv")
		return 2
	}
	if *sourceManifestPath == "" && *advisoriesFile == "" && *advisoriesBundleFile == "" && len(osvSources) == 0 {
		fmt.Fprintln(stderr, "at least one of --source-manifest, --advisories, --advisories-bundle, or --osv is required")
		return 2
	}
	if *advisoriesFile != "" && *advisoriesBundleFile != "" {
		fmt.Fprintln(stderr, "--advisories and --advisories-bundle cannot be used together")
		return 2
	}
	if *advisoriesBundleFile != "" && *bundleKeyFile == "" {
		fmt.Fprintln(stderr, "--advisories-bundle requires --bundle-key")
		return 2
	}
	if *bundleKeyFile != "" && *advisoriesBundleFile == "" {
		fmt.Fprintln(stderr, "--bundle-key requires --advisories-bundle")
		return 2
	}

	advisories := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	var err error
	if *sourceManifestPath != "" {
		manifest, err := deps.loadSourceManifest(*sourceManifestPath)
		if err != nil {
			fmt.Fprintf(stderr, "load source manifest: %v\n", err)
			return 1
		}
		advisories, err = deps.resolveSources(context.Background(), manifest, vulndb.SourceResolver{
			LoadAdvisories:     deps.loadAdvisories,
			LoadAdvisoryBundle: deps.loadAdvisoryBundle,
			LoadOSVSource:      deps.loadOSVSource,
			LoadAlpineSecDB:    deps.loadAlpineSecDB,
			LoadDebianTracker:  deps.loadDebianTracker,
			LoadUbuntuNotices:  deps.loadUbuntuNotices,
			LoadKubernetesFeed: deps.loadKubernetesFeed,
		})
		if err != nil {
			fmt.Fprintf(stderr, "resolve source manifest: %v\n", err)
			return 1
		}
	} else if *advisoriesBundleFile != "" {
		loaded, loadErr := deps.loadAdvisoryBundle(*advisoriesBundleFile, *bundleKeyFile)
		err = loadErr
		if err != nil {
			fmt.Fprintf(stderr, "load advisories bundle: %v\n", err)
			return 1
		}
		advisories.Advisories = append(advisories.Advisories, loaded.Advisories...)
	} else {
		if *advisoriesFile != "" {
			loaded, loadErr := deps.loadAdvisories(*advisoriesFile)
			err = loadErr
			if err != nil {
				fmt.Fprintf(stderr, "load advisories: %v\n", err)
				return 1
			}
			advisories.Advisories = append(advisories.Advisories, loaded.Advisories...)
		}
	}
	for _, source := range osvSources {
		loaded, err := deps.loadOSVSource(source)
		if err != nil {
			fmt.Fprintf(stderr, "load osv source: %v\n", err)
			return 1
		}
		advisories.Advisories = append(advisories.Advisories, loaded.Advisories...)
	}

	if err := deps.writeDB(*out, advisories); err != nil {
		fmt.Fprintf(stderr, "write advisory db: %v\n", err)
		return 1
	}
	if *metadataOut != "" {
		info, err := deps.inspectDB(*out)
		if err != nil {
			fmt.Fprintf(stderr, "inspect advisory db: %v\n", err)
			return 1
		}
		metadata, err := deps.buildMetadata(*out, info)
		if err != nil {
			fmt.Fprintf(stderr, "build db metadata: %v\n", err)
			return 1
		}
		if err := deps.writeMetadata(*metadataOut, metadata); err != nil {
			fmt.Fprintf(stderr, "write db metadata: %v\n", err)
			return 1
		}
	}
	_, _ = fmt.Fprintf(stdout, "wrote vulnerability database to %s (%d advisories)\n", *out, len(advisories.Advisories))
	return 0
}

func runDBInfo(args []string, stdout, stderr io.Writer, deps dbDeps) int {
	fs := flag.NewFlagSet("db info", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "", "path to a vulnerability sqlite database")
	format := fs.String("format", "table", "output format: table or json")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "--db is required")
		return 2
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}

	info, err := deps.inspectDB(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "inspect advisory db: %v\n", err)
		return 1
	}

	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(info); err != nil {
			fmt.Fprintf(stderr, "write json: %v\n", err)
			return 1
		}
		return 0
	}

	_, _ = fmt.Fprintf(stdout, "Kubescan Vulnerability DB\n")
	_, _ = fmt.Fprintf(stdout, "Schema: %s\n", info.Schema)
	_, _ = fmt.Fprintf(stdout, "Schema Version: %s\n", info.SchemaVersion)
	_, _ = fmt.Fprintf(stdout, "Bundle API Version: %s\n", info.BundleAPIVersion)
	_, _ = fmt.Fprintf(stdout, "Bundle Kind: %s\n", info.BundleKind)
	_, _ = fmt.Fprintf(stdout, "Advisories: %d\n", info.AdvisoryCount)
	_, _ = fmt.Fprintf(stdout, "Built At: %s\n", info.BuiltAt.Format("2006-01-02T15:04:05Z07:00"))
	return 0
}

func runDBVerify(args []string, stdout, stderr io.Writer, deps dbDeps) int {
	fs := flag.NewFlagSet("db verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "", "path to a vulnerability sqlite database")
	metadataPath := fs.String("metadata", "", "path to artifact metadata JSON")
	signaturePath := fs.String("signature", "", "path to detached base64 signature")
	keyPath := fs.String("key", "", "path to an Ed25519 public key for db signature verification")
	bundlePath := fs.String("bundle", "", "path to a Sigstore bundle for vulnerability db verification")
	trustedRootPath := fs.String("trusted-root", "", "path to a Sigstore trusted_root.json override")
	tufCachePath := fs.String("tuf-cache", "", "override path for the Sigstore TUF cache")
	tufMirror := fs.String("tuf-mirror", "", "override Sigstore TUF mirror URL")
	certificateIdentity := fs.String("certificate-identity", "", "expected signing certificate identity")
	certificateIdentityRegexp := fs.String("certificate-identity-regexp", "", "expected signing certificate identity regex")
	certificateOIDCIssuer := fs.String("certificate-oidc-issuer", "", "expected signing certificate OIDC issuer")
	certificateOIDCIssuerRegexp := fs.String("certificate-oidc-issuer-regexp", "", "expected signing certificate OIDC issuer regex")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dbPath == "" {
		fmt.Fprintln(stderr, "--db is required")
		return 2
	}
	if (*signaturePath != "" || *keyPath != "") && (*signaturePath == "" || *keyPath == "") {
		fmt.Fprintln(stderr, "--signature and --key must be provided together")
		return 2
	}
	if *metadataPath == "" && *signaturePath == "" && *bundlePath == "" {
		fmt.Fprintln(stderr, "at least one of --metadata, --signature, or --bundle is required")
		return 2
	}

	if err := deps.verifyArtifact(vulndb.VerifyOptions{
		DBPath:        *dbPath,
		MetadataPath:  *metadataPath,
		SignaturePath: *signaturePath,
		KeyPath:       *keyPath,
		Sigstore: vulndb.SigstoreVerifyOptions{
			BundlePath:                  *bundlePath,
			TrustedRootPath:             *trustedRootPath,
			TUFCachePath:                *tufCachePath,
			TUFMirror:                   *tufMirror,
			CertificateIdentity:         *certificateIdentity,
			CertificateIdentityRegexp:   *certificateIdentityRegexp,
			CertificateOIDCIssuer:       *certificateOIDCIssuer,
			CertificateOIDCIssuerRegexp: *certificateOIDCIssuerRegexp,
		},
	}); err != nil {
		fmt.Fprintf(stderr, "verify advisory db: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "vulnerability db verified")
	return 0
}

func runDBUpdate(args []string, stdout, stderr io.Writer, deps dbDeps) int {
	fs := flag.NewFlagSet("db update", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbURL := fs.String("url", "", "remote URL for the vulnerability sqlite database")
	metadataURL := fs.String("metadata-url", "", "remote URL for artifact metadata JSON")
	signatureURL := fs.String("signature-url", "", "remote URL for detached base64 signature")
	keyPath := fs.String("key", "", "path to an Ed25519 public key for downloaded db signature verification")
	bundleURL := fs.String("bundle-url", "", "remote URL for a Sigstore bundle JSON for the downloaded db")
	trustedRootPath := fs.String("trusted-root", "", "path to a Sigstore trusted_root.json override")
	tufCachePath := fs.String("tuf-cache", "", "override path for the Sigstore TUF cache")
	tufMirror := fs.String("tuf-mirror", "", "override Sigstore TUF mirror URL")
	certificateIdentity := fs.String("certificate-identity", "", "expected signing certificate identity")
	certificateIdentityRegexp := fs.String("certificate-identity-regexp", "", "expected signing certificate identity regex")
	certificateOIDCIssuer := fs.String("certificate-oidc-issuer", "", "expected signing certificate OIDC issuer")
	certificateOIDCIssuerRegexp := fs.String("certificate-oidc-issuer-regexp", "", "expected signing certificate OIDC issuer regex")
	out := fs.String("out", "", "output sqlite database path")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dbURL == "" || *out == "" {
		fmt.Fprintln(stderr, "--url and --out are required")
		return 2
	}
	if (*signatureURL != "" || *keyPath != "") && (*signatureURL == "" || *keyPath == "") {
		fmt.Fprintln(stderr, "--signature-url and --key must be provided together")
		return 2
	}

	if err := deps.downloadDB(vulndb.DownloadOptions{
		DBURL:        *dbURL,
		MetadataURL:  *metadataURL,
		SignatureURL: *signatureURL,
		KeyPath:      *keyPath,
		BundleURL:    *bundleURL,
		OutPath:      *out,
		Sigstore: vulndb.SigstoreVerifyOptions{
			TrustedRootPath:             *trustedRootPath,
			TUFCachePath:                *tufCachePath,
			TUFMirror:                   *tufMirror,
			CertificateIdentity:         *certificateIdentity,
			CertificateIdentityRegexp:   *certificateIdentityRegexp,
			CertificateOIDCIssuer:       *certificateOIDCIssuer,
			CertificateOIDCIssuerRegexp: *certificateOIDCIssuerRegexp,
		},
	}); err != nil {
		fmt.Fprintf(stderr, "update advisory db: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "downloaded vulnerability db to %s\n", *out)
	return 0
}
