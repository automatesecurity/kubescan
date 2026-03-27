package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"kubescan/internal/bundle"
	"kubescan/pkg/imagescan"
	"kubescan/pkg/licensescan"
	"kubescan/pkg/ocsf"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/secretscan"
	"kubescan/pkg/vuln"
	"kubescan/pkg/vulndb"
)

type imageInspectWithAuthFunc func(context.Context, string, imagescan.AuthOptions) (imagescan.Metadata, error)
type imageLayerScanFunc func(context.Context, string, imagescan.AuthOptions, imagescan.LayerScanOptions, time.Time) ([]policy.Finding, error)
type sbomWriteFunc func(io.Writer, vuln.SBOM) error

type imageDeps struct {
	inspect            imageInspectWithAuthFunc
	scanLayers         imageLayerScanFunc
	extractSBOM        func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error)
	writeCycloneDX     sbomWriteFunc
	writeSPDX          sbomWriteFunc
	loadSBOM           func(string) (vuln.SBOM, error)
	loadAdvisories     func(string) (vuln.AdvisoryBundle, error)
	loadAdvisoryDB     func(string) (vuln.AdvisoryBundle, error)
	loadAdvisoryBundle func(string, string) (vuln.AdvisoryBundle, error)
	openOutput         func(string) (io.WriteCloser, error)
	stdin              io.Reader
}

func RunImage(args []string, stdout, stderr io.Writer) int {
	return runImage(args, stdout, stderr, imageDeps{
		inspect:            imagescan.InspectRemoteWithAuth,
		scanLayers:         imagescan.ScanRemoteLayersWithAuth,
		extractSBOM:        imagescan.ExtractRemoteSBOMWithAuth,
		writeCycloneDX:     vuln.WriteCycloneDX,
		writeSPDX:          vuln.WriteSPDX,
		loadSBOM:           vuln.LoadSBOM,
		loadAdvisories:     vuln.LoadAdvisories,
		loadAdvisoryDB:     vulndb.Load,
		loadAdvisoryBundle: bundle.LoadSignedAdvisories,
		openOutput:         openOutputFile,
		stdin:              os.Stdin,
	})
}

func runImage(args []string, stdout, stderr io.Writer, deps imageDeps) int {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	fs.SetOutput(stderr)

	imageRef := fs.String("image", "", "OCI image reference to inspect")
	scanLayers := fs.Bool("scan-layers", false, "scan unpacked image layers for secrets and declared licenses")
	registryUsername := fs.String("registry-username", "", "registry username for authenticated image access")
	registryPassword := fs.String("registry-password", "", "registry password for authenticated image access")
	registryPasswordStdin := fs.Bool("registry-password-stdin", false, "read the registry password from stdin")
	registryToken := fs.String("registry-token", "", "registry bearer token for authenticated image access")
	sbomFile := fs.String("sbom", "", "path to a CycloneDX JSON SBOM file for the image")
	sbomOut := fs.String("sbom-out", "", "write extracted image package inventory as a CycloneDX JSON SBOM file")
	sbomFormat := fs.String("sbom-format", "cyclonedx", "SBOM output format for --sbom-out: cyclonedx or spdx")
	advisoriesFile := fs.String("advisories", "", "path to an advisory bundle file")
	advisoriesDBFile := fs.String("advisories-db", "", "path to a local vulnerability sqlite database")
	advisoriesBundleFile := fs.String("advisories-bundle", "", "path to a signed advisory bundle file")
	bundleKeyFile := fs.String("bundle-key", "", "path to an Ed25519 public key for signed bundle verification")
	secretScanModeName := fs.String("secret-scan", string(secretscan.ModeBalanced), "secret scan mode for image layers: patterns, balanced, or aggressive")
	format := fs.String("format", "table", "output format: table, json, html, sarif, or ocsf-json")
	colorMode := fs.String("color", "auto", "terminal color mode for table output: auto, always, or never")
	out := fs.String("out", "", "write output to a file instead of stdout")
	failOn := fs.String("fail-on", "", "fail the scan when any finding meets or exceeds this severity: low, medium, high, critical")
	var licenseAllow multiStringFlag
	var licenseDeny multiStringFlag
	fs.Var(&licenseAllow, "license-allow", "approved SPDX license identifier for image-layer license checks; repeat for multiple values")
	fs.Var(&licenseDeny, "license-deny", "disallowed SPDX license identifier for image-layer license checks; repeat for multiple values")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *imageRef == "" {
		fmt.Fprintln(stderr, "--image is required")
		return 2
	}
	if *registryPassword != "" && *registryPasswordStdin {
		fmt.Fprintln(stderr, "--registry-password and --registry-password-stdin cannot be used together")
		return 2
	}
	if *registryToken != "" && (*registryUsername != "" || *registryPassword != "" || *registryPasswordStdin) {
		fmt.Fprintln(stderr, "--registry-token cannot be combined with username/password registry auth")
		return 2
	}
	if *registryUsername != "" && *registryPassword == "" && !*registryPasswordStdin {
		fmt.Fprintln(stderr, "--registry-username requires --registry-password or --registry-password-stdin")
		return 2
	}
	if (*registryPassword != "" || *registryPasswordStdin) && *registryUsername == "" {
		fmt.Fprintln(stderr, "registry password auth requires --registry-username")
		return 2
	}
	advisoryInputs := 0
	if *advisoriesFile != "" {
		advisoryInputs++
	}
	if *advisoriesDBFile != "" {
		advisoryInputs++
	}
	if *advisoriesBundleFile != "" {
		advisoryInputs++
	}
	if advisoryInputs > 1 {
		fmt.Fprintln(stderr, "--advisories, --advisories-db, and --advisories-bundle cannot be used together")
		return 2
	}
	if *sbomFile != "" && advisoryInputs == 0 {
		fmt.Fprintln(stderr, "--sbom requires --advisories, --advisories-db, or --advisories-bundle")
		return 2
	}
	if *sbomFile != "" && *sbomOut != "" {
		fmt.Fprintln(stderr, "--sbom and --sbom-out cannot be used together for image scans")
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
	if !*scanLayers && (*secretScanModeName != string(secretscan.ModeBalanced) || len(licenseAllow) > 0 || len(licenseDeny) > 0) {
		fmt.Fprintln(stderr, "--secret-scan, --license-allow, and --license-deny require --scan-layers for image scans")
		return 2
	}
	if *colorMode != "auto" && *colorMode != "always" && *colorMode != "never" {
		fmt.Fprintf(stderr, "unsupported color mode %q\n", *colorMode)
		return 2
	}
	if *sbomFormat != "cyclonedx" && *sbomFormat != "spdx" {
		fmt.Fprintf(stderr, "unsupported sbom format %q\n", *sbomFormat)
		return 2
	}
	if *out != "" && *sbomOut != "" && *out == *sbomOut {
		fmt.Fprintln(stderr, "--out and --sbom-out must be different files")
		return 2
	}

	secretScanMode, err := secretscan.ParseMode(*secretScanModeName)
	if err != nil {
		fmt.Fprintf(stderr, "parse secret scan mode: %v\n", err)
		return 2
	}
	var failThreshold policy.Severity
	if *failOn != "" {
		failThreshold, err = policy.ParseSeverity(*failOn)
		if err != nil {
			fmt.Fprintf(stderr, "parse fail-on severity: %v\n", err)
			return 2
		}
	}

	auth := imagescan.AuthOptions{
		Username: strings.TrimSpace(*registryUsername),
		Password: *registryPassword,
		Token:    strings.TrimSpace(*registryToken),
	}
	if *registryPasswordStdin {
		if deps.stdin == nil {
			fmt.Fprintln(stderr, "stdin is not configured")
			return 1
		}
		passwordBytes, err := io.ReadAll(deps.stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read registry password from stdin: %v\n", err)
			return 1
		}
		auth.Password = strings.TrimRight(string(passwordBytes), "\r\n")
	}

	metadata, err := deps.inspect(context.Background(), *imageRef, auth)
	if err != nil {
		fmt.Fprintf(stderr, "inspect image: %v\n", err)
		return 1
	}

	findings := imagescan.Evaluate(metadata, time.Now().UTC())
	if *scanLayers {
		if deps.scanLayers == nil {
			fmt.Fprintln(stderr, "image layer scanning is not configured")
			return 1
		}
		layerFindings, err := deps.scanLayers(context.Background(), *imageRef, auth, imagescan.LayerScanOptions{
			LicensePolicy: licensescan.Policy{
				Allowlist: []string(licenseAllow),
				Denylist:  []string(licenseDeny),
			},
			SecretScanMode: secretScanMode,
		}, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(stderr, "scan image layers: %v\n", err)
			return 1
		}
		findings = append(findings, layerFindings...)
	}

	var extractedSBOM *vuln.SBOM
	if *sbomOut != "" || (advisoryInputs > 0 && *sbomFile == "") {
		if deps.extractSBOM == nil {
			fmt.Fprintln(stderr, "image package extraction is not configured")
			return 1
		}
		sbom, err := deps.extractSBOM(context.Background(), metadata.Reference, auth)
		if err != nil {
			fmt.Fprintf(stderr, "extract image packages: %v\n", err)
			return 1
		}
		extractedSBOM = &sbom
	}
	if *sbomOut != "" {
		writer := deps.writeCycloneDX
		if *sbomFormat == "spdx" {
			writer = deps.writeSPDX
		}
		if writer == nil {
			fmt.Fprintln(stderr, "sbom writing is not configured")
			return 1
		}
		file, err := deps.openOutput(*sbomOut)
		if err != nil {
			fmt.Fprintf(stderr, "open sbom output: %v\n", err)
			return 1
		}
		if err := writer(file, *extractedSBOM); err != nil {
			_ = file.Close()
			fmt.Fprintf(stderr, "write sbom: %v\n", err)
			return 1
		}
		if err := file.Close(); err != nil {
			fmt.Fprintf(stderr, "close sbom output: %v\n", err)
			return 1
		}
	}
	if *sbomFile != "" || advisoryInputs > 0 {
		var advisories vuln.AdvisoryBundle
		if *advisoriesBundleFile != "" {
			advisories, err = deps.loadAdvisoryBundle(*advisoriesBundleFile, *bundleKeyFile)
			if err != nil {
				fmt.Fprintf(stderr, "load advisories bundle: %v\n", err)
				return 1
			}
		} else if *advisoriesDBFile != "" {
			advisories, err = deps.loadAdvisoryDB(*advisoriesDBFile)
			if err != nil {
				fmt.Fprintf(stderr, "load advisories db: %v\n", err)
				return 1
			}
		} else {
			advisories, err = deps.loadAdvisories(*advisoriesFile)
			if err != nil {
				fmt.Fprintf(stderr, "load advisories: %v\n", err)
				return 1
			}
		}

		var sbom vuln.SBOM
		if *sbomFile != "" {
			sbom, err = deps.loadSBOM(*sbomFile)
			if err != nil {
				fmt.Fprintf(stderr, "load sbom: %v\n", err)
				return 1
			}
		} else {
			sbom = *extractedSBOM
		}

		resource := policy.ResourceRef{Kind: "Image", Name: metadata.Reference}
		findings = append(findings, vuln.MatchImage(resource, metadata.Reference, sbom, advisories, time.Now().UTC())...)
	}

	result := report.BuildScanResult(findings)
	output := stdout
	if *out != "" {
		file, err := deps.openOutput(*out)
		if err != nil {
			fmt.Fprintf(stderr, "open output: %v\n", err)
			return 1
		}
		defer file.Close()
		output = file
	}
	tableOptions := report.TableOptions{Color: shouldUseColor(*colorMode, output)}

	switch *format {
	case "json":
		if err := report.WriteJSON(output, result); err != nil {
			fmt.Fprintf(stderr, "write json: %v\n", err)
			return 1
		}
	case "html":
		if err := report.WriteHTML(output, result); err != nil {
			fmt.Fprintf(stderr, "write html: %v\n", err)
			return 1
		}
	case "sarif":
		if err := report.WriteSARIF(output, result); err != nil {
			fmt.Fprintf(stderr, "write sarif: %v\n", err)
			return 1
		}
	case "ocsf-json":
		if err := ocsf.WriteJSON(output, result); err != nil {
			fmt.Fprintf(stderr, "write ocsf json: %v\n", err)
			return 1
		}
	case "table":
		if err := report.WriteTableWithOptions(output, result, tableOptions); err != nil {
			fmt.Fprintf(stderr, "write table: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}

	if failThreshold != "" {
		for _, finding := range findings {
			if policy.MeetsOrExceedsSeverity(finding.Severity, failThreshold) {
				return 4
			}
		}
		return 0
	}
	if len(findings) > 0 {
		return 3
	}
	return 0
}
