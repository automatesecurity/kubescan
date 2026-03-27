package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"kubescan/internal/bundle"
	"kubescan/pkg/filescan"
	"kubescan/pkg/licensescan"
	"kubescan/pkg/ocsf"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/secretscan"
	"kubescan/pkg/vmscan"
	"kubescan/pkg/vuln"
	"kubescan/pkg/vulndb"
)

type vmDeps struct {
	resolveTarget      func(string, string) (vmscan.ResolvedTarget, error)
	scanResolvedRootFS func(vmscan.ResolvedTarget, policy.RuleProfile, time.Time, filescan.Options) ([]policy.Finding, error)
	extractSBOM        func(vmscan.ResolvedTarget) (vuln.SBOM, error)
	writeCycloneDX     sbomWriteFunc
	writeSPDX          sbomWriteFunc
	loadAdvisories     func(string) (vuln.AdvisoryBundle, error)
	loadAdvisoryDB     func(string) (vuln.AdvisoryBundle, error)
	loadAdvisoryBundle func(string, string) (vuln.AdvisoryBundle, error)
	openOutput         func(string) (io.WriteCloser, error)
}

func RunVM(args []string, stdout, stderr io.Writer) int {
	return runVM(args, stdout, stderr, vmDeps{
		resolveTarget:      vmscan.ResolveTarget,
		scanResolvedRootFS: vmscan.ScanResolvedRootFS,
		extractSBOM:        vmscan.ExtractSBOM,
		writeCycloneDX:     vuln.WriteCycloneDX,
		writeSPDX:          vuln.WriteSPDX,
		loadAdvisories:     vuln.LoadAdvisories,
		loadAdvisoryDB:     vulndb.Load,
		loadAdvisoryBundle: bundle.LoadSignedAdvisories,
		openOutput:         openOutputFile,
	})
}

func runVM(args []string, stdout, stderr io.Writer, deps vmDeps) int {
	fs := flag.NewFlagSet("vm", flag.ContinueOnError)
	fs.SetOutput(stderr)

	rootfs := fs.String("rootfs", "", "mounted or extracted VM root filesystem path to scan")
	disk := fs.String("disk", "", "VM disk, archive, or appliance path to scan directly (.qcow2, .vmdk, .vhd, .vhdx, .raw, .img, .ova, .tar, .tar.gz, .tgz)")
	profileName := fs.String("profile", string(policy.RuleProfileDefault), "built-in rule profile: default, hardening, or enterprise")
	secretScanModeName := fs.String("secret-scan", string(secretscan.ModeBalanced), "secret scan mode: patterns, balanced, or aggressive")
	advisoriesFile := fs.String("advisories", "", "path to an advisory bundle file")
	advisoriesDBFile := fs.String("advisories-db", "", "path to a local vulnerability sqlite database")
	advisoriesBundleFile := fs.String("advisories-bundle", "", "path to a signed advisory bundle file")
	bundleKeyFile := fs.String("bundle-key", "", "path to an Ed25519 public key for signed bundle verification")
	sbomOut := fs.String("sbom-out", "", "write extracted VM package inventory as a CycloneDX JSON SBOM file")
	sbomFormat := fs.String("sbom-format", "cyclonedx", "SBOM output format for --sbom-out: cyclonedx or spdx")
	format := fs.String("format", "table", "output format: table, json, html, sarif, or ocsf-json")
	colorMode := fs.String("color", "auto", "terminal color mode for table output: auto, always, or never")
	out := fs.String("out", "", "write output to a file instead of stdout")
	failOn := fs.String("fail-on", "", "fail the scan when any finding meets or exceeds this severity: low, medium, high, critical")
	var licenseAllow multiStringFlag
	var licenseDeny multiStringFlag
	var excludePaths multiStringFlag
	fs.Var(&licenseAllow, "license-allow", "approved SPDX license identifier; repeat for multiple values")
	fs.Var(&licenseDeny, "license-deny", "disallowed SPDX license identifier; repeat for multiple values")
	fs.Var(&excludePaths, "exclude-path", "exclude a path or glob pattern from rootfs scanning; repeat for multiple values")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rootfs == "" && *disk == "" {
		fmt.Fprintln(stderr, "either --rootfs or --disk is required")
		return 2
	}
	if *rootfs != "" && *disk != "" {
		fmt.Fprintln(stderr, "--rootfs and --disk cannot be used together")
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
	if *advisoriesBundleFile != "" && *bundleKeyFile == "" {
		fmt.Fprintln(stderr, "--advisories-bundle requires --bundle-key")
		return 2
	}
	if *bundleKeyFile != "" && *advisoriesBundleFile == "" {
		fmt.Fprintln(stderr, "--bundle-key requires --advisories-bundle")
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

	profile, err := policy.ParseRuleProfile(*profileName)
	if err != nil {
		fmt.Fprintf(stderr, "parse rule profile: %v\n", err)
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

	if deps.resolveTarget == nil || deps.scanResolvedRootFS == nil {
		fmt.Fprintln(stderr, "vm scanning is not configured")
		return 1
	}
	target, err := deps.resolveTarget(*rootfs, *disk)
	if err != nil {
		fmt.Fprintf(stderr, "resolve vm target: %v\n", err)
		return 1
	}
	defer target.Cleanup()

	findings, err := deps.scanResolvedRootFS(target, profile, time.Now().UTC(), filescan.Options{
		LicensePolicy: licensescan.Policy{
			Allowlist: []string(licenseAllow),
			Denylist:  []string(licenseDeny),
		},
		ExcludePaths:   []string(excludePaths),
		SecretScanMode: secretScanMode,
	})
	if err != nil {
		fmt.Fprintf(stderr, "scan vm target: %v\n", err)
		return 1
	}

	var extractedSBOM *vuln.SBOM
	if *sbomOut != "" || advisoryInputs > 0 {
		sbom, err := deps.extractSBOM(target)
		if err != nil {
			fmt.Fprintf(stderr, "extract vm packages: %v\n", err)
			return 1
		}
		extractedSBOM = &sbom
	}
	if *sbomOut != "" {
		writer := deps.writeCycloneDX
		if *sbomFormat == "spdx" {
			writer = deps.writeSPDX
		}
		file, err := deps.openOutput(*sbomOut)
		if err != nil {
			fmt.Fprintf(stderr, "open sbom output: %v\n", err)
			return 1
		}
		if writer == nil {
			_ = file.Close()
			fmt.Fprintln(stderr, "sbom writing is not configured")
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
	if advisoryInputs > 0 {
		var advisories vuln.AdvisoryBundle
		if *advisoriesBundleFile != "" {
			advisories, err = deps.loadAdvisoryBundle(*advisoriesBundleFile, *bundleKeyFile)
		} else if *advisoriesDBFile != "" {
			advisories, err = deps.loadAdvisoryDB(*advisoriesDBFile)
		} else {
			advisories, err = deps.loadAdvisories(*advisoriesFile)
		}
		if err != nil {
			fmt.Fprintf(stderr, "load advisories: %v\n", err)
			return 1
		}
		findings = append(findings, vuln.MatchImage(policy.ResourceRef{Kind: "VMRootFS", Name: target.SourceRef}, target.SourceRef, *extractedSBOM, advisories, time.Now().UTC())...)
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
