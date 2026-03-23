package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"kubescan/pkg/filescan"
	"kubescan/pkg/licensescan"
	"kubescan/pkg/ocsf"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/reposcan"
	"kubescan/pkg/secretscan"
)

type pathScanFunc func(string, policy.RuleProfile, filescan.Options, time.Time) ([]policy.Finding, error)
type repoCloneFunc func(string, reposcan.CloneOptions) (string, func(), error)

type pathScanDeps struct {
	scanPath   pathScanFunc
	openOutput func(string) (io.WriteCloser, error)
	cloneRepo  repoCloneFunc
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func RunFS(args []string, stdout, stderr io.Writer) int {
	return runPathScan("fs", "", args, stdout, stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			result, err := filescan.ScanPathWithOptions(path, profile, now, options)
			return result.Findings, err
		},
		openOutput: openOutputFile,
	})
}

func RunRepo(args []string, stdout, stderr io.Writer) int {
	return runPathScan("repo", ".", args, stdout, stderr, pathScanDeps{
		scanPath: func(path string, profile policy.RuleProfile, options filescan.Options, now time.Time) ([]policy.Finding, error) {
			result, err := filescan.ScanPathWithOptions(path, profile, now, options)
			return result.Findings, err
		},
		openOutput: openOutputFile,
		cloneRepo:  reposcan.CloneShallow,
	})
}

func runPathScan(command string, defaultPath string, args []string, stdout, stderr io.Writer, deps pathScanDeps) int {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)

	path := fs.String("path", defaultPath, "path to scan")
	profileName := fs.String("profile", string(policy.RuleProfileDefault), "built-in rule profile: default, hardening, or enterprise")
	format := fs.String("format", "table", "output format: table, json, html, sarif, or ocsf-json")
	reportMode := fs.String("report", "all", "report mode: all or summary")
	colorMode := fs.String("color", "auto", "terminal color mode for table output: auto, always, or never")
	out := fs.String("out", "", "write output to a file instead of stdout")
	failOn := fs.String("fail-on", "", "fail the scan when any finding meets or exceeds this severity: low, medium, high, critical")
	secretScanModeName := fs.String("secret-scan", string(secretscan.ModeBalanced), "secret scan mode: patterns, balanced, or aggressive")
	var repoURL *string
	var repoRef *string
	var gitSSHCommand *string
	var providerNative *bool
	var gitHTTPHeaders multiStringFlag
	var sparsePaths multiStringFlag
	if command == "repo" {
		repoURL = fs.String("url", "", "remote Git repository URL to clone and scan")
		repoRef = fs.String("ref", "", "branch, tag, or ref to fetch after cloning a remote repository")
		providerNative = fs.Bool("provider-native", false, "use provider-native repository retrieval when supported by the remote URL")
		gitSSHCommand = fs.String("git-ssh-command", "", "custom GIT_SSH_COMMAND for authenticated SSH repository access")
		fs.Var(&gitHTTPHeaders, "git-http-header", "extra HTTP header for authenticated Git HTTPS access; repeat for multiple values")
		fs.Var(&sparsePaths, "sparse-path", "limit remote repository retrieval to one path prefix or glob; repeat for multiple values")
	}
	var licenseAllow multiStringFlag
	var licenseDeny multiStringFlag
	var excludePaths multiStringFlag
	fs.Var(&licenseAllow, "license-allow", "approved SPDX license identifier; repeat for multiple values")
	fs.Var(&licenseDeny, "license-deny", "disallowed SPDX license identifier; repeat for multiple values")
	fs.Var(&excludePaths, "exclude-path", "exclude a path or glob pattern from filesystem or repository scanning; repeat for multiple values")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "--path is required")
		return 2
	}
	if command == "repo" && repoRef != nil && *repoRef != "" && repoURL != nil && *repoURL == "" {
		fmt.Fprintln(stderr, "--ref requires --url")
		return 2
	}
	if command == "repo" && providerNative != nil && *providerNative && repoURL != nil && *repoURL == "" {
		fmt.Fprintln(stderr, "--provider-native requires --url")
		return 2
	}
	if command == "repo" && gitSSHCommand != nil && *gitSSHCommand != "" && repoURL != nil && *repoURL == "" {
		fmt.Fprintln(stderr, "--git-ssh-command requires --url")
		return 2
	}
	if command == "repo" && len(gitHTTPHeaders) > 0 && repoURL != nil && *repoURL == "" {
		fmt.Fprintln(stderr, "--git-http-header requires --url")
		return 2
	}
	if command == "repo" && len(sparsePaths) > 0 && repoURL != nil && *repoURL == "" {
		fmt.Fprintln(stderr, "--sparse-path requires --url")
		return 2
	}
	if command == "repo" && repoURL != nil && *repoURL != "" && *path != defaultPath {
		fmt.Fprintln(stderr, "--path and --url cannot be used together")
		return 2
	}
	if *reportMode != "all" && *reportMode != "summary" {
		fmt.Fprintf(stderr, "unsupported report mode %q\n", *reportMode)
		return 2
	}
	if *colorMode != "auto" && *colorMode != "always" && *colorMode != "never" {
		fmt.Fprintf(stderr, "unsupported color mode %q\n", *colorMode)
		return 2
	}
	if *reportMode == "summary" && (*format == "sarif" || *format == "ocsf-json") {
		fmt.Fprintf(stderr, "--report summary is not supported with --format %s\n", *format)
		return 2
	}

	secretScanMode, err := secretscan.ParseMode(*secretScanModeName)
	if err != nil {
		fmt.Fprintf(stderr, "parse secret scan mode: %v\n", err)
		return 2
	}
	profile, err := policy.ParseRuleProfile(*profileName)
	if err != nil {
		fmt.Fprintf(stderr, "parse rule profile: %v\n", err)
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

	scanPath := *path
	cleanup := func() {}
	if command == "repo" && repoURL != nil && *repoURL != "" {
		if deps.cloneRepo == nil {
			fmt.Fprintln(stderr, "remote repository scanning is not configured")
			return 1
		}
		scanPath, cleanup, err = deps.cloneRepo(*repoURL, reposcan.CloneOptions{
			Ref:            *repoRef,
			HTTPHeaders:    []string(gitHTTPHeaders),
			SSHCommand:     *gitSSHCommand,
			SparsePaths:    []string(sparsePaths),
			ProviderNative: providerNative != nil && *providerNative,
		})
		if err != nil {
			fmt.Fprintf(stderr, "clone repository: %v\n", err)
			return 1
		}
		defer cleanup()
	}

	findings, err := deps.scanPath(scanPath, profile, filescan.Options{
		LicensePolicy: licensescan.Policy{
			Allowlist: []string(licenseAllow),
			Denylist:  []string(licenseDeny),
		},
		ExcludePaths:   []string(excludePaths),
		SecretScanMode: secretScanMode,
	}, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "scan path: %v\n", err)
		return 1
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
		if *reportMode == "summary" {
			result.Findings = nil
		}
		if err := report.WriteJSON(output, result); err != nil {
			fmt.Fprintf(stderr, "write json: %v\n", err)
			return 1
		}
	case "html":
		if *reportMode == "summary" {
			result.Findings = nil
		}
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
		writeTable := func(w io.Writer, result report.ScanResult) error {
			return report.WriteTableWithOptions(w, result, tableOptions)
		}
		if *reportMode == "summary" {
			writeTable = func(w io.Writer, result report.ScanResult) error {
				return report.WriteSummaryTableWithOptions(w, result, tableOptions)
			}
		}
		if err := writeTable(output, result); err != nil {
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
