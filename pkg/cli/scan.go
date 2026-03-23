package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/term"
	"kubescan/internal/bundle"
	"kubescan/pkg/attackpath"
	"kubescan/pkg/k8s"
	"kubescan/pkg/ocsf"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/vuln"
)

type clusterCollectFunc func(context.Context, k8s.ClusterOptions) (policy.Inventory, error)

type scanDeps struct {
	loadFromFile       func(string) (policy.Inventory, error)
	loadFromBytes      func([]byte) (policy.Inventory, error)
	loadPolicy         func(string) (policy.Controls, error)
	loadPolicyBundle   func(string, string) (policy.Controls, error)
	loadRuleBundle     func(string, string) (policy.RuleBundle, error)
	loadSBOM           func(string) (vuln.SBOM, error)
	loadAdvisories     func(string) (vuln.AdvisoryBundle, error)
	loadAdvisoryBundle func(string, string) (vuln.AdvisoryBundle, error)
	renderHelm         func(string, string, string, []string) ([]byte, error)
	renderKustomize    func(string) ([]byte, error)
	collect            clusterCollectFunc
	openOutput         func(string) (io.WriteCloser, error)
}

type stringFlags []string

func (s *stringFlags) String() string {
	return strings.Join(*s, ",")
}

func (s *stringFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func RunScan(args []string, stdout, stderr io.Writer) int {
	return runScan(args, stdout, stderr, scanDeps{
		loadFromFile:       loadInventoryFromFile,
		loadFromBytes:      loadInventoryFromBytes,
		loadPolicy:         policy.LoadControls,
		loadPolicyBundle:   bundle.LoadSignedPolicyControls,
		loadRuleBundle:     bundle.LoadSignedRuleBundle,
		loadSBOM:           vuln.LoadSBOM,
		loadAdvisories:     vuln.LoadAdvisories,
		loadAdvisoryBundle: bundle.LoadSignedAdvisories,
		renderHelm:         renderHelmChart,
		renderKustomize:    renderKustomizeDir,
		collect:            collectClusterInventory,
		openOutput:         openOutputFile,
	})
}

func runScan(args []string, stdout, stderr io.Writer, deps scanDeps) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	input := fs.String("input", "", "path to a Kubernetes manifest file")
	helmChart := fs.String("helm-chart", "", "path to a Helm chart directory to render and scan")
	var helmValues stringFlags
	fs.Var(&helmValues, "helm-values", "path to a Helm values file; repeat for multiple values files")
	helmRelease := fs.String("helm-release", "kubescan", "Helm release name to use for rendering")
	helmNamespace := fs.String("helm-namespace", "default", "Helm namespace to use for rendering")
	kustomizeDir := fs.String("kustomize-dir", "", "path to a Kustomize directory to render and scan")
	policyFile := fs.String("policy", "", "path to a policy controls file")
	policyBundleFile := fs.String("policy-bundle", "", "path to a signed policy controls bundle file")
	rulesBundleFile := fs.String("rules-bundle", "", "path to a signed rule bundle file")
	var sbomFiles stringFlags
	fs.Var(&sbomFiles, "sbom", "path to a CycloneDX JSON SBOM file; repeat --sbom for multiple images")
	var includeKinds stringFlags
	var excludeKinds stringFlags
	var includeNamespaces stringFlags
	var excludeNamespaces stringFlags
	fs.Var(&includeKinds, "include-kind", "only scan these resource kinds; repeat or use comma-separated values")
	fs.Var(&excludeKinds, "exclude-kind", "exclude these resource kinds; repeat or use comma-separated values")
	fs.Var(&includeNamespaces, "include-namespace", "only scan these namespaces; repeat or use comma-separated values")
	fs.Var(&excludeNamespaces, "exclude-namespace", "exclude these namespaces; repeat or use comma-separated values")
	advisoriesFile := fs.String("advisories", "", "path to an advisory bundle file")
	advisoriesBundleFile := fs.String("advisories-bundle", "", "path to a signed advisory bundle file")
	componentVulnsEnabled := fs.Bool("component-vulns", false, "match live cluster control-plane and node components against advisories")
	bundleKeyFile := fs.String("bundle-key", "", "path to an Ed25519 public key for signed bundle verification")
	ruleProfileName := fs.String("profile", string(policy.RuleProfileDefault), "built-in rule profile: default, hardening, or enterprise")
	format := fs.String("format", "table", "output format: table, json, html, sarif, or ocsf-json")
	reportMode := fs.String("report", "all", "report mode: all or summary")
	colorMode := fs.String("color", "auto", "terminal color mode for table output: auto, always, or never")
	attackPathsEnabled := fs.Bool("attack-paths", false, "analyze and report attack paths from the collected Kubernetes graph")
	out := fs.String("out", "", "write output to a file instead of stdout")
	failOn := fs.String("fail-on", "", "fail the scan when any finding meets or exceeds this severity: low, medium, high, critical")
	complianceName := fs.String("compliance", "", "compliance profile to evaluate: k8s-cis, nsa, pss-restricted")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig file")
	contextName := fs.String("context", "", "kubeconfig context to use")
	namespace := fs.String("namespace", "", "namespace to scan; defaults to all namespaces")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	explicitSources := 0
	if *input != "" {
		explicitSources++
	}
	if *helmChart != "" {
		explicitSources++
	}
	if *kustomizeDir != "" {
		explicitSources++
	}
	if explicitSources > 1 {
		fmt.Fprintln(stderr, "--input, --helm-chart, and --kustomize-dir are mutually exclusive")
		return 2
	}
	if explicitSources > 0 && (*kubeconfig != "" || *contextName != "" || *namespace != "") {
		fmt.Fprintln(stderr, "file, Helm, and Kustomize sources cannot be combined with cluster scan flags")
		return 2
	}
	if *componentVulnsEnabled && explicitSources > 0 {
		fmt.Fprintln(stderr, "--component-vulns is only supported for live cluster scans")
		return 2
	}
	if *policyFile != "" && *policyBundleFile != "" {
		fmt.Fprintln(stderr, "--policy and --policy-bundle cannot be used together")
		return 2
	}
	if *advisoriesFile != "" && *advisoriesBundleFile != "" {
		fmt.Fprintln(stderr, "--advisories and --advisories-bundle cannot be used together")
		return 2
	}
	if len(sbomFiles) > 0 && *advisoriesFile == "" && *advisoriesBundleFile == "" {
		fmt.Fprintln(stderr, "--sbom requires --advisories or --advisories-bundle")
		return 2
	}
	if *componentVulnsEnabled && *advisoriesFile == "" && *advisoriesBundleFile == "" {
		fmt.Fprintln(stderr, "--component-vulns requires --advisories or --advisories-bundle")
		return 2
	}
	if len(sbomFiles) == 0 && !*componentVulnsEnabled && (*advisoriesFile != "" || *advisoriesBundleFile != "") {
		fmt.Fprintln(stderr, "--advisories and --advisories-bundle require at least one --sbom or --component-vulns")
		return 2
	}
	if (*advisoriesBundleFile != "" || *policyBundleFile != "") && *bundleKeyFile == "" {
		fmt.Fprintln(stderr, "--policy-bundle and --advisories-bundle require --bundle-key")
		return 2
	}
	if *rulesBundleFile != "" && *bundleKeyFile == "" {
		fmt.Fprintln(stderr, "--rules-bundle requires --bundle-key")
		return 2
	}
	if *bundleKeyFile != "" && *advisoriesBundleFile == "" && *policyBundleFile == "" && *rulesBundleFile == "" {
		fmt.Fprintln(stderr, "--bundle-key requires --policy-bundle, --rules-bundle, or --advisories-bundle")
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
	if *reportMode == "summary" && *format == "sarif" {
		fmt.Fprintln(stderr, "--report summary is not supported with --format sarif")
		return 2
	}
	if *reportMode == "summary" && *format == "ocsf-json" {
		fmt.Fprintln(stderr, "--report summary is not supported with --format ocsf-json")
		return 2
	}
	if *attackPathsEnabled && *format == "sarif" {
		fmt.Fprintln(stderr, "--attack-paths is not supported with --format sarif")
		return 2
	}
	if *attackPathsEnabled && *format == "ocsf-json" {
		fmt.Fprintln(stderr, "--attack-paths is not supported with --format ocsf-json")
		return 2
	}
	ruleProfile, err := policy.ParseRuleProfile(*ruleProfileName)
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
	var complianceProfile *policy.ComplianceProfile
	if *complianceName != "" {
		profile, err := policy.ParseComplianceProfile(*complianceName)
		if err != nil {
			fmt.Fprintf(stderr, "parse compliance profile: %v\n", err)
			return 2
		}
		complianceProfile = &profile
	}

	var (
		inventory policy.Inventory
	)
	if *input != "" {
		inventory, err = deps.loadFromFile(*input)
		if err != nil {
			fmt.Fprintf(stderr, "load inventory: %v\n", err)
			return 1
		}
	} else if *helmChart != "" {
		content, err := deps.renderHelm(*helmChart, *helmRelease, *helmNamespace, helmValues)
		if err != nil {
			fmt.Fprintf(stderr, "render helm chart: %v\n", err)
			return 1
		}
		inventory, err = deps.loadFromBytes(content)
		if err != nil {
			fmt.Fprintf(stderr, "load rendered inventory: %v\n", err)
			return 1
		}
	} else if *kustomizeDir != "" {
		content, err := deps.renderKustomize(*kustomizeDir)
		if err != nil {
			fmt.Fprintf(stderr, "render kustomize: %v\n", err)
			return 1
		}
		inventory, err = deps.loadFromBytes(content)
		if err != nil {
			fmt.Fprintf(stderr, "load rendered inventory: %v\n", err)
			return 1
		}
	} else {
		inventory, err = deps.collect(context.Background(), k8s.ClusterOptions{
			Kubeconfig: *kubeconfig,
			Context:    *contextName,
			Namespace:  *namespace,
		})
		if err != nil {
			fmt.Fprintf(stderr, "collect inventory: %v\n", err)
			return 1
		}
	}
	inventory = policy.ApplyInventoryFilter(inventory, policy.InventoryFilter{
		IncludeKinds:      includeKinds,
		ExcludeKinds:      excludeKinds,
		IncludeNamespaces: includeNamespaces,
		ExcludeNamespaces: excludeNamespaces,
	})

	var ruleBundle *policy.RuleBundle
	if *rulesBundleFile != "" {
		loadedBundle, err := deps.loadRuleBundle(*rulesBundleFile, *bundleKeyFile)
		if err != nil {
			fmt.Fprintf(stderr, "load rule bundle: %v\n", err)
			return 1
		}
		ruleBundle = &loadedBundle
	}

	var controls *policy.Controls
	if *policyFile != "" || *policyBundleFile != "" {
		var loadedControls policy.Controls
		if *policyBundleFile != "" {
			loadedControls, err = deps.loadPolicyBundle(*policyBundleFile, *bundleKeyFile)
			if err != nil {
				fmt.Fprintf(stderr, "load policy bundle: %v\n", err)
				return 1
			}
		} else {
			loadedControls, err = deps.loadPolicy(*policyFile)
			if err != nil {
				fmt.Fprintf(stderr, "load policy controls: %v\n", err)
				return 1
			}
		}
		controls = &loadedControls
	}

	findings := evaluateRulesForProfile(inventory, ruleProfile, ruleBundle)
	if len(sbomFiles) > 0 || *componentVulnsEnabled {
		var advisories vuln.AdvisoryBundle
		if *advisoriesBundleFile != "" {
			advisories, err = deps.loadAdvisoryBundle(*advisoriesBundleFile, *bundleKeyFile)
			if err != nil {
				fmt.Fprintf(stderr, "load advisories bundle: %v\n", err)
				return 1
			}
		} else {
			advisories, err = deps.loadAdvisories(*advisoriesFile)
			if err != nil {
				fmt.Fprintf(stderr, "load advisories: %v\n", err)
				return 1
			}
		}
		if len(sbomFiles) > 0 {
			sboms, err := vuln.LoadSBOMIndex(sbomFiles, deps.loadSBOM)
			if err != nil {
				fmt.Fprintf(stderr, "load sbom: %v\n", err)
				return 1
			}
			findings = append(findings, vuln.MatchInventory(inventory, sboms, advisories, time.Now().UTC())...)
		}
		if *componentVulnsEnabled {
			findings = append(findings, vuln.MatchClusterComponents(inventory, advisories, time.Now().UTC())...)
		}
	}
	if controls != nil {
		findings, err = policy.ApplyControls(findings, *controls, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(stderr, "apply policy controls: %v\n", err)
			return 1
		}
	}
	var complianceReport *policy.ComplianceReport
	if complianceProfile != nil {
		complianceFindings := evaluateRulesForProfile(inventory, policy.RuleProfileEnterprise, ruleBundle)
		if controls != nil {
			complianceFindings, err = policy.ApplyControls(complianceFindings, *controls, time.Now().UTC())
			if err != nil {
				fmt.Fprintf(stderr, "apply policy controls for compliance: %v\n", err)
				return 1
			}
		}
		compliance := policy.EvaluateCompliance(*complianceProfile, complianceFindings)
		complianceReport = &compliance
	}
	var attackPaths []attackpath.Result
	if *attackPathsEnabled {
		attackPaths = attackpath.Analyze(inventory, findings)
	}
	result := report.BuildScanResultWithAttackPathsAndCompliance(findings, attackPaths, complianceReport)

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
	tableOptions := report.TableOptions{
		Color: shouldUseColor(*colorMode, output),
	}

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

func evaluateRulesForProfile(inventory policy.Inventory, profile policy.RuleProfile, ruleBundle *policy.RuleBundle) []policy.Finding {
	if ruleBundle != nil {
		return policy.EvaluateWithProfileAndBundle(inventory, profile, *ruleBundle)
	}
	return policy.EvaluateWithProfile(inventory, profile)
}

func loadInventoryFromFile(path string) (policy.Inventory, error) {
	file, err := os.Open(path)
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("open input: %w", err)
	}
	defer file.Close()

	inventory, err := k8s.LoadInventory(file)
	if err != nil {
		return policy.Inventory{}, err
	}
	return inventory, nil
}

func loadInventoryFromBytes(content []byte) (policy.Inventory, error) {
	return k8s.LoadInventory(strings.NewReader(string(content)))
}

func collectClusterInventory(ctx context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
	collector, err := k8s.NewCollectorFromOptions(options)
	if err != nil {
		return policy.Inventory{}, err
	}
	return collector.Collect(ctx, options.Namespace)
}

func openOutputFile(path string) (io.WriteCloser, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func renderHelmChart(chartPath, releaseName, namespace string, valuesFiles []string) ([]byte, error) {
	args := []string{"template", releaseName, chartPath, "--namespace", namespace}
	for _, valuesFile := range valuesFiles {
		args = append(args, "--values", valuesFile)
	}
	cmd := exec.Command("helm", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func renderKustomizeDir(path string) ([]byte, error) {
	candidates := [][]string{
		{"kustomize", "build", path},
		{"kubectl", "kustomize", path},
	}
	for _, candidate := range candidates {
		cmd := exec.Command(candidate[0], candidate[1:]...)
		output, err := cmd.CombinedOutput()
		if err == nil {
			return output, nil
		}
		if _, lookPathErr := exec.LookPath(candidate[0]); lookPathErr != nil {
			continue
		}
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil, fmt.Errorf("kustomize renderer not available; install kustomize or kubectl")
}

func shouldUseColor(mode string, writer io.Writer) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default:
		type fdWriter interface {
			Fd() uintptr
		}
		file, ok := writer.(fdWriter)
		return ok && term.IsTerminal(int(file.Fd()))
	}
}
