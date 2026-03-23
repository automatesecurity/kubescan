package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kubescan/internal/buildinfo"
	"kubescan/internal/operator"
	"kubescan/pkg/k8s"
	"kubescan/pkg/policy"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 1 {
		switch args[0] {
		case "version", "--version", "-v":
			return writeVersion(os.Stdout, "kubescan-operator")
		}
	}

	fs := flag.NewFlagSet("kubescan-operator", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	interval := fs.Duration("interval", 15*time.Minute, "periodic scan interval")
	enableWatch := fs.Bool("watch", true, "enable watch-based rescans in addition to periodic full scans")
	watchDebounce := fs.Duration("watch-debounce", 10*time.Second, "debounce window for watch-triggered rescans")
	cycleTimeout := fs.Duration("cycle-timeout", 5*time.Minute, "maximum duration for a single scan cycle")
	reportTTL := fs.Duration("report-ttl", 0, "optional maximum age for managed ScanReports before they are pruned on full reconciliation (0 disables age-based pruning)")
	pruneStaleReports := fs.Bool("prune-stale-reports", false, "delete stale managed ScanReports that no longer match an active ScanPolicy during full reconciliation")
	maxFindings := fs.Int("max-findings", 250, "maximum number of findings to store per ScanReport")
	maxAttackPaths := fs.Int("max-attack-paths", 100, "maximum number of attack paths to store per ScanReport")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig file")
	contextName := fs.String("context", "", "kubeconfig context to use")
	namespace := fs.String("namespace", "", "default namespace scope for operator scans")
	namespacedOnly := fs.Bool("namespaced-only", false, "collect only namespace-scoped resources and skip cluster-scoped inventory such as nodes and cluster RBAC")
	defaultOnly := fs.Bool("default-only", false, "skip ScanPolicy discovery and use only the default operator flags")
	defaultProfileName := fs.String("profile", string(policy.RuleProfileHardening), "default rule profile when no ScanPolicy objects exist")
	defaultCompliance := fs.String("compliance", "", "default compliance profile when no ScanPolicy objects exist")
	defaultAttackPaths := fs.Bool("attack-paths", false, "enable attack-path analysis in the default policy when no ScanPolicy objects exist")
	defaultReportName := fs.String("report-name", "cluster-default", "report name to use when no ScanPolicy objects exist")
	once := fs.Bool("once", false, "run one scan cycle and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	defaultProfile, err := policy.ParseRuleProfile(*defaultProfileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse default rule profile: %v\n", err)
		return 2
	}
	if *defaultCompliance != "" {
		if _, err := policy.ParseComplianceProfile(*defaultCompliance); err != nil {
			fmt.Fprintf(os.Stderr, "parse default compliance profile: %v\n", err)
			return 2
		}
	}

	config, err := k8s.RESTConfigFromOptions(k8s.ClusterOptions{
		Kubeconfig: *kubeconfig,
		Context:    *contextName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build kubernetes config: %v\n", err)
		return 1
	}

	runner, err := operator.NewRunner(config, operator.Options{
		ClusterOptions: k8s.ClusterOptions{
			Kubeconfig:     *kubeconfig,
			Context:        *contextName,
			Namespace:      *namespace,
			NamespacedOnly: *namespacedOnly,
		},
		Watch:                *enableWatch,
		WatchDebounce:        *watchDebounce,
		Interval:             *interval,
		CycleTimeout:         *cycleTimeout,
		ReportTTL:            *reportTTL,
		PruneStaleReports:    *pruneStaleReports,
		MaxStoredFindings:    *maxFindings,
		MaxStoredAttackPaths: *maxAttackPaths,
		DefaultProfile:       defaultProfile,
		DefaultCompliance:    *defaultCompliance,
		DefaultAttackPaths:   *defaultAttackPaths,
		DefaultReportName:    *defaultReportName,
		DisablePolicyLookup:  *defaultOnly,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create operator runner: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := runner.RunOnce(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "run operator cycle: %v\n", err)
			return 1
		}
		return 0
	}

	if err := runner.Run(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "run operator: %v\n", err)
		return 1
	}
	return 0
}

func writeVersion(w io.Writer, name string) int {
	_, _ = fmt.Fprintln(w, buildinfo.Current(name).String())
	return 0
}
