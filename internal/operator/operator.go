package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"kubescan/api/v1alpha1"
	"kubescan/internal/bundle"
	"kubescan/pkg/attackpath"
	"kubescan/pkg/imagescan"
	"kubescan/pkg/k8s"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/vuln"
)

var (
	scanPolicyGVR = schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "scanpolicies"}
	scanReportGVR = schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "scanreports"}
	sbomReportGVR = schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "sbomreports"}
	nodeReportGVR = schema.GroupVersionResource{Group: v1alpha1.GroupName, Version: v1alpha1.Version, Resource: "nodereports"}
)

const (
	bundleFailurePolicyFail        = "fail"
	bundleFailurePolicyUseLastGood = "use-last-good"
	maxDeltaResourcesStored        = 25
	maxTrendPointsStored           = 12
	defaultSourceRefreshInterval   = 30 * time.Second
)

type collectFunc func(context.Context, k8s.ClusterOptions) (policy.Inventory, error)

type Options struct {
	ClusterOptions       k8s.ClusterOptions
	Interval             time.Duration
	Watch                bool
	WatchDebounce        time.Duration
	CycleTimeout         time.Duration
	ReportTTL            time.Duration
	PruneStaleReports    bool
	MaxStoredFindings    int
	MaxStoredAttackPaths int
	DefaultProfile       policy.RuleProfile
	DefaultCompliance    string
	DefaultAttackPaths   bool
	DefaultReportName    string
	DisablePolicyLookup  bool
}

type Runner struct {
	dynamicClient     dynamic.Interface
	coreClient        kubernetes.Interface
	collect           collectFunc
	now               func() time.Time
	options           Options
	startWatches      func(context.Context, chan<- rescanTrigger)
	extractSBOM       func(context.Context, string, imagescan.AuthOptions) (vuln.SBOM, error)
	fetchHTTPSBOM     func(context.Context, string, map[string]string) (vuln.SBOM, error)
	fetchGitHubSBOM   func(context.Context, string, string, map[string]string) (vuln.SBOM, error)
	emitEvent         func(context.Context, string, string, string, string, string) error
	postWebhook       func(context.Context, string, map[string]string, []byte) error
	bundleCacheMu     sync.Mutex
	bundleCache       map[string]cachedSourceState
	remoteSBOMCacheMu sync.Mutex
	remoteSBOMCache   map[string]cachedRemoteSBOMState
}

type cachedSourceState struct {
	bundles  resolvedPolicyBundles
	statuses []v1alpha1.SourceStatus
}

type cachedRemoteSBOMState struct {
	sbom   vuln.SBOM
	status v1alpha1.SourceStatus
}

func NewRunner(config *rest.Config, options Options) (*Runner, error) {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	coreClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	runner := &Runner{
		dynamicClient:   dynamicClient,
		coreClient:      coreClient,
		collect:         collectInventory,
		now:             time.Now,
		options:         normalizeOptions(options),
		extractSBOM:     imagescan.ExtractRemoteSBOMWithAuth,
		fetchHTTPSBOM:   loadHTTPSBOM,
		fetchGitHubSBOM: loadGitHubReleaseAssetSBOM,
		emitEvent:       nil,
		postWebhook:     postJSONWebhook,
		bundleCache:     map[string]cachedSourceState{},
		remoteSBOMCache: map[string]cachedRemoteSBOMState{},
	}
	runner.emitEvent = runner.emitCoreEvent
	runner.startWatches = runner.watchResources
	return runner, nil
}

func normalizeOptions(options Options) Options {
	if options.Interval <= 0 {
		options.Interval = 15 * time.Minute
	}
	if !options.Watch {
		options.WatchDebounce = 0
	} else if options.WatchDebounce <= 0 {
		options.WatchDebounce = 10 * time.Second
	}
	if options.CycleTimeout <= 0 {
		options.CycleTimeout = 5 * time.Minute
	}
	if options.MaxStoredFindings <= 0 {
		options.MaxStoredFindings = 250
	}
	if options.MaxStoredAttackPaths <= 0 {
		options.MaxStoredAttackPaths = 100
	}
	if options.DefaultProfile == "" {
		options.DefaultProfile = policy.RuleProfileHardening
	}
	if options.DefaultReportName == "" {
		options.DefaultReportName = "cluster-default"
	}
	return options
}

func (r *Runner) Run(ctx context.Context) error {
	var triggerCh <-chan rescanTrigger
	if r.options.Watch {
		triggers := make(chan rescanTrigger, 8)
		triggerCh = triggers
		r.startWatches(ctx, triggers)
	}

	if err := r.runLoop(ctx, triggerCh); err != nil {
		return err
	}
	return nil
}

func (r *Runner) runLoop(ctx context.Context, triggerCh <-chan rescanTrigger) error {
	if err := r.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		// keep the operator alive and retry on the next interval
	}

	ticker := time.NewTicker(r.options.Interval)
	defer ticker.Stop()
	refreshTicker := time.NewTicker(r.sourceRefreshCheckInterval())
	defer refreshTicker.Stop()

	var debounceTimer *time.Timer
	var debounceC <-chan time.Time
	pending := pendingRescan{}
	resetDebounce := func() {
		if r.options.WatchDebounce <= 0 {
			return
		}
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(r.options.WatchDebounce)
			debounceC = debounceTimer.C
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimer.Reset(r.options.WatchDebounce)
		debounceC = debounceTimer.C
	}
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
				// keep the operator alive and retry on the next interval
			}
		case <-refreshTicker.C:
			if err := r.runBackgroundSourceRefresh(ctx); err != nil && !errors.Is(err, context.Canceled) {
				// keep the operator alive and retry on the next interval
			}
		case trigger := <-triggerCh:
			if r.options.WatchDebounce <= 0 {
				if err := r.runForPending(ctx, pendingRescan{}.with(trigger)); err != nil && !errors.Is(err, context.Canceled) {
					// keep the operator alive and retry on the next interval
				}
				continue
			}
			pending.add(trigger)
			resetDebounce()
		case <-debounceC:
			debounceC = nil
			triggered := pending
			pending = pendingRescan{}
			if err := r.runForPending(ctx, triggered); err != nil && !errors.Is(err, context.Canceled) {
				// keep the operator alive and retry on the next interval
			}
		}
	}
}

func (r *Runner) sourceRefreshCheckInterval() time.Duration {
	if r.options.Interval > 0 && r.options.Interval < defaultSourceRefreshInterval {
		return r.options.Interval
	}
	return defaultSourceRefreshInterval
}

func (r *Runner) RunOnce(ctx context.Context) error {
	return r.runForPending(ctx, pendingRescan{full: true})
}

func (r *Runner) runBackgroundSourceRefresh(ctx context.Context) error {
	policies, err := r.resolvePolicies(ctx)
	if err != nil {
		return err
	}

	var errs []error
	for _, named := range policies {
		if named.Spec.Suspend {
			continue
		}
		policyCtx, cancel := context.WithTimeout(ctx, r.options.CycleTimeout)
		shouldReconcile, refreshErr := r.refreshPolicyRemoteSources(policyCtx, named)
		cancel()
		if refreshErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", named.Name, refreshErr))
		}
		if !shouldReconcile {
			continue
		}
		reconcileCtx, reconcileCancel := context.WithTimeout(ctx, r.options.CycleTimeout)
		if err := r.reconcilePolicy(reconcileCtx, named); err != nil && !errors.Is(err, context.Canceled) {
			errs = append(errs, fmt.Errorf("%s: %w", named.Name, err))
		}
		reconcileCancel()
	}
	return errors.Join(errs...)
}

func (r *Runner) runForPending(ctx context.Context, pending pendingRescan) error {
	policies, err := r.resolvePolicies(ctx)
	if err != nil {
		return err
	}

	var errs []error
	for _, named := range policies {
		if named.Spec.Suspend {
			continue
		}
		if !pending.matches(
			r.effectivePolicyNamespace(named),
			named.Spec.IncludeNamespaces,
			named.Spec.ExcludeNamespaces,
			named.Spec.IncludeKinds,
			named.Spec.ExcludeKinds,
		) {
			continue
		}
		if err := r.reconcilePolicy(ctx, named); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", named.Name, err))
		}
	}
	if pending.full && r.options.PruneStaleReports {
		if err := r.pruneReports(ctx, policies); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type namedPolicy struct {
	Name string
	Spec v1alpha1.ScanPolicySpec
}

func (r *Runner) resolvePolicies(ctx context.Context) ([]namedPolicy, error) {
	policies, err := r.listPolicies(ctx)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		policies = []namedPolicy{r.defaultPolicy()}
	}
	return policies, nil
}

func (r *Runner) defaultPolicy() namedPolicy {
	return namedPolicy{
		Name: r.options.DefaultReportName,
		Spec: v1alpha1.ScanPolicySpec{
			Namespace:           r.options.ClusterOptions.Namespace,
			Profile:             string(r.options.DefaultProfile),
			Compliance:          r.options.DefaultCompliance,
			AttackPaths:         r.options.DefaultAttackPaths,
			BundleFailurePolicy: bundleFailurePolicyFail,
		},
	}
}

func (r *Runner) listPolicies(ctx context.Context) ([]namedPolicy, error) {
	if r.options.DisablePolicyLookup {
		return nil, nil
	}
	list, err := r.dynamicClient.Resource(scanPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list scan policies: %w", err)
	}
	policies := make([]namedPolicy, 0, len(list.Items))
	for _, item := range list.Items {
		var policyObject v1alpha1.ScanPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &policyObject); err != nil {
			return nil, fmt.Errorf("decode scan policy %s: %w", item.GetName(), err)
		}
		policies = append(policies, namedPolicy{
			Name: item.GetName(),
			Spec: policyObject.Spec,
		})
	}
	return policies, nil
}

func (r *Runner) effectivePolicyNamespace(named namedPolicy) string {
	if named.Spec.Namespace != "" {
		return named.Spec.Namespace
	}
	return r.options.ClusterOptions.Namespace
}

func (r *Runner) reconcilePolicy(ctx context.Context, named namedPolicy) error {
	status := v1alpha1.ScanReportStatus{}
	spec := scanReportSpec(named)
	now := metav1.NewTime(r.now().UTC())
	status.GeneratedAt = &now

	policyCtx, cancel := context.WithTimeout(ctx, r.options.CycleTimeout)
	defer cancel()

	reportResult, sourceStatuses, usedCachedSources, err := r.evaluatePolicy(policyCtx, named)
	if err != nil {
		status.Phase = "Error"
		status.LastError = err.Error()
		return r.upsertReport(ctx, named.Name, r.effectivePolicyNamespace(named), spec, status)
	}

	status.Phase = "Ready"
	status.SourceStatuses = sourceStatuses
	status.UsedCachedSources = usedCachedSources
	status.TotalFindings = reportResult.Summary.TotalFindings
	status.TotalAttackPaths = reportResult.Summary.AttackPaths.TotalPaths
	storedResult, findingsTruncated, attackPathsTruncated := truncateResult(*reportResult, r.options.MaxStoredFindings, r.options.MaxStoredAttackPaths)
	status.StoredFindings = len(storedResult.Findings)
	status.StoredAttackPaths = len(storedResult.AttackPaths)
	status.FindingsTruncated = findingsTruncated
	status.AttackPathsTruncated = attackPathsTruncated
	status.Result = &storedResult
	return r.upsertReport(ctx, named.Name, r.effectivePolicyNamespace(named), spec, status)
}

func (r *Runner) evaluatePolicy(ctx context.Context, named namedPolicy) (*report.ScanResult, []v1alpha1.SourceStatus, bool, error) {
	profileName := named.Spec.Profile
	if profileName == "" {
		profileName = string(r.options.DefaultProfile)
	}
	ruleProfile, err := policy.ParseRuleProfile(profileName)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse rule profile: %w", err)
	}

	namespace := named.Spec.Namespace
	if namespace == "" {
		namespace = r.options.ClusterOptions.Namespace
	}
	inventory, err := r.collect(ctx, k8s.ClusterOptions{
		Kubeconfig:     r.options.ClusterOptions.Kubeconfig,
		Context:        r.options.ClusterOptions.Context,
		Namespace:      namespace,
		NamespacedOnly: r.options.ClusterOptions.NamespacedOnly,
	})
	if err != nil {
		return nil, nil, false, fmt.Errorf("collect inventory: %w", err)
	}
	inventory = policy.ApplyInventoryFilter(inventory, policy.InventoryFilter{
		IncludeKinds:      named.Spec.IncludeKinds,
		ExcludeKinds:      named.Spec.ExcludeKinds,
		IncludeNamespaces: named.Spec.IncludeNamespaces,
		ExcludeNamespaces: named.Spec.ExcludeNamespaces,
	})

	resolvedBundles, err := r.loadPolicyBundles(ctx, named)
	if err != nil {
		return nil, nil, false, err
	}

	findings := evaluateRulesForProfile(inventory, ruleProfile, resolvedBundles.ruleBundle)
	if resolvedBundles.sboms != nil && resolvedBundles.advisories != nil {
		findings = append(findings, vuln.MatchInventory(inventory, resolvedBundles.sboms, *resolvedBundles.advisories, r.now().UTC())...)
	}
	if named.Spec.ComponentVulns && resolvedBundles.advisories != nil {
		findings = append(findings, vuln.MatchClusterComponents(inventory, *resolvedBundles.advisories, r.now().UTC())...)
	}
	if resolvedBundles.controls != nil {
		findings, err = policy.ApplyControls(findings, *resolvedBundles.controls, r.now().UTC())
		if err != nil {
			return nil, nil, false, fmt.Errorf("apply policy controls: %w", err)
		}
	}

	var complianceReport *policy.ComplianceReport
	complianceName := named.Spec.Compliance
	if complianceName == "" {
		complianceName = r.options.DefaultCompliance
	}
	if complianceName != "" {
		profile, err := policy.ParseComplianceProfile(complianceName)
		if err != nil {
			return nil, nil, false, fmt.Errorf("parse compliance profile: %w", err)
		}
		complianceFindings := evaluateRulesForProfile(inventory, policy.RuleProfileEnterprise, resolvedBundles.ruleBundle)
		if resolvedBundles.sboms != nil && resolvedBundles.advisories != nil {
			complianceFindings = append(complianceFindings, vuln.MatchInventory(inventory, resolvedBundles.sboms, *resolvedBundles.advisories, r.now().UTC())...)
		}
		if named.Spec.ComponentVulns && resolvedBundles.advisories != nil {
			complianceFindings = append(complianceFindings, vuln.MatchClusterComponents(inventory, *resolvedBundles.advisories, r.now().UTC())...)
		}
		if resolvedBundles.controls != nil {
			complianceFindings, err = policy.ApplyControls(complianceFindings, *resolvedBundles.controls, r.now().UTC())
			if err != nil {
				return nil, nil, false, fmt.Errorf("apply policy controls for compliance: %w", err)
			}
		}
		compliance := policy.EvaluateCompliance(profile, complianceFindings)
		complianceReport = &compliance
	}

	var attackPaths []attackpath.Result
	if named.Spec.AttackPaths || (named.Spec.Profile == "" && r.options.DefaultAttackPaths) {
		attackPaths = attackpath.Analyze(inventory, findings)
	}

	result := report.BuildScanResultWithAttackPathsAndCompliance(findings, attackPaths, complianceReport)
	result.GeneratedAt = r.now().UTC()
	return &result, resolvedBundles.statuses, resolvedBundles.usedCachedSources, nil
}

func scanReportSpec(named namedPolicy) v1alpha1.ScanReportSpec {
	return v1alpha1.ScanReportSpec{
		PolicyName:          named.Name,
		Namespace:           named.Spec.Namespace,
		Profile:             named.Spec.Profile,
		Compliance:          named.Spec.Compliance,
		AttackPaths:         named.Spec.AttackPaths,
		ComponentVulns:      named.Spec.ComponentVulns,
		Notification:        cloneNotificationSpec(named.Spec.Notification),
		SBOMRefreshInterval: named.Spec.SBOMRefreshInterval,
		BundleFailurePolicy: named.Spec.BundleFailurePolicy,
		IncludeKinds:        append([]string(nil), named.Spec.IncludeKinds...),
		ExcludeKinds:        append([]string(nil), named.Spec.ExcludeKinds...),
		IncludeNamespaces:   append([]string(nil), named.Spec.IncludeNamespaces...),
		ExcludeNamespaces:   append([]string(nil), named.Spec.ExcludeNamespaces...),
		BundleKeyRef:        cloneBundleRef(named.Spec.BundleKeyRef),
		PolicyBundleRef:     cloneBundleRef(named.Spec.PolicyBundleRef),
		RulesBundleRef:      cloneBundleRef(named.Spec.RulesBundleRef),
		AdvisoriesBundleRef: cloneBundleRef(named.Spec.AdvisoriesBundleRef),
		SBOMRefs:            cloneBundleRefs(named.Spec.SBOMRefs),
		SBOMSelector:        named.Spec.SBOMSelector,
	}
}

type resolvedPolicyBundles struct {
	controls          *policy.Controls
	ruleBundle        *policy.RuleBundle
	advisories        *vuln.AdvisoryBundle
	sboms             vuln.SBOMIndex
	statuses          []v1alpha1.SourceStatus
	usedCachedSources bool
}

func (r *Runner) loadPolicyBundles(ctx context.Context, named namedPolicy) (resolvedPolicyBundles, error) {
	policyName := named.Name
	cacheKey := policyName

	loadFresh := func() (resolvedPolicyBundles, error) {
		var resolved resolvedPolicyBundles
		if named.Spec.BundleKeyRef == nil {
			if named.Spec.PolicyBundleRef != nil || named.Spec.RulesBundleRef != nil || named.Spec.AdvisoriesBundleRef != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("bundleKeyRef is required when bundle refs are configured")
			}
		}

		var keyContent []byte
		if named.Spec.BundleKeyRef != nil {
			content, status, err := r.readBundleRef(ctx, named, *named.Spec.BundleKeyRef, "bundle-key")
			resolved.statuses = append(resolved.statuses, status)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("load bundle key: %w", err)
			}
			keyContent = content
		}

		if named.Spec.PolicyBundleRef != nil {
			content, status, err := r.readBundleRef(ctx, named, *named.Spec.PolicyBundleRef, "policy-bundle")
			resolved.statuses = append(resolved.statuses, status)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("load policy bundle ref: %w", err)
			}
			controls, err := bundle.LoadSignedPolicyControlsBytes(content, keyContent)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("verify policy bundle: %w", err)
			}
			resolved.controls = &controls
		}
		if named.Spec.RulesBundleRef != nil {
			content, status, err := r.readBundleRef(ctx, named, *named.Spec.RulesBundleRef, "rules-bundle")
			resolved.statuses = append(resolved.statuses, status)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("load rules bundle ref: %w", err)
			}
			ruleBundle, err := bundle.LoadSignedRuleBundleBytes(content, keyContent)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("verify rules bundle: %w", err)
			}
			resolved.ruleBundle = &ruleBundle
		}
		if named.Spec.AdvisoriesBundleRef != nil {
			content, status, err := r.readBundleRef(ctx, named, *named.Spec.AdvisoriesBundleRef, "advisories-bundle")
			resolved.statuses = append(resolved.statuses, status)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("load advisories bundle ref: %w", err)
			}
			advisories, err := bundle.LoadSignedAdvisoriesBytes(content, keyContent)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("verify advisories bundle: %w", err)
			}
			resolved.advisories = &advisories
		}
		if len(named.Spec.SBOMRefs) > 0 {
			sboms := vuln.SBOMIndex{}
			for _, ref := range named.Spec.SBOMRefs {
				sbom, status, err := r.loadSBOMSource(ctx, named, ref)
				resolved.statuses = append(resolved.statuses, status)
				if err != nil {
					return resolvedPolicyBundles{}, fmt.Errorf("load sbom ref: %w", err)
				}
				sboms[normalizeOperatorImageRef(sbom.ImageRef)] = sbom
			}
			resolved.sboms = sboms
		}
		if strings.TrimSpace(named.Spec.SBOMSelector) != "" {
			discovered, statuses, err := r.loadDiscoveredSBOMs(ctx, named, named.Spec.SBOMSelector)
			resolved.statuses = append(resolved.statuses, statuses...)
			if err != nil {
				return resolvedPolicyBundles{}, fmt.Errorf("load discovered sboms: %w", err)
			}
			if resolved.sboms == nil {
				resolved.sboms = vuln.SBOMIndex{}
			}
			for key, sbom := range discovered {
				resolved.sboms[key] = sbom
			}
		}
		return resolved, nil
	}

	resolved, err := loadFresh()
	if err == nil {
		r.bundleCacheMu.Lock()
		if r.bundleCache == nil {
			r.bundleCache = map[string]cachedSourceState{}
		}
		r.bundleCache[cacheKey] = cachedSourceState{
			bundles:  cloneResolvedPolicyBundles(resolved),
			statuses: cloneSourceStatuses(resolved.statuses),
		}
		r.bundleCacheMu.Unlock()
		return resolved, nil
	}

	if !strings.EqualFold(strings.TrimSpace(named.Spec.BundleFailurePolicy), bundleFailurePolicyUseLastGood) {
		return resolvedPolicyBundles{}, err
	}

	r.bundleCacheMu.Lock()
	cached, ok := r.bundleCache[cacheKey]
	r.bundleCacheMu.Unlock()
	if !ok {
		return resolvedPolicyBundles{}, err
	}

	statuses := cloneSourceStatuses(cached.statuses)
	now := metav1.NewTime(r.now().UTC())
	for i := range statuses {
		statuses[i].Cached = true
		statuses[i].Phase = "UsingCached"
		statuses[i].LastError = err.Error()
		statuses[i].VerifiedAt = &now
	}
	cachedBundles := cloneResolvedPolicyBundles(cached.bundles)
	cachedBundles.statuses = statuses
	cachedBundles.usedCachedSources = true
	return cachedBundles, nil
}

func (r *Runner) readBundleRef(ctx context.Context, named namedPolicy, ref v1alpha1.BundleRef, sourceType string) ([]byte, v1alpha1.SourceStatus, error) {
	kind := strings.TrimSpace(ref.Kind)
	name := strings.TrimSpace(ref.Name)
	key := strings.TrimSpace(ref.Key)
	namespace := strings.TrimSpace(ref.Namespace)
	status := v1alpha1.SourceStatus{
		Type:      sourceType,
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Key:       key,
	}
	if kind == "" || name == "" || key == "" {
		status.Phase = "Error"
		status.LastError = "bundle ref requires kind, name, and key"
		return nil, status, errors.New(status.LastError)
	}
	if namespace == "" {
		namespace = r.effectivePolicyNamespace(named)
		status.Namespace = namespace
	}
	if namespace == "" {
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("bundle ref %s/%s requires namespace", kind, name)
		return nil, status, errors.New(status.LastError)
	}

	finalize := func(content []byte) ([]byte, v1alpha1.SourceStatus, error) {
		status.Phase = "Ready"
		status.Digest = sha256Digest(content)
		now := metav1.NewTime(r.now().UTC())
		status.VerifiedAt = &now
		return content, status, nil
	}

	switch kind {
	case "ConfigMap":
		configMap, err := r.coreClient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			status.Phase = "Error"
			status.LastError = err.Error()
			return nil, status, err
		}
		if value, ok := configMap.Data[key]; ok {
			return finalize([]byte(value))
		}
		if value, ok := configMap.BinaryData[key]; ok {
			return finalize(value)
		}
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("configmap %s/%s missing key %s", namespace, name, key)
		return nil, status, errors.New(status.LastError)
	case "Secret":
		secret, err := r.coreClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			status.Phase = "Error"
			status.LastError = err.Error()
			return nil, status, err
		}
		value, ok := secret.Data[key]
		if !ok {
			status.Phase = "Error"
			status.LastError = fmt.Sprintf("secret %s/%s missing key %s", namespace, name, key)
			return nil, status, errors.New(status.LastError)
		}
		return finalize(value)
	default:
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("unsupported bundle ref kind %q", kind)
		return nil, status, errors.New(status.LastError)
	}
}

func cloneBundleRef(ref *v1alpha1.BundleRef) *v1alpha1.BundleRef {
	if ref == nil {
		return nil
	}
	cloned := *ref
	if ref.AuthSecretRef != nil {
		authRef := *ref.AuthSecretRef
		cloned.AuthSecretRef = &authRef
	}
	return &cloned
}

func cloneBundleRefs(refs []v1alpha1.BundleRef) []v1alpha1.BundleRef {
	if len(refs) == 0 {
		return nil
	}
	cloned := make([]v1alpha1.BundleRef, len(refs))
	for i := range refs {
		cloned[i] = refs[i]
		if refs[i].AuthSecretRef != nil {
			authRef := *refs[i].AuthSecretRef
			cloned[i].AuthSecretRef = &authRef
		}
	}
	return cloned
}

func cloneNotificationSpec(spec *v1alpha1.NotificationSpec) *v1alpha1.NotificationSpec {
	if spec == nil {
		return nil
	}
	cloned := *spec
	if spec.AuthSecretRef != nil {
		refCopy := *spec.AuthSecretRef
		cloned.AuthSecretRef = &refCopy
	}
	return &cloned
}

func (r *Runner) loadSBOMSource(ctx context.Context, named namedPolicy, ref v1alpha1.BundleRef) (vuln.SBOM, v1alpha1.SourceStatus, error) {
	return r.loadSBOMSourceWithOptions(ctx, named, ref, true)
}

func (r *Runner) loadSBOMSourceWithOptions(ctx context.Context, named namedPolicy, ref v1alpha1.BundleRef, allowCache bool) (vuln.SBOM, v1alpha1.SourceStatus, error) {
	kind := strings.TrimSpace(ref.Kind)
	name := strings.TrimSpace(ref.Name)
	key := strings.TrimSpace(ref.Key)
	namespace := strings.TrimSpace(ref.Namespace)
	status := v1alpha1.SourceStatus{
		Type:      "sbom",
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Key:       key,
	}
	if kind == "" || name == "" {
		status.Phase = "Error"
		status.LastError = "sbom ref requires kind and name"
		return vuln.SBOM{}, status, errors.New(status.LastError)
	}
	if namespace == "" {
		namespace = r.effectivePolicyNamespace(named)
		status.Namespace = namespace
	}
	if namespace == "" && !isRemoteSBOMKind(kind) {
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("sbom ref %s/%s requires namespace", kind, name)
		return vuln.SBOM{}, status, errors.New(status.LastError)
	}

	refreshInterval, err := parseSBOMRefreshInterval(named.Spec.SBOMRefreshInterval)
	if err != nil {
		status.Phase = "Error"
		status.LastError = err.Error()
		return vuln.SBOM{}, status, err
	}
	if isRemoteSBOMKind(kind) && refreshInterval > 0 && allowCache {
		if cachedSBOM, cachedStatus, cachedErr, ok := r.cachedRemoteSBOM(named.Name, ref, refreshInterval); ok {
			return cachedSBOM, cachedStatus, cachedErr
		}
	}

	remoteSourceError := func(err error) (vuln.SBOM, v1alpha1.SourceStatus, error) {
		status.Phase = "Error"
		status.LastError = err.Error()
		if isRemoteSBOMKind(kind) && refreshInterval > 0 {
			status = r.finalizeRemoteSBOMError(named.Name, ref, status, refreshInterval)
		}
		return vuln.SBOM{}, status, err
	}

	switch kind {
	case "ConfigMap", "Secret":
		if key == "" {
			status.Phase = "Error"
			status.LastError = fmt.Sprintf("sbom ref %s/%s requires key", kind, name)
			return vuln.SBOM{}, status, errors.New(status.LastError)
		}
		content, bundleStatus, err := r.readBundleRef(ctx, named, ref, "sbom")
		status = bundleStatus
		if err != nil {
			return vuln.SBOM{}, status, err
		}
		sbom, err := vuln.LoadSBOMBytes(content)
		if err != nil {
			status.Phase = "Error"
			status.LastError = err.Error()
			return vuln.SBOM{}, status, fmt.Errorf("decode sbom ref %s/%s[%s]: %w", kind, name, key, err)
		}
		sbom.ImageRef = normalizeOperatorImageRef(sbom.ImageRef)
		return sbom, status, nil
	case v1alpha1.SBOMReportKind:
		object, err := r.dynamicClient.Resource(sbomReportGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			status.Phase = "Error"
			status.LastError = err.Error()
			return vuln.SBOM{}, status, err
		}
		var sbomReport v1alpha1.SBOMReport
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &sbomReport); err != nil {
			status.Phase = "Error"
			status.LastError = err.Error()
			return vuln.SBOM{}, status, fmt.Errorf("decode sbom report %s/%s: %w", namespace, name, err)
		}
		content := strings.TrimSpace(sbomReport.Spec.Content)
		if content == "" {
			status.Phase = "Error"
			status.LastError = fmt.Sprintf("sbom report %s/%s has empty spec.content", namespace, name)
			return vuln.SBOM{}, status, errors.New(status.LastError)
		}
		sbom, err := vuln.LoadSBOMBytes([]byte(content))
		if err != nil {
			status.Phase = "Error"
			status.LastError = err.Error()
			return vuln.SBOM{}, status, fmt.Errorf("decode sbom report %s/%s: %w", namespace, name, err)
		}
		normalized := normalizeOperatorImageRef(sbom.ImageRef)
		if normalized == "" {
			normalized = normalizeOperatorImageRef(sbomReport.Spec.ImageRef)
		}
		sbom.ImageRef = normalized
		if normalized == "" {
			status.Phase = "Error"
			status.LastError = fmt.Sprintf("sbom report %s/%s has empty image reference", namespace, name)
			return vuln.SBOM{}, status, errors.New(status.LastError)
		}
		status.Phase = "Ready"
		status.Digest = sha256Digest([]byte(content))
		now := metav1.NewTime(r.now().UTC())
		status.VerifiedAt = &now
		return sbom, status, nil
	case "HTTP":
		headers, description, err := r.resolveHTTPAuth(ctx, namespace, ref)
		status.Description = description
		if err != nil {
			return remoteSourceError(err)
		}
		sbom, err := r.fetchHTTPSBOM(ctx, name, headers)
		if err != nil {
			return remoteSourceError(err)
		}
		sbom.ImageRef = normalizeOperatorImageRef(sbom.ImageRef)
		status = r.finalizeRemoteSBOMStatus(named.Name, ref, status, sbom, refreshInterval)
		return sbom, status, nil
	case "GitHubReleaseAsset":
		if key == "" {
			status.Phase = "Error"
			status.LastError = fmt.Sprintf("sbom ref %s/%s requires key", kind, name)
			return vuln.SBOM{}, status, errors.New(status.LastError)
		}
		headers, description, err := r.resolveHTTPAuth(ctx, namespace, ref)
		status.Description = description
		if err != nil {
			return remoteSourceError(err)
		}
		sbom, err := r.fetchGitHubSBOM(ctx, name, key, headers)
		if err != nil {
			return remoteSourceError(err)
		}
		sbom.ImageRef = normalizeOperatorImageRef(sbom.ImageRef)
		status = r.finalizeRemoteSBOMStatus(named.Name, ref, status, sbom, refreshInterval)
		return sbom, status, nil
	case "OCIImage":
		auth, description, err := r.resolveOCIAuth(ctx, namespace, ref)
		status.Description = description
		if err != nil {
			return remoteSourceError(err)
		}
		sbom, err := r.extractSBOM(ctx, name, auth)
		if err != nil {
			return remoteSourceError(err)
		}
		sbom.ImageRef = normalizeOperatorImageRef(sbom.ImageRef)
		status = r.finalizeRemoteSBOMStatus(named.Name, ref, status, sbom, refreshInterval)
		return sbom, status, nil
	default:
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("unsupported sbom ref kind %q", kind)
		return vuln.SBOM{}, status, errors.New(status.LastError)
	}
}

func parseSBOMRefreshInterval(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	interval, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("parse sbomRefreshInterval: %w", err)
	}
	if interval < 0 {
		return 0, fmt.Errorf("parse sbomRefreshInterval: duration must be non-negative")
	}
	return interval, nil
}

func isRemoteSBOMKind(kind string) bool {
	switch strings.TrimSpace(kind) {
	case "HTTP", "OCIImage", "GitHubReleaseAsset":
		return true
	default:
		return false
	}
}

func remoteSBOMCacheKey(policyName string, ref v1alpha1.BundleRef) string {
	return strings.Join([]string{
		strings.TrimSpace(policyName),
		strings.TrimSpace(ref.Kind),
		strings.TrimSpace(ref.Namespace),
		strings.TrimSpace(ref.Name),
		strings.TrimSpace(ref.Key),
	}, "|")
}

func (r *Runner) cachedRemoteSBOM(policyName string, ref v1alpha1.BundleRef, refreshInterval time.Duration) (vuln.SBOM, v1alpha1.SourceStatus, error, bool) {
	if refreshInterval <= 0 {
		return vuln.SBOM{}, v1alpha1.SourceStatus{}, nil, false
	}
	cached, ok := r.remoteSBOMCacheLookup(policyName, ref)
	if !ok || cached.status.VerifiedAt == nil {
		return vuln.SBOM{}, v1alpha1.SourceStatus{}, nil, false
	}
	nextRefresh := remoteSBOMNextRefresh(cached.status, refreshInterval)
	if !r.now().UTC().Before(nextRefresh) {
		return vuln.SBOM{}, v1alpha1.SourceStatus{}, nil, false
	}
	status := cloneSourceStatuses([]v1alpha1.SourceStatus{cached.status})[0]
	status.Cached = true
	nextRefreshAt := metav1.NewTime(nextRefresh.UTC())
	status.NextRefreshAt = &nextRefreshAt
	if strings.EqualFold(status.Phase, "Error") {
		if strings.TrimSpace(status.LastError) == "" {
			status.LastError = "cached remote sbom refresh error"
		}
		return vuln.SBOM{}, status, errors.New(status.LastError), true
	}
	return cached.sbom, status, nil, true
}

func (r *Runner) finalizeRemoteSBOMStatus(policyName string, ref v1alpha1.BundleRef, status v1alpha1.SourceStatus, sbom vuln.SBOM, refreshInterval time.Duration) v1alpha1.SourceStatus {
	status.Phase = "Ready"
	now := metav1.NewTime(r.now().UTC())
	status.VerifiedAt = &now
	status.Digest = sbomDigest(sbom)
	if refreshInterval > 0 {
		nextRefreshAt := metav1.NewTime(now.Time.Add(refreshInterval).UTC())
		status.NextRefreshAt = &nextRefreshAt
	}
	cacheKey := remoteSBOMCacheKey(policyName, ref)
	r.remoteSBOMCacheMu.Lock()
	if r.remoteSBOMCache == nil {
		r.remoteSBOMCache = map[string]cachedRemoteSBOMState{}
	}
	if previous, ok := r.remoteSBOMCache[cacheKey]; ok && previous.status.Digest != "" && previous.status.Digest != status.Digest {
		status.Changed = true
	}
	r.remoteSBOMCache[cacheKey] = cachedRemoteSBOMState{
		sbom:   sbom,
		status: status,
	}
	r.remoteSBOMCacheMu.Unlock()
	return status
}

func (r *Runner) finalizeRemoteSBOMError(policyName string, ref v1alpha1.BundleRef, status v1alpha1.SourceStatus, refreshInterval time.Duration) v1alpha1.SourceStatus {
	status.Phase = "Error"
	now := metav1.NewTime(r.now().UTC())
	status.VerifiedAt = &now
	if refreshInterval > 0 {
		nextRefreshAt := metav1.NewTime(now.Time.Add(refreshInterval).UTC())
		status.NextRefreshAt = &nextRefreshAt
	}

	cacheKey := remoteSBOMCacheKey(policyName, ref)
	r.remoteSBOMCacheMu.Lock()
	if r.remoteSBOMCache == nil {
		r.remoteSBOMCache = map[string]cachedRemoteSBOMState{}
	}
	cached := r.remoteSBOMCache[cacheKey]
	if status.Digest == "" {
		status.Digest = cached.status.Digest
	}
	cached.status = status
	r.remoteSBOMCache[cacheKey] = cached
	r.remoteSBOMCacheMu.Unlock()
	return status
}

func (r *Runner) remoteSBOMCacheLookup(policyName string, ref v1alpha1.BundleRef) (cachedRemoteSBOMState, bool) {
	cacheKey := remoteSBOMCacheKey(policyName, ref)
	r.remoteSBOMCacheMu.Lock()
	cached, ok := r.remoteSBOMCache[cacheKey]
	r.remoteSBOMCacheMu.Unlock()
	if !ok {
		return cachedRemoteSBOMState{}, false
	}
	cached.status = cloneSourceStatuses([]v1alpha1.SourceStatus{cached.status})[0]
	if len(cached.sbom.Packages) > 0 {
		cached.sbom.Packages = append([]vuln.Package(nil), cached.sbom.Packages...)
	}
	return cached, true
}

func remoteSBOMNextRefresh(status v1alpha1.SourceStatus, refreshInterval time.Duration) time.Time {
	if status.NextRefreshAt != nil {
		return status.NextRefreshAt.Time
	}
	if status.VerifiedAt != nil {
		return status.VerifiedAt.Time.Add(refreshInterval)
	}
	return time.Time{}
}

func (r *Runner) remoteSBOMRefreshDue(policyName string, ref v1alpha1.BundleRef, refreshInterval time.Duration) bool {
	if refreshInterval <= 0 {
		return false
	}
	cached, ok := r.remoteSBOMCacheLookup(policyName, ref)
	if !ok || cached.status.VerifiedAt == nil {
		return true
	}
	nextRefresh := remoteSBOMNextRefresh(cached.status, refreshInterval)
	if nextRefresh.IsZero() {
		return true
	}
	return !r.now().UTC().Before(nextRefresh)
}

func (r *Runner) refreshPolicyRemoteSources(ctx context.Context, named namedPolicy) (bool, error) {
	refreshInterval, err := parseSBOMRefreshInterval(named.Spec.SBOMRefreshInterval)
	if err != nil {
		return false, err
	}
	if refreshInterval <= 0 {
		return false, nil
	}

	shouldReconcile := false
	var errs []error
	for _, ref := range named.Spec.SBOMRefs {
		if !isRemoteSBOMKind(ref.Kind) || !r.remoteSBOMRefreshDue(named.Name, ref, refreshInterval) {
			continue
		}
		previous, hadPrevious := r.remoteSBOMCacheLookup(named.Name, ref)
		_, status, err := r.loadSBOMSourceWithOptions(ctx, named, ref, false)
		if err != nil {
			errs = append(errs, fmt.Errorf("refresh remote sbom %s/%s: %w", strings.TrimSpace(ref.Kind), strings.TrimSpace(ref.Name), err))
		}
		if remoteSourceChangeRequiresReconcile(previous.status, status, hadPrevious) {
			shouldReconcile = true
		}
	}
	return shouldReconcile, errors.Join(errs...)
}

func remoteSourceChangeRequiresReconcile(previous, current v1alpha1.SourceStatus, hadPrevious bool) bool {
	if !hadPrevious {
		return strings.EqualFold(current.Phase, "Error") || current.Changed
	}
	if previous.Digest != current.Digest {
		return true
	}
	if previous.Phase != current.Phase {
		return true
	}
	if strings.TrimSpace(previous.LastError) != strings.TrimSpace(current.LastError) {
		return true
	}
	return current.Changed
}

func sbomDigest(sbom vuln.SBOM) string {
	content, err := json.Marshal(sbom)
	if err != nil {
		return sha256Digest([]byte(normalizeOperatorImageRef(sbom.ImageRef) + "|" + strconv.Itoa(len(sbom.Packages))))
	}
	return sha256Digest(content)
}

func (r *Runner) loadDiscoveredSBOMs(ctx context.Context, named namedPolicy, selector string) (vuln.SBOMIndex, []v1alpha1.SourceStatus, error) {
	namespace := r.effectivePolicyNamespace(named)
	if namespace == "" {
		return nil, nil, fmt.Errorf("sbomSelector requires an effective namespace")
	}
	sboms := vuln.SBOMIndex{}
	statuses := []v1alpha1.SourceStatus{}

	configMaps, err := r.coreClient.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, nil, err
	}
	for _, configMap := range configMaps.Items {
		itemStatuses, err := appendSBOMsFromConfigMap(sboms, &configMap, r.now)
		statuses = append(statuses, itemStatuses...)
		if err != nil {
			return nil, nil, err
		}
	}

	secrets, err := r.coreClient.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, nil, err
	}
	for _, secret := range secrets.Items {
		itemStatuses, err := appendSBOMsFromSecret(sboms, &secret, r.now)
		statuses = append(statuses, itemStatuses...)
		if err != nil {
			return nil, nil, err
		}
	}

	sbomReports, err := r.dynamicClient.Resource(sbomReportGVR).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, nil, err
		}
	} else {
		for _, item := range sbomReports.Items {
			status, err := appendSBOMsFromReport(sboms, &item, r.now)
			statuses = append(statuses, status)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return sboms, statuses, nil
}

func appendSBOMsFromConfigMap(index vuln.SBOMIndex, configMap *corev1.ConfigMap, now func() time.Time) ([]v1alpha1.SourceStatus, error) {
	var statuses []v1alpha1.SourceStatus
	for key, value := range configMap.Data {
		status, err := appendSBOMEntry(index, "ConfigMap", configMap.Namespace, configMap.Name, key, []byte(value), now)
		statuses = append(statuses, status)
		if err != nil {
			return statuses, err
		}
	}
	for key, value := range configMap.BinaryData {
		status, err := appendSBOMEntry(index, "ConfigMap", configMap.Namespace, configMap.Name, key, value, now)
		statuses = append(statuses, status)
		if err != nil {
			return statuses, err
		}
	}
	return statuses, nil
}

func appendSBOMsFromSecret(index vuln.SBOMIndex, secret *corev1.Secret, now func() time.Time) ([]v1alpha1.SourceStatus, error) {
	var statuses []v1alpha1.SourceStatus
	for key, value := range secret.Data {
		status, err := appendSBOMEntry(index, "Secret", secret.Namespace, secret.Name, key, value, now)
		statuses = append(statuses, status)
		if err != nil {
			return statuses, err
		}
	}
	return statuses, nil
}

func appendSBOMsFromReport(index vuln.SBOMIndex, item *unstructured.Unstructured, now func() time.Time) (v1alpha1.SourceStatus, error) {
	status := v1alpha1.SourceStatus{
		Type:      "sbom",
		Kind:      v1alpha1.SBOMReportKind,
		Name:      item.GetName(),
		Namespace: item.GetNamespace(),
	}
	var sbomReport v1alpha1.SBOMReport
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &sbomReport); err != nil {
		status.Phase = "Error"
		status.LastError = err.Error()
		return status, fmt.Errorf("decode sbom report %s/%s: %w", item.GetNamespace(), item.GetName(), err)
	}
	content := strings.TrimSpace(sbomReport.Spec.Content)
	if content == "" {
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("sbom report %s/%s has empty spec.content", item.GetNamespace(), item.GetName())
		return status, errors.New(status.LastError)
	}
	sbom, err := vuln.LoadSBOMBytes([]byte(content))
	if err != nil {
		status.Phase = "Error"
		status.LastError = err.Error()
		return status, fmt.Errorf("%s %s/%s: %w", v1alpha1.SBOMReportKind, item.GetNamespace(), item.GetName(), err)
	}
	normalized := normalizeOperatorImageRef(sbom.ImageRef)
	if normalized == "" {
		normalized = normalizeOperatorImageRef(sbomReport.Spec.ImageRef)
	}
	if normalized == "" {
		status.Phase = "Error"
		status.LastError = fmt.Sprintf("sbom report %s/%s has empty image reference", item.GetNamespace(), item.GetName())
		return status, errors.New(status.LastError)
	}
	index[normalized] = sbom
	status.Phase = "Ready"
	status.Digest = sha256Digest([]byte(content))
	verifiedAt := metav1.NewTime(now().UTC())
	status.VerifiedAt = &verifiedAt
	return status, nil
}

func appendSBOMEntry(index vuln.SBOMIndex, kind, namespace, name, key string, content []byte, now func() time.Time) (v1alpha1.SourceStatus, error) {
	status := v1alpha1.SourceStatus{
		Type:      "sbom",
		Kind:      kind,
		Name:      name,
		Namespace: namespace,
		Key:       key,
	}
	if !strings.HasSuffix(strings.ToLower(strings.TrimSpace(key)), ".json") {
		status.Phase = "Skipped"
		status.Description = "non-json key ignored"
		return status, nil
	}
	sbom, err := vuln.LoadSBOMBytes(content)
	if err != nil {
		status.Phase = "Error"
		status.LastError = err.Error()
		return status, fmt.Errorf("%s %s/%s key %s: %w", kind, namespace, name, key, err)
	}
	normalized := normalizeOperatorImageRef(sbom.ImageRef)
	if normalized == "" {
		status.Phase = "Error"
		status.LastError = "empty image reference"
		return status, fmt.Errorf("%s %s/%s key %s: empty image reference", kind, namespace, name, key)
	}
	index[normalized] = sbom
	status.Phase = "Ready"
	status.Digest = sha256Digest(content)
	verifiedAt := metav1.NewTime(now().UTC())
	status.VerifiedAt = &verifiedAt
	return status, nil
}

func cloneSourceStatuses(statuses []v1alpha1.SourceStatus) []v1alpha1.SourceStatus {
	if len(statuses) == 0 {
		return nil
	}
	cloned := make([]v1alpha1.SourceStatus, len(statuses))
	for i := range statuses {
		cloned[i] = statuses[i]
		if statuses[i].VerifiedAt != nil {
			verifiedAt := *statuses[i].VerifiedAt
			cloned[i].VerifiedAt = &verifiedAt
		}
		if statuses[i].NextRefreshAt != nil {
			nextRefreshAt := *statuses[i].NextRefreshAt
			cloned[i].NextRefreshAt = &nextRefreshAt
		}
	}
	return cloned
}

func cloneResolvedPolicyBundles(resolved resolvedPolicyBundles) resolvedPolicyBundles {
	cloned := resolvedPolicyBundles{
		controls:          resolved.controls,
		ruleBundle:        resolved.ruleBundle,
		advisories:        resolved.advisories,
		statuses:          cloneSourceStatuses(resolved.statuses),
		usedCachedSources: resolved.usedCachedSources,
	}
	if len(resolved.sboms) > 0 {
		cloned.sboms = make(vuln.SBOMIndex, len(resolved.sboms))
		for key, sbom := range resolved.sboms {
			sbomClone := sbom
			if len(sbom.Packages) > 0 {
				sbomClone.Packages = append([]vuln.Package(nil), sbom.Packages...)
			}
			cloned.sboms[key] = sbomClone
		}
	}
	return cloned
}

func sha256Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Runner) resolveHTTPAuth(ctx context.Context, defaultNamespace string, ref v1alpha1.BundleRef) (map[string]string, string, error) {
	if ref.AuthSecretRef == nil {
		return nil, "", nil
	}
	headers, err := r.resolveHTTPHeadersFromSecretRef(ctx, r.defaultRefNamespace(defaultNamespace, ref.Namespace), ref.AuthSecretRef)
	if err != nil {
		return nil, "", err
	}
	description := "secret-backed Authorization header"
	if _, ok := headers["Authorization"]; !ok || len(headers) > 1 {
		description = "secret-backed HTTP headers"
	}
	return headers, description, nil
}

func (r *Runner) resolveHTTPHeadersFromSecretRef(ctx context.Context, defaultNamespace string, ref *v1alpha1.SecretKeyRef) (map[string]string, error) {
	if ref == nil {
		return nil, nil
	}
	raw, err := r.readSecretKeyRef(ctx, defaultNamespace, *ref)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("http auth secret value is empty")
	}
	headers := map[string]string{}
	if looksLikeJSON(value) {
		var payload struct {
			Headers map[string]string `json:"headers"`
			Token   string            `json:"token"`
		}
		if err := jsonUnmarshalString(value, &payload); err != nil {
			return nil, fmt.Errorf("decode http auth secret: %w", err)
		}
		for key, headerValue := range payload.Headers {
			trimmedKey := strings.TrimSpace(key)
			trimmedValue := strings.TrimSpace(headerValue)
			if trimmedKey != "" && trimmedValue != "" {
				headers[trimmedKey] = trimmedValue
			}
		}
		if token := strings.TrimSpace(payload.Token); token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		if len(headers) == 0 {
			return nil, fmt.Errorf("http auth secret did not contain usable headers")
		}
		return headers, nil
	}
	if strings.Contains(value, ":") && !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		parts := strings.SplitN(value, ":", 2)
		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])
		if headerName != "" && headerValue != "" {
			headers[headerName] = headerValue
			return headers, nil
		}
	}
	headers["Authorization"] = value
	if !strings.Contains(value, " ") {
		headers["Authorization"] = "Bearer " + value
	}
	return headers, nil
}

func (r *Runner) resolveOCIAuth(ctx context.Context, defaultNamespace string, ref v1alpha1.BundleRef) (imagescan.AuthOptions, string, error) {
	if ref.AuthSecretRef == nil {
		return imagescan.AuthOptions{}, "", nil
	}
	raw, err := r.readSecretKeyRef(ctx, r.defaultRefNamespace(defaultNamespace, ref.Namespace), *ref.AuthSecretRef)
	if err != nil {
		return imagescan.AuthOptions{}, "", err
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return imagescan.AuthOptions{}, "", fmt.Errorf("oci auth secret value is empty")
	}
	if looksLikeJSON(value) {
		var auth imagescan.AuthOptions
		if err := jsonUnmarshalString(value, &auth); err != nil {
			return imagescan.AuthOptions{}, "", fmt.Errorf("decode oci auth secret: %w", err)
		}
		if auth.Username == "" && auth.Password == "" && auth.Token == "" {
			return imagescan.AuthOptions{}, "", fmt.Errorf("oci auth secret did not contain usable credentials")
		}
		return auth, "secret-backed OCI auth", nil
	}
	if strings.Contains(value, ":") {
		parts := strings.SplitN(value, ":", 2)
		return imagescan.AuthOptions{
			Username: strings.TrimSpace(parts[0]),
			Password: parts[1],
		}, "secret-backed OCI username/password", nil
	}
	return imagescan.AuthOptions{Token: value}, "secret-backed OCI token", nil
}

func (r *Runner) readSecretKeyRef(ctx context.Context, defaultNamespace string, ref v1alpha1.SecretKeyRef) (string, error) {
	name := strings.TrimSpace(ref.Name)
	key := strings.TrimSpace(ref.Key)
	namespace := strings.TrimSpace(ref.Namespace)
	if name == "" || key == "" {
		return "", fmt.Errorf("authSecretRef requires name and key")
	}
	if namespace == "" {
		namespace = defaultNamespace
	}
	if namespace == "" {
		return "", fmt.Errorf("authSecretRef %s requires namespace", name)
	}
	secret, err := r.coreClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s missing key %s", namespace, name, key)
	}
	return string(value), nil
}

func (r *Runner) defaultRefNamespace(fallbackNamespace string, namespace string) string {
	if strings.TrimSpace(namespace) != "" {
		return strings.TrimSpace(namespace)
	}
	if strings.TrimSpace(fallbackNamespace) != "" {
		return strings.TrimSpace(fallbackNamespace)
	}
	return strings.TrimSpace(r.options.ClusterOptions.Namespace)
}

func loadHTTPSBOM(ctx context.Context, targetURL string, headers map[string]string) (vuln.SBOM, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(targetURL)), "https://") {
		return vuln.SBOM{}, fmt.Errorf("http sbom source requires https:// URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("build sbom request: %w", err)
	}
	for key, value := range headers {
		if strings.TrimSpace(key) == "" || value == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("fetch sbom: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return vuln.SBOM{}, fmt.Errorf("fetch sbom: unexpected status %s", resp.Status)
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("read sbom response: %w", err)
	}
	sbom, err := vuln.LoadSBOMBytes(content)
	if err != nil {
		return vuln.SBOM{}, err
	}
	return sbom, nil
}

func loadGitHubReleaseAssetSBOM(ctx context.Context, releaseRef string, assetName string, headers map[string]string) (vuln.SBOM, error) {
	owner, repo, tag, err := parseGitHubReleaseAssetRef(releaseRef)
	if err != nil {
		return vuln.SBOM{}, err
	}
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("build github release request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	for key, value := range headers {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return vuln.SBOM{}, fmt.Errorf("fetch github release metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return vuln.SBOM{}, fmt.Errorf("fetch github release metadata: unexpected status %s", resp.Status)
	}
	var payload struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&payload); err != nil {
		return vuln.SBOM{}, fmt.Errorf("decode github release metadata: %w", err)
	}
	for _, asset := range payload.Assets {
		if strings.TrimSpace(asset.Name) != strings.TrimSpace(assetName) {
			continue
		}
		return loadHTTPSBOM(ctx, asset.BrowserDownloadURL, headers)
	}
	return vuln.SBOM{}, fmt.Errorf("github release asset %q not found in %s", assetName, releaseRef)
}

func parseGitHubReleaseAssetRef(value string) (string, string, string, error) {
	trimmed := strings.TrimSpace(value)
	parts := strings.SplitN(trimmed, "@", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", "", fmt.Errorf("github release asset source must use owner/repo@tag")
	}
	repoParts := strings.Split(strings.TrimSpace(parts[0]), "/")
	if len(repoParts) != 2 || strings.TrimSpace(repoParts[0]) == "" || strings.TrimSpace(repoParts[1]) == "" {
		return "", "", "", fmt.Errorf("github release asset source must use owner/repo@tag")
	}
	return strings.TrimSpace(repoParts[0]), strings.TrimSpace(repoParts[1]), strings.TrimSpace(parts[1]), nil
}

func looksLikeJSON(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func jsonUnmarshalString(value string, target any) error {
	return json.Unmarshal([]byte(value), target)
}

func (r *Runner) emitCoreEvent(ctx context.Context, namespace, objectName, eventType, reason, message string) error {
	if r.coreClient == nil {
		return fmt.Errorf("core client is not configured")
	}
	if strings.TrimSpace(namespace) == "" {
		namespace = "default"
	}
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kubescan-",
			Namespace:    namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: v1alpha1.GroupName + "/" + v1alpha1.Version,
			Kind:       v1alpha1.ScanReportKind,
			Name:       objectName,
			Namespace:  "",
		},
		Type:           eventType,
		Reason:         reason,
		Message:        message,
		Source:         corev1.EventSource{Component: "kubescan-operator"},
		FirstTimestamp: metav1.NewTime(r.now().UTC()),
		LastTimestamp:  metav1.NewTime(r.now().UTC()),
		Count:          1,
	}
	_, err := r.coreClient.CoreV1().Events(namespace).Create(ctx, event, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create kubernetes event: %w", err)
	}
	return nil
}

func postJSONWebhook(ctx context.Context, targetURL string, headers map[string]string, payload []byte) error {
	trimmedURL := strings.TrimSpace(targetURL)
	lowerURL := strings.ToLower(trimmedURL)
	if !strings.HasPrefix(lowerURL, "https://") && !strings.HasPrefix(lowerURL, "http://") {
		return fmt.Errorf("webhook URL must use http:// or https://")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimmedURL, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		if strings.TrimSpace(key) == "" || value == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("post webhook: unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func normalizeOperatorImageRef(value string) string {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(trimmed, "docker-pullable://"):
		return strings.TrimPrefix(trimmed, "docker-pullable://")
	case strings.HasPrefix(trimmed, "docker://"):
		return strings.TrimPrefix(trimmed, "docker://")
	case strings.HasPrefix(trimmed, "containerd://"):
		return strings.TrimPrefix(trimmed, "containerd://")
	case strings.HasPrefix(trimmed, "cri-o://"):
		return strings.TrimPrefix(trimmed, "cri-o://")
	default:
		return trimmed
	}
}

func evaluateRulesForProfile(inventory policy.Inventory, profile policy.RuleProfile, ruleBundle *policy.RuleBundle) []policy.Finding {
	if ruleBundle != nil {
		return policy.EvaluateWithProfileAndBundle(inventory, profile, *ruleBundle)
	}
	return policy.EvaluateWithProfile(inventory, profile)
}

func (r *Runner) upsertReport(ctx context.Context, name string, effectiveNamespace string, spec v1alpha1.ScanReportSpec, status v1alpha1.ScanReportStatus) error {
	reportObject := v1alpha1.ScanReport{
		APIVersion: v1alpha1.GroupName + "/" + v1alpha1.Version,
		Kind:       v1alpha1.ScanReportKind,
		Metadata: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "kubescan-operator",
				"app.kubernetes.io/managed-by": "kubescan",
			},
		},
		Spec:   spec,
		Status: status,
	}
	status.Trend = buildScanReportTrend(v1alpha1.ScanReportStatus{}, status)
	reportObject.Status = status
	resource := r.dynamicClient.Resource(scanReportGVR)

	existing, err := resource.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			if hasHistoryExportSink(spec.Notification) {
				status.Notification = r.deliverNotifications(ctx, effectiveNamespace, name, spec, status)
				reportObject.Status = status
			}
			object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&reportObject)
			if err != nil {
				return fmt.Errorf("encode scan report: %w", err)
			}
			unstructuredObject := &unstructured.Unstructured{Object: object}
			if _, err := resource.Create(ctx, unstructuredObject, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("create scan report: %w", err)
			}
			return nil
		}
		return fmt.Errorf("get scan report: %w", err)
	}

	var existingReport v1alpha1.ScanReport
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(existing.Object, &existingReport); err == nil {
		status.Delta = buildScanReportDelta(existingReport.Status, status)
		status.Trend = buildScanReportTrend(existingReport.Status, status)
		if (status.Delta != nil && status.Delta.HasChanges) || hasHistoryExportSink(spec.Notification) {
			status.Notification = r.deliverNotifications(ctx, effectiveNamespace, name, spec, status)
		}
		reportObject.Status = status
	}

	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&reportObject)
	if err != nil {
		return fmt.Errorf("encode scan report: %w", err)
	}
	unstructuredObject := &unstructured.Unstructured{Object: object}

	unstructuredObject.SetResourceVersion(existing.GetResourceVersion())
	if _, err := resource.Update(ctx, unstructuredObject, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update scan report: %w", err)
	}
	return nil
}

func (r *Runner) deliverNotifications(ctx context.Context, effectiveNamespace, reportName string, spec v1alpha1.ScanReportSpec, status v1alpha1.ScanReportStatus) *v1alpha1.NotificationStatus {
	notification := spec.Notification
	if notification == nil {
		return nil
	}
	if !notification.EmitEvents &&
		strings.TrimSpace(notification.WebhookURL) == "" &&
		strings.TrimSpace(notification.SlackWebhookURL) == "" &&
		strings.TrimSpace(notification.HistoryWebhookURL) == "" {
		return nil
	}
	if !notificationEligible(*notification, status) {
		return nil
	}
	deltaEligible := status.Delta != nil && status.Delta.HasChanges
	historyEligible := strings.TrimSpace(notification.HistoryWebhookURL) != ""
	if !deltaEligible && !historyEligible {
		return nil
	}

	result := &v1alpha1.NotificationStatus{}
	now := metav1.NewTime(r.now().UTC())
	result.LastAttemptAt = &now
	message := summarizeDelta(reportName, status.Delta)
	var errs []string

	if deltaEligible && notification.EmitEvents {
		namespace := strings.TrimSpace(effectiveNamespace)
		if namespace == "" {
			namespace = strings.TrimSpace(r.options.ClusterOptions.Namespace)
		}
		if namespace == "" {
			namespace = "default"
		}
		if r.coreClient == nil || r.emitEvent == nil {
			errs = append(errs, "event delivery unavailable")
		} else if err := r.emitEvent(ctx, namespace, reportName, "Normal", "ScanDeltaChanged", message); err != nil {
			errs = append(errs, "event: "+err.Error())
		} else {
			result.EventEmitted = true
		}
	}

	if deltaEligible {
		if webhookURL := strings.TrimSpace(notification.WebhookURL); webhookURL != "" {
			if r.postWebhook == nil {
				errs = append(errs, "webhook delivery unavailable")
			} else {
				headers, err := r.resolveHTTPHeadersFromSecretRef(ctx, effectiveNamespace, notification.AuthSecretRef)
				if err != nil {
					errs = append(errs, "webhook auth: "+err.Error())
				} else {
					payload, err := json.Marshal(buildDeltaNotificationPayload(reportName, spec, status))
					if err != nil {
						errs = append(errs, "webhook payload: "+err.Error())
					} else if err := r.postWebhook(ctx, webhookURL, headers, payload); err != nil {
						errs = append(errs, "webhook: "+err.Error())
					} else {
						result.WebhookDelivered = true
					}
				}
			}
		}
		if slackWebhookURL := strings.TrimSpace(notification.SlackWebhookURL); slackWebhookURL != "" {
			if r.postWebhook == nil {
				errs = append(errs, "slack delivery unavailable")
			} else {
				headers, err := r.resolveHTTPHeadersFromSecretRef(ctx, effectiveNamespace, notification.AuthSecretRef)
				if err != nil {
					errs = append(errs, "slack auth: "+err.Error())
				} else {
					payload, err := json.Marshal(buildSlackNotificationPayload(reportName, spec, status))
					if err != nil {
						errs = append(errs, "slack payload: "+err.Error())
					} else if err := r.postWebhook(ctx, slackWebhookURL, headers, payload); err != nil {
						errs = append(errs, "slack: "+err.Error())
					} else {
						result.SlackDelivered = true
					}
				}
			}
		}
	}
	if historyWebhookURL := strings.TrimSpace(notification.HistoryWebhookURL); historyWebhookURL != "" {
		if r.postWebhook == nil {
			errs = append(errs, "history webhook delivery unavailable")
		} else {
			headers, err := r.resolveHTTPHeadersFromSecretRef(ctx, effectiveNamespace, notification.AuthSecretRef)
			if err != nil {
				errs = append(errs, "history webhook auth: "+err.Error())
			} else {
				payload, err := json.Marshal(buildHistoryNotificationPayload(reportName, spec, status))
				if err != nil {
					errs = append(errs, "history webhook payload: "+err.Error())
				} else if err := r.postWebhook(ctx, historyWebhookURL, headers, payload); err != nil {
					errs = append(errs, "history webhook: "+err.Error())
				} else {
					result.HistoryWebhookDelivered = true
				}
			}
		}
	}

	if len(errs) > 0 {
		result.LastError = strings.Join(errs, "; ")
	}
	return result
}

type deltaNotificationPayload struct {
	APIVersion  string                    `json:"apiVersion"`
	Kind        string                    `json:"kind"`
	ReportName  string                    `json:"reportName"`
	GeneratedAt *metav1.Time              `json:"generatedAt,omitempty"`
	Spec        v1alpha1.ScanReportSpec   `json:"spec"`
	Delta       *v1alpha1.ScanReportDelta `json:"delta,omitempty"`
	Summary     report.Summary            `json:"summary"`
}

type historyNotificationPayload struct {
	APIVersion     string                    `json:"apiVersion"`
	Kind           string                    `json:"kind"`
	ReportName     string                    `json:"reportName"`
	GeneratedAt    *metav1.Time              `json:"generatedAt,omitempty"`
	Spec           v1alpha1.ScanReportSpec   `json:"spec"`
	Phase          string                    `json:"phase,omitempty"`
	LastError      string                    `json:"lastError,omitempty"`
	UsedCached     bool                      `json:"usedCachedSources,omitempty"`
	Delta          *v1alpha1.ScanReportDelta `json:"delta,omitempty"`
	Trend          *v1alpha1.ScanReportTrend `json:"trend,omitempty"`
	SourceStatuses []v1alpha1.SourceStatus   `json:"sourceStatuses,omitempty"`
	Summary        report.Summary            `json:"summary"`
}

type slackNotificationPayload struct {
	Text string `json:"text"`
}

func buildDeltaNotificationPayload(reportName string, spec v1alpha1.ScanReportSpec, status v1alpha1.ScanReportStatus) deltaNotificationPayload {
	summary := report.Summary{}
	if status.Result != nil {
		summary = status.Result.Summary
	}
	return deltaNotificationPayload{
		APIVersion:  v1alpha1.GroupName + "/" + v1alpha1.Version,
		Kind:        "ScanReportDeltaNotification",
		ReportName:  reportName,
		GeneratedAt: status.GeneratedAt,
		Spec:        spec,
		Delta:       status.Delta,
		Summary:     summary,
	}
}

func buildHistoryNotificationPayload(reportName string, spec v1alpha1.ScanReportSpec, status v1alpha1.ScanReportStatus) historyNotificationPayload {
	summary := report.Summary{}
	if status.Result != nil {
		summary = status.Result.Summary
	}
	return historyNotificationPayload{
		APIVersion:     v1alpha1.GroupName + "/" + v1alpha1.Version,
		Kind:           "ScanReportHistoryNotification",
		ReportName:     reportName,
		GeneratedAt:    status.GeneratedAt,
		Spec:           spec,
		Phase:          status.Phase,
		LastError:      status.LastError,
		UsedCached:     status.UsedCachedSources,
		Delta:          status.Delta,
		Trend:          cloneTrend(status.Trend),
		SourceStatuses: cloneSourceStatuses(status.SourceStatuses),
		Summary:        summary,
	}
}

func buildSlackNotificationPayload(reportName string, spec v1alpha1.ScanReportSpec, status v1alpha1.ScanReportStatus) slackNotificationPayload {
	text := summarizeDelta(reportName, status.Delta)
	if status.Result != nil {
		text = fmt.Sprintf(
			"%s | findings=%d attack_paths=%d profile=%s",
			text,
			status.Result.Summary.TotalFindings,
			status.Result.Summary.AttackPaths.TotalPaths,
			strings.TrimSpace(spec.Profile),
		)
	}
	return slackNotificationPayload{Text: text}
}

func hasHistoryExportSink(notification *v1alpha1.NotificationSpec) bool {
	if notification == nil {
		return false
	}
	return strings.TrimSpace(notification.HistoryWebhookURL) != ""
}

func notificationEligible(notification v1alpha1.NotificationSpec, status v1alpha1.ScanReportStatus) bool {
	threshold := strings.TrimSpace(notification.MinimumSeverity)
	if threshold == "" {
		return true
	}
	severity, err := policy.ParseSeverity(threshold)
	if err != nil {
		return true
	}
	return policy.MeetsOrExceedsSeverity(maxResultSeverity(status), severity)
}

func maxResultSeverity(status v1alpha1.ScanReportStatus) policy.Severity {
	if status.Result == nil {
		return ""
	}
	for _, severity := range []policy.Severity{
		policy.SeverityCritical,
		policy.SeverityHigh,
		policy.SeverityMedium,
		policy.SeverityLow,
	} {
		if status.Result.Summary.TotalBySeverity[severity] > 0 {
			return severity
		}
	}
	return ""
}

func summarizeDelta(reportName string, delta *v1alpha1.ScanReportDelta) string {
	if delta == nil {
		return fmt.Sprintf("ScanReport %s updated", reportName)
	}
	return fmt.Sprintf(
		"ScanReport %s changed: findings +%d/-%d, severity changes %d, attack paths +%d/-%d",
		reportName,
		delta.FindingsAdded,
		delta.FindingsRemoved,
		delta.FindingsSeverityChanged,
		delta.AttackPathsAdded,
		delta.AttackPathsRemoved,
	)
}

func (r *Runner) pruneReports(ctx context.Context, policies []namedPolicy) error {
	list, err := r.dynamicClient.Resource(scanReportGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("list scan reports for pruning: %w", err)
	}

	desired := map[string]struct{}{}
	for _, named := range policies {
		if named.Spec.Suspend {
			continue
		}
		desired[named.Name] = struct{}{}
	}

	var errs []error
	now := r.now().UTC()
	for _, item := range list.Items {
		if item.GetLabels()["app.kubernetes.io/managed-by"] != "kubescan" {
			continue
		}

		var deleteReason string
		if _, ok := desired[item.GetName()]; !ok {
			deleteReason = "stale unmanaged policy"
		} else if r.options.ReportTTL > 0 && reportOlderThan(item.Object, now.Add(-r.options.ReportTTL)) {
			deleteReason = "expired report ttl"
		}
		if deleteReason == "" {
			continue
		}

		if err := r.dynamicClient.Resource(scanReportGVR).Delete(ctx, item.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete scan report %s (%s): %w", item.GetName(), deleteReason, err))
		}
	}
	return errors.Join(errs...)
}

func reportOlderThan(object map[string]any, cutoff time.Time) bool {
	status, ok := object["status"].(map[string]any)
	if !ok {
		return false
	}
	raw, ok := status["generatedAt"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return false
	}
	generatedAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return generatedAt.Before(cutoff)
}

func collectInventory(ctx context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
	collector, err := k8s.NewCollectorFromOptions(options)
	if err != nil {
		return policy.Inventory{}, err
	}
	return collector.Collect(ctx, options.Namespace)
}

type watchedResource struct {
	gvr        schema.GroupVersionResource
	namespaced bool
	scope      string
}

func (r *Runner) watchedResources() []watchedResource {
	resources := []watchedResource{
		{gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, namespaced: true, scope: "full"},
		{gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, namespaced: true, scope: "full"},
		{gvr: sbomReportGVR, namespaced: true, scope: "full"},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}, namespaced: true, scope: "namespace"},
		{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}, namespaced: true, scope: "namespace"},
	}
	if !r.options.ClusterOptions.NamespacedOnly {
		resources = append(resources,
			watchedResource{gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}, scope: "namespace-object"},
			watchedResource{gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}, scope: "full"},
			watchedResource{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}, scope: "full"},
			watchedResource{gvr: schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}, scope: "full"},
			watchedResource{gvr: nodeReportGVR, scope: "full"},
		)
	}
	if !r.options.DisablePolicyLookup {
		resources = append(resources, watchedResource{gvr: scanPolicyGVR, scope: "full"})
	}
	return resources
}

func (r *Runner) watchResources(ctx context.Context, triggerCh chan<- rescanTrigger) {
	for _, resource := range r.watchedResources() {
		go r.watchResource(ctx, resource, triggerCh)
	}
}

func (r *Runner) watchResource(ctx context.Context, resource watchedResource, triggerCh chan<- rescanTrigger) {
	for {
		if ctx.Err() != nil {
			return
		}
		watcher, err := r.openWatch(ctx, resource)
		if err != nil {
			if !sleepOrDone(ctx, 2*time.Second) {
				return
			}
			continue
		}

		restart := false
		for !restart {
			select {
			case <-ctx.Done():
				watcher.Stop()
				return
			case event, ok := <-watcher.ResultChan():
				if !ok {
					restart = true
					break
				}
				switch event.Type {
				case watch.Added, watch.Modified, watch.Deleted:
					sendTrigger(triggerCh, triggerFromEvent(resource, event))
				}
			}
		}
		watcher.Stop()
		if !sleepOrDone(ctx, time.Second) {
			return
		}
	}
}

func (r *Runner) openWatch(ctx context.Context, resource watchedResource) (watch.Interface, error) {
	namespaceable := r.dynamicClient.Resource(resource.gvr)
	if resource.namespaced {
		namespace := r.options.ClusterOptions.Namespace
		if namespace == "" {
			namespace = metav1.NamespaceAll
		}
		return namespaceable.Namespace(namespace).Watch(ctx, metav1.ListOptions{})
	}
	return namespaceable.Watch(ctx, metav1.ListOptions{})
}

type rescanTrigger struct {
	full      bool
	namespace string
	kind      string
	name      string
}

type pendingRescan struct {
	full               bool
	namespaceKinds     map[string]map[string]struct{}
	clusterScopedKinds map[string]struct{}
}

func (p pendingRescan) with(trigger rescanTrigger) pendingRescan {
	p.add(trigger)
	return p
}

func (p *pendingRescan) add(trigger rescanTrigger) {
	if trigger.full {
		p.full = true
		p.namespaceKinds = nil
		p.clusterScopedKinds = nil
		return
	}
	namespace := strings.TrimSpace(trigger.namespace)
	kind := normalizeKind(trigger.kind)
	if namespace == "" || p.full {
		if kind == "" {
			return
		}
		if p.clusterScopedKinds == nil {
			p.clusterScopedKinds = map[string]struct{}{}
		}
		p.clusterScopedKinds[kind] = struct{}{}
		return
	}
	if p.namespaceKinds == nil {
		p.namespaceKinds = map[string]map[string]struct{}{}
	}
	if p.namespaceKinds[namespace] == nil {
		p.namespaceKinds[namespace] = map[string]struct{}{}
	}
	if kind == "" {
		p.namespaceKinds[namespace]["*"] = struct{}{}
		return
	}
	p.namespaceKinds[namespace][kind] = struct{}{}
}

func (p pendingRescan) matches(policyNamespace string, includeNamespaces, excludeNamespaces, includeKinds, excludeKinds []string) bool {
	if p.full || (len(p.namespaceKinds) == 0 && len(p.clusterScopedKinds) == 0) {
		return true
	}
	includeKindSet := normalizedStringSet(includeKinds)
	excludeKindSet := normalizedStringSet(excludeKinds)
	if len(p.clusterScopedKinds) > 0 && kindSetMatchesPolicy(p.clusterScopedKinds, includeKindSet, excludeKindSet) {
		return true
	}
	if policyNamespace != "" {
		return namespaceKindsMatchPolicy(p.namespaceKinds[policyNamespace], includeKindSet, excludeKindSet)
	}
	includes := stringSet(includeNamespaces)
	excludes := stringSet(excludeNamespaces)
	for namespace, kinds := range p.namespaceKinds {
		if len(includes) > 0 {
			if _, ok := includes[namespace]; !ok {
				continue
			}
		}
		if _, excluded := excludes[namespace]; excluded {
			continue
		}
		if namespaceKindsMatchPolicy(kinds, includeKindSet, excludeKindSet) {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return set
}

func normalizedStringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := normalizeKind(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return set
}

func namespaceKindsMatchPolicy(kinds map[string]struct{}, includeKinds, excludeKinds map[string]struct{}) bool {
	if len(kinds) == 0 {
		return false
	}
	if _, ok := kinds["*"]; ok {
		if len(includeKinds) == 0 {
			return true
		}
		for kind := range includeKinds {
			if _, excluded := excludeKinds[kind]; !excluded {
				return true
			}
		}
		return false
	}
	return kindSetMatchesPolicy(kinds, includeKinds, excludeKinds)
}

func kindSetMatchesPolicy(changedKinds, includeKinds, excludeKinds map[string]struct{}) bool {
	for kind := range changedKinds {
		if len(includeKinds) > 0 {
			if _, ok := includeKinds[kind]; !ok {
				continue
			}
		}
		if _, excluded := excludeKinds[kind]; excluded {
			continue
		}
		return true
	}
	return false
}

func triggerFromEvent(resource watchedResource, event watch.Event) rescanTrigger {
	kind, name := eventKindAndName(event.Object)
	switch resource.scope {
	case "full":
		return rescanTrigger{full: true, kind: kind, name: name}
	case "namespace-object":
		if accessor, err := meta.Accessor(event.Object); err == nil {
			return rescanTrigger{namespace: accessor.GetName(), kind: kind, name: name}
		}
		return rescanTrigger{full: true, kind: kind, name: name}
	default:
		if accessor, err := meta.Accessor(event.Object); err == nil {
			return rescanTrigger{namespace: accessor.GetNamespace(), kind: kind, name: name}
		}
		return rescanTrigger{full: true, kind: kind, name: name}
	}
}

func eventKindAndName(object runtime.Object) (string, string) {
	if accessor, err := meta.Accessor(object); err == nil {
		name := accessor.GetName()
		if typeAccessor, err := meta.TypeAccessor(object); err == nil {
			return normalizeKind(typeAccessor.GetKind()), name
		}
		return "", name
	}
	return "", ""
}

func normalizeKind(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func sendTrigger(triggerCh chan<- rescanTrigger, trigger rescanTrigger) {
	select {
	case triggerCh <- trigger:
	default:
	}
}

func sleepOrDone(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func truncateResult(result report.ScanResult, maxFindings, maxAttackPaths int) (report.ScanResult, bool, bool) {
	findingsTruncated := false
	attackPathsTruncated := false
	if maxFindings >= 0 && len(result.Findings) > maxFindings {
		result.Findings = append([]policy.Finding(nil), result.Findings[:maxFindings]...)
		findingsTruncated = true
	}
	if maxAttackPaths >= 0 && len(result.AttackPaths) > maxAttackPaths {
		result.AttackPaths = append([]attackpath.Result(nil), result.AttackPaths[:maxAttackPaths]...)
		attackPathsTruncated = true
	}
	return result, findingsTruncated, attackPathsTruncated
}

type resourceDeltaAccumulator struct {
	ref                     policy.ResourceRef
	findingsAdded           int
	findingsRemoved         int
	findingsSeverityChanged int
}

func buildScanReportTrend(previous, current v1alpha1.ScanReportStatus) *v1alpha1.ScanReportTrend {
	point := buildScanReportTrendPoint(current)
	if point.GeneratedAt == nil {
		return cloneTrend(previous.Trend)
	}

	trend := &v1alpha1.ScanReportTrend{
		WindowSize: maxTrendPointsStored,
	}
	if previous.Trend != nil {
		trend.TotalRuns = previous.Trend.TotalRuns
		trend.RecentRuns = append(trend.RecentRuns, previous.Trend.RecentRuns...)
	}
	trend.TotalRuns++
	trend.RecentRuns = append(trend.RecentRuns, point)
	if len(trend.RecentRuns) > maxTrendPointsStored {
		trend.RecentRuns = append([]v1alpha1.ScanReportTrendPoint(nil), trend.RecentRuns[len(trend.RecentRuns)-maxTrendPointsStored:]...)
	}
	summarizeTrend(trend)
	return trend
}

func buildScanReportTrendPoint(status v1alpha1.ScanReportStatus) v1alpha1.ScanReportTrendPoint {
	point := v1alpha1.ScanReportTrendPoint{
		GeneratedAt:       status.GeneratedAt,
		Phase:             status.Phase,
		UsedCachedSources: status.UsedCachedSources,
		TotalFindings:     status.TotalFindings,
		TotalAttackPaths:  status.TotalAttackPaths,
	}
	if status.Result != nil {
		point.TotalFindings = status.Result.Summary.TotalFindings
		point.TotalAttackPaths = status.Result.Summary.AttackPaths.TotalPaths
		point.CriticalFindings = status.Result.Summary.TotalBySeverity[policy.SeverityCritical]
		point.HighFindings = status.Result.Summary.TotalBySeverity[policy.SeverityHigh]
		point.MediumFindings = status.Result.Summary.TotalBySeverity[policy.SeverityMedium]
		point.LowFindings = status.Result.Summary.TotalBySeverity[policy.SeverityLow]
	}
	return point
}

func cloneTrend(trend *v1alpha1.ScanReportTrend) *v1alpha1.ScanReportTrend {
	if trend == nil {
		return nil
	}
	cloned := *trend
	if len(trend.RecentRuns) > 0 {
		cloned.RecentRuns = append([]v1alpha1.ScanReportTrendPoint(nil), trend.RecentRuns...)
	}
	return &cloned
}

func summarizeTrend(trend *v1alpha1.ScanReportTrend) {
	if trend == nil {
		return
	}
	trend.HighestRecentSeverity = ""
	trend.ConsecutiveCleanRuns = 0
	trend.ConsecutiveErrorRuns = 0
	trend.FindingsDeltaFromLatest = 0
	trend.AttackPathsDeltaLatest = 0
	for _, point := range trend.RecentRuns {
		for _, severity := range []struct {
			kind  policy.Severity
			count int
		}{
			{policy.SeverityCritical, point.CriticalFindings},
			{policy.SeverityHigh, point.HighFindings},
			{policy.SeverityMedium, point.MediumFindings},
			{policy.SeverityLow, point.LowFindings},
		} {
			if severity.count > 0 {
				if trend.HighestRecentSeverity == "" || policy.MeetsOrExceedsSeverity(severity.kind, policy.Severity(trend.HighestRecentSeverity)) {
					trend.HighestRecentSeverity = string(severity.kind)
				}
				break
			}
		}
	}
	if n := len(trend.RecentRuns); n > 0 {
		latest := trend.RecentRuns[n-1]
		for i := n - 1; i >= 0; i-- {
			point := trend.RecentRuns[i]
			if point.TotalFindings == 0 && point.TotalAttackPaths == 0 && point.Phase == "Ready" {
				trend.ConsecutiveCleanRuns++
			} else {
				break
			}
		}
		for i := n - 1; i >= 0; i-- {
			if trend.RecentRuns[i].Phase == "Error" {
				trend.ConsecutiveErrorRuns++
			} else {
				break
			}
		}
		if n > 1 {
			previous := trend.RecentRuns[n-2]
			trend.FindingsDeltaFromLatest = latest.TotalFindings - previous.TotalFindings
			trend.AttackPathsDeltaLatest = latest.TotalAttackPaths - previous.TotalAttackPaths
		}
	}
}

func buildScanReportDelta(previous, current v1alpha1.ScanReportStatus) *v1alpha1.ScanReportDelta {
	if previous.Result == nil || current.Result == nil || previous.GeneratedAt == nil {
		return nil
	}

	delta := &v1alpha1.ScanReportDelta{
		PreviousGeneratedAt: previous.GeneratedAt.DeepCopy(),
	}

	previousFindings := make(map[string]policy.Finding, len(previous.Result.Findings))
	currentFindings := make(map[string]policy.Finding, len(current.Result.Findings))
	resourceChanges := map[string]*resourceDeltaAccumulator{}

	for _, finding := range previous.Result.Findings {
		previousFindings[findingIdentity(finding)] = finding
	}
	for _, finding := range current.Result.Findings {
		currentFindings[findingIdentity(finding)] = finding
	}

	for key, finding := range currentFindings {
		previousFinding, existed := previousFindings[key]
		switch {
		case !existed:
			delta.FindingsAdded++
			accumulateResourceDelta(resourceChanges, finding.Resource).findingsAdded++
		case previousFinding.Severity != finding.Severity:
			delta.FindingsSeverityChanged++
			accumulateResourceDelta(resourceChanges, finding.Resource).findingsSeverityChanged++
		}
	}
	for key, finding := range previousFindings {
		if _, ok := currentFindings[key]; ok {
			continue
		}
		delta.FindingsRemoved++
		accumulateResourceDelta(resourceChanges, finding.Resource).findingsRemoved++
	}

	previousPaths := make(map[string]struct{}, len(previous.Result.AttackPaths))
	currentPaths := make(map[string]struct{}, len(current.Result.AttackPaths))
	for _, path := range previous.Result.AttackPaths {
		previousPaths[attackPathIdentity(path)] = struct{}{}
	}
	for _, path := range current.Result.AttackPaths {
		currentPaths[attackPathIdentity(path)] = struct{}{}
		if _, ok := previousPaths[attackPathIdentity(path)]; !ok {
			delta.AttackPathsAdded++
		}
	}
	for key := range previousPaths {
		if _, ok := currentPaths[key]; !ok {
			delta.AttackPathsRemoved++
		}
	}

	resourceDeltas := make([]v1alpha1.ScanResourceDelta, 0, len(resourceChanges))
	for _, accumulator := range resourceChanges {
		resourceDeltas = append(resourceDeltas, v1alpha1.ScanResourceDelta{
			Kind:                    accumulator.ref.Kind,
			Namespace:               accumulator.ref.Namespace,
			Name:                    accumulator.ref.Name,
			FindingsAdded:           accumulator.findingsAdded,
			FindingsRemoved:         accumulator.findingsRemoved,
			FindingsSeverityChanged: accumulator.findingsSeverityChanged,
		})
	}
	sort.Slice(resourceDeltas, func(i, j int) bool {
		leftScore := resourceDeltaScore(resourceDeltas[i])
		rightScore := resourceDeltaScore(resourceDeltas[j])
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		if resourceDeltas[i].Namespace != resourceDeltas[j].Namespace {
			return resourceDeltas[i].Namespace < resourceDeltas[j].Namespace
		}
		if resourceDeltas[i].Kind != resourceDeltas[j].Kind {
			return resourceDeltas[i].Kind < resourceDeltas[j].Kind
		}
		return resourceDeltas[i].Name < resourceDeltas[j].Name
	})
	delta.ResourcesChanged = len(resourceDeltas)
	if len(resourceDeltas) > maxDeltaResourcesStored {
		resourceDeltas = append([]v1alpha1.ScanResourceDelta(nil), resourceDeltas[:maxDeltaResourcesStored]...)
		delta.ResourcesTruncated = true
	}
	delta.ResourceDeltas = resourceDeltas
	delta.HasChanges = delta.FindingsAdded > 0 ||
		delta.FindingsRemoved > 0 ||
		delta.FindingsSeverityChanged > 0 ||
		delta.AttackPathsAdded > 0 ||
		delta.AttackPathsRemoved > 0
	return delta
}

func findingIdentity(finding policy.Finding) string {
	if strings.TrimSpace(finding.ID) != "" {
		return finding.ID
	}
	return strings.Join([]string{
		finding.RuleID,
		finding.Resource.Kind,
		finding.Resource.Namespace,
		finding.Resource.Name,
		finding.Message,
	}, "|")
}

func attackPathIdentity(path attackpath.Result) string {
	return strings.Join([]string{
		path.ID,
		path.Entry.Kind,
		path.Entry.Namespace,
		path.Entry.Name,
		path.Target,
		path.Path,
	}, "|")
}

func accumulateResourceDelta(changes map[string]*resourceDeltaAccumulator, ref policy.ResourceRef) *resourceDeltaAccumulator {
	key := strings.Join([]string{ref.Kind, ref.Namespace, ref.Name}, "|")
	if changes[key] == nil {
		changes[key] = &resourceDeltaAccumulator{ref: ref}
	}
	return changes[key]
}

func resourceDeltaScore(delta v1alpha1.ScanResourceDelta) int {
	return delta.FindingsAdded + delta.FindingsRemoved + delta.FindingsSeverityChanged
}
