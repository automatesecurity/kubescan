package operator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"kubescan/api/v1alpha1"
	"kubescan/internal/bundle"
	"kubescan/pkg/attackpath"
	"kubescan/pkg/imagescan"
	"kubescan/pkg/k8s"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/vuln"

	"sigs.k8s.io/yaml"
)

func TestRunOnceCreatesDefaultScanReport(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	})
	runner := &Runner{
		dynamicClient: client,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{
			DefaultProfile:    policy.RuleProfileDefault,
			DefaultReportName: "cluster-default",
		}),
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "cluster-default", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	if got := reportObject.Object["kind"]; got != v1alpha1.ScanReportKind {
		t.Fatalf("expected ScanReport kind, got %#v", got)
	}
	spec := nestedMap(t, reportObject.Object, "spec")
	if got := spec["profile"]; got != "default" {
		t.Fatalf("expected default profile, got %#v", got)
	}
	status := nestedMap(t, reportObject.Object, "status")
	if got := status["phase"]; got != "Ready" {
		t.Fatalf("expected Ready phase, got %#v", got)
	}
	storedFindings, ok := status["storedFindings"].(int64)
	if !ok || storedFindings < 1 {
		t.Fatalf("expected storedFindings >= 1, got %#v", status["storedFindings"])
	}
	result := nestedMap(t, status, "result")
	summary := nestedMap(t, result, "summary")
	totalFindings, ok := summary["totalFindings"].(int64)
	if !ok || totalFindings < 1 {
		t.Fatalf("expected at least 1 finding, got %#v", summary["totalFindings"])
	}
	if status["findingsTruncated"] == true {
		t.Fatalf("did not expect findings truncation in default operator run")
	}
}

func TestRunOnceUsesScanPolicySpec(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "team-a",
			},
			"spec": map[string]any{
				"namespace":   "payments",
				"profile":     "hardening",
				"compliance":  "k8s-cis",
				"attackPaths": true,
			},
		},
	})
	collectedNamespace := ""
	runner := &Runner{
		dynamicClient: client,
		collect: func(_ context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
			collectedNamespace = options.Namespace
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource:           policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
						Labels:             map[string]string{"app": "api"},
						ServiceAccountName: "default",
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
				Services: []policy.Service{
					{
						Resource: policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
						Type:     "LoadBalancer",
						Selector: map[string]string{"app": "api"},
					},
				},
				Roles: []policy.Role{
					{
						Resource: policy.ResourceRef{Kind: "Role", Namespace: "payments", Name: "wildcard"},
						Rules: []policy.PolicyRule{
							{Verbs: []string{"*"}, Resources: []string{"pods"}},
						},
					},
				},
				Bindings: []policy.Binding{
					{
						Resource:    policy.ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "api-admin"},
						RoleRefKind: "Role",
						RoleRefName: "wildcard",
						Subjects: []policy.Subject{
							{Kind: "ServiceAccount", Namespace: "payments", Name: "default"},
						},
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 5, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{
			DefaultProfile:       policy.RuleProfileDefault,
			MaxStoredFindings:    2,
			MaxStoredAttackPaths: 1,
		}),
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if collectedNamespace != "payments" {
		t.Fatalf("expected namespace payments, got %q", collectedNamespace)
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "team-a", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	spec := nestedMap(t, reportObject.Object, "spec")
	if got := spec["namespace"]; got != "payments" {
		t.Fatalf("expected payments namespace in report spec, got %#v", got)
	}
	if got := spec["profile"]; got != "hardening" {
		t.Fatalf("expected hardening profile in report spec, got %#v", got)
	}
	if got := spec["compliance"]; got != "k8s-cis" {
		t.Fatalf("expected k8s-cis compliance in report spec, got %#v", got)
	}
	status := nestedMap(t, reportObject.Object, "status")
	if got := status["findingsTruncated"]; got != true {
		t.Fatalf("expected findingsTruncated true, got %#v", got)
	}
	if got := status["storedFindings"]; got != int64(2) {
		t.Fatalf("expected storedFindings 2, got %#v", got)
	}
	if got := status["storedAttackPaths"]; got == nil {
		t.Fatalf("expected storedAttackPaths status field")
	}
	result := nestedMap(t, status, "result")
	if _, ok := result["compliance"]; !ok {
		t.Fatalf("expected compliance report in operator result")
	}
	if attackPaths, ok := result["attackPaths"].([]any); !ok || len(attackPaths) == 0 {
		t.Fatalf("expected attack path results, got %#v", result["attackPaths"])
	}
	if findings, ok := result["findings"].([]any); !ok || len(findings) != 2 {
		t.Fatalf("expected truncated findings, got %#v", result["findings"])
	}
}

func TestUpsertReportComputesDeltaSummary(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanReportGVR: "ScanReportList",
	})
	runner := &Runner{
		dynamicClient: client,
	}

	firstGeneratedAt := metav1.NewTime(time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC))
	firstResult := report.BuildScanResultWithAttackPaths(
		[]policy.Finding{
			testFinding("finding-1", "KS010", policy.SeverityHigh, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
			testFinding("finding-2", "KS012", policy.SeverityMedium, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
		},
		nil,
	)
	if err := runner.upsertReport(context.Background(), "payments-hardening", "payments", v1alpha1.ScanReportSpec{}, v1alpha1.ScanReportStatus{
		Phase:       "Ready",
		GeneratedAt: &firstGeneratedAt,
		Result:      &firstResult,
	}); err != nil {
		t.Fatalf("first upsertReport returned error: %v", err)
	}

	secondGeneratedAt := metav1.NewTime(time.Date(2026, 3, 22, 10, 5, 0, 0, time.UTC))
	secondResult := report.BuildScanResultWithAttackPaths(
		[]policy.Finding{
			testFinding("finding-1", "KS010", policy.SeverityCritical, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
			testFinding("finding-3", "KS011", policy.SeverityHigh, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
		},
		[]attackpath.Result{
			{
				ID:       "AP001",
				Title:    "Public entry reaches node-compromise preconditions",
				Severity: policy.SeverityCritical,
				Entry:    policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
				Target:   "Node compromise preconditions",
				Path:     "Internet -> Service/api -> Deployment/api",
			},
		},
	)
	if err := runner.upsertReport(context.Background(), "payments-hardening", "payments", v1alpha1.ScanReportSpec{}, v1alpha1.ScanReportStatus{
		Phase:       "Ready",
		GeneratedAt: &secondGeneratedAt,
		Result:      &secondResult,
	}); err != nil {
		t.Fatalf("second upsertReport returned error: %v", err)
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "payments-hardening", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	status := nestedMap(t, reportObject.Object, "status")
	delta := nestedMap(t, status, "delta")
	if got := delta["hasChanges"]; got != true {
		t.Fatalf("expected delta.hasChanges true, got %#v", got)
	}
	if got := delta["findingsAdded"]; got != int64(1) {
		t.Fatalf("expected one added finding, got %#v", got)
	}
	if got := delta["findingsRemoved"]; got != int64(1) {
		t.Fatalf("expected one removed finding, got %#v", got)
	}
	if got := delta["findingsSeverityChanged"]; got != int64(1) {
		t.Fatalf("expected one severity-changed finding, got %#v", got)
	}
	if got := delta["attackPathsAdded"]; got != int64(1) {
		t.Fatalf("expected one added attack path, got %#v", got)
	}
	if got, ok := delta["attackPathsRemoved"]; ok && got != int64(0) {
		t.Fatalf("expected zero removed attack paths, got %#v", got)
	}
	if got := delta["resourcesChanged"]; got != int64(1) {
		t.Fatalf("expected one changed resource, got %#v", got)
	}
	resourceDeltas, ok := delta["resourceDeltas"].([]any)
	if !ok || len(resourceDeltas) != 1 {
		t.Fatalf("expected one resource delta, got %#v", delta["resourceDeltas"])
	}
	resourceDelta, ok := resourceDeltas[0].(map[string]any)
	if !ok {
		t.Fatalf("expected resource delta object, got %#v", resourceDeltas[0])
	}
	if got := resourceDelta["namespace"]; got != "payments" {
		t.Fatalf("expected payments namespace, got %#v", got)
	}
	if got := resourceDelta["kind"]; got != "Deployment" {
		t.Fatalf("expected Deployment kind, got %#v", got)
	}
	if got := resourceDelta["name"]; got != "api" {
		t.Fatalf("expected api name, got %#v", got)
	}
	if got := resourceDelta["findingsAdded"]; got != int64(1) {
		t.Fatalf("expected resource findingsAdded 1, got %#v", got)
	}
	if got := resourceDelta["findingsRemoved"]; got != int64(1) {
		t.Fatalf("expected resource findingsRemoved 1, got %#v", got)
	}
	if got := resourceDelta["findingsSeverityChanged"]; got != int64(1) {
		t.Fatalf("expected resource findingsSeverityChanged 1, got %#v", got)
	}
}

func TestUpsertReportDeliversNotificationsOnDeltaChange(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanReportGVR: "ScanReportList",
	})

	var eventCalls int
	var webhookCalls int
	var gotWebhookURLs []string
	var gotWebhookHeaders map[string]string
	var gotWebhookPayloads []map[string]any

	coreClient := kubefake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook-auth", Namespace: "payments"},
		Data: map[string][]byte{
			"token": []byte("delta-token"),
		},
	})
	runner := &Runner{
		dynamicClient: client,
		coreClient:    coreClient,
		now: func() time.Time {
			return time.Date(2026, 3, 22, 10, 10, 0, 0, time.UTC)
		},
		emitEvent: func(_ context.Context, namespace, objectName, eventType, reason, message string) error {
			eventCalls++
			if namespace != "payments" {
				t.Fatalf("expected payments event namespace, got %q", namespace)
			}
			if objectName != "payments-hardening" {
				t.Fatalf("expected payments-hardening event object, got %q", objectName)
			}
			if reason != "ScanDeltaChanged" {
				t.Fatalf("expected ScanDeltaChanged reason, got %q", reason)
			}
			if message == "" || eventType != "Normal" {
				t.Fatalf("expected populated event message and Normal type, got %q / %q", message, eventType)
			}
			return nil
		},
		postWebhook: func(_ context.Context, url string, headers map[string]string, payload []byte) error {
			webhookCalls++
			gotWebhookURLs = append(gotWebhookURLs, url)
			gotWebhookHeaders = headers
			var decoded map[string]any
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatalf("json.Unmarshal webhook payload: %v", err)
			}
			gotWebhookPayloads = append(gotWebhookPayloads, decoded)
			return nil
		},
	}

	firstGeneratedAt := metav1.NewTime(time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC))
	firstResult := report.BuildScanResult([]policy.Finding{
		testFinding("finding-1", "KS010", policy.SeverityHigh, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
	})
	if err := runner.upsertReport(context.Background(), "payments-hardening", "payments", v1alpha1.ScanReportSpec{
		Notification: &v1alpha1.NotificationSpec{
			EmitEvents:      true,
			WebhookURL:      "https://hooks.example.internal/kubescan",
			SlackWebhookURL: "https://hooks.slack.example.internal/services/abc",
			MinimumSeverity: "high",
			AuthSecretRef: &v1alpha1.SecretKeyRef{
				Name: "webhook-auth",
				Key:  "token",
			},
		},
	}, v1alpha1.ScanReportStatus{
		Phase:       "Ready",
		GeneratedAt: &firstGeneratedAt,
		Result:      &firstResult,
	}); err != nil {
		t.Fatalf("first upsertReport returned error: %v", err)
	}
	if eventCalls != 0 || webhookCalls != 0 {
		t.Fatalf("expected no notifications on initial create, got events=%d webhooks=%d", eventCalls, webhookCalls)
	}

	secondGeneratedAt := metav1.NewTime(time.Date(2026, 3, 22, 10, 10, 0, 0, time.UTC))
	secondResult := report.BuildScanResult([]policy.Finding{
		testFinding("finding-1", "KS010", policy.SeverityCritical, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
		testFinding("finding-2", "KS011", policy.SeverityHigh, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
	})
	if err := runner.upsertReport(context.Background(), "payments-hardening", "payments", v1alpha1.ScanReportSpec{
		Notification: &v1alpha1.NotificationSpec{
			EmitEvents:      true,
			WebhookURL:      "https://hooks.example.internal/kubescan",
			SlackWebhookURL: "https://hooks.slack.example.internal/services/abc",
			MinimumSeverity: "high",
			AuthSecretRef: &v1alpha1.SecretKeyRef{
				Name: "webhook-auth",
				Key:  "token",
			},
		},
	}, v1alpha1.ScanReportStatus{
		Phase:       "Ready",
		GeneratedAt: &secondGeneratedAt,
		Result:      &secondResult,
	}); err != nil {
		t.Fatalf("second upsertReport returned error: %v", err)
	}
	if eventCalls != 1 || webhookCalls != 2 {
		t.Fatalf("expected one event and two webhooks, got events=%d webhooks=%d", eventCalls, webhookCalls)
	}
	if gotWebhookURLs[0] != "https://hooks.example.internal/kubescan" || gotWebhookURLs[1] != "https://hooks.slack.example.internal/services/abc" {
		t.Fatalf("unexpected webhook urls %#v", gotWebhookURLs)
	}
	if gotWebhookHeaders["Authorization"] != "Bearer delta-token" {
		t.Fatalf("unexpected webhook headers %#v", gotWebhookHeaders)
	}
	if gotWebhookPayloads[0]["kind"] != "ScanReportDeltaNotification" {
		t.Fatalf("unexpected webhook payload kind %#v", gotWebhookPayloads[0]["kind"])
	}
	deltaPayload, ok := gotWebhookPayloads[0]["delta"].(map[string]any)
	if !ok {
		t.Fatalf("expected delta payload, got %#v", gotWebhookPayloads[0]["delta"])
	}
	if deltaPayload["hasChanges"] != true {
		t.Fatalf("expected webhook delta.hasChanges true, got %#v", deltaPayload["hasChanges"])
	}
	if gotWebhookPayloads[1]["text"] == nil {
		t.Fatalf("expected slack payload text, got %#v", gotWebhookPayloads[1])
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "payments-hardening", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	status := nestedMap(t, reportObject.Object, "status")
	notification := nestedMap(t, status, "notification")
	if got := notification["eventEmitted"]; got != true {
		t.Fatalf("expected eventEmitted true, got %#v", got)
	}
	if got := notification["webhookDelivered"]; got != true {
		t.Fatalf("expected webhookDelivered true, got %#v", got)
	}
	if got := notification["slackDelivered"]; got != true {
		t.Fatalf("expected slackDelivered true, got %#v", got)
	}
}

func TestUpsertReportDeliversHistoryWebhookOnInitialCreate(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanReportGVR: "ScanReportList",
	})

	var webhookCalls int
	var gotPayload map[string]any
	runner := &Runner{
		dynamicClient: client,
		now: func() time.Time {
			return time.Date(2026, 3, 22, 10, 20, 0, 0, time.UTC)
		},
		postWebhook: func(_ context.Context, url string, headers map[string]string, payload []byte) error {
			webhookCalls++
			if url != "https://history.example.internal/kubescan" {
				t.Fatalf("unexpected history webhook URL %q", url)
			}
			if len(headers) != 0 {
				t.Fatalf("did not expect auth headers for history webhook, got %#v", headers)
			}
			if err := json.Unmarshal(payload, &gotPayload); err != nil {
				t.Fatalf("json.Unmarshal history payload: %v", err)
			}
			return nil
		},
	}

	generatedAt := metav1.NewTime(time.Date(2026, 3, 22, 10, 20, 0, 0, time.UTC))
	result := report.BuildScanResult([]policy.Finding{
		testFinding("finding-1", "KS010", policy.SeverityHigh, policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}),
	})
	if err := runner.upsertReport(context.Background(), "payments-history", "payments", v1alpha1.ScanReportSpec{
		Notification: &v1alpha1.NotificationSpec{
			HistoryWebhookURL: "https://history.example.internal/kubescan",
		},
	}, v1alpha1.ScanReportStatus{
		Phase:       "Ready",
		GeneratedAt: &generatedAt,
		Result:      &result,
	}); err != nil {
		t.Fatalf("upsertReport returned error: %v", err)
	}
	if webhookCalls != 1 {
		t.Fatalf("expected one history webhook call, got %d", webhookCalls)
	}
	if gotPayload["kind"] != "ScanReportHistoryNotification" {
		t.Fatalf("unexpected history payload kind %#v", gotPayload["kind"])
	}
	if gotPayload["trend"] == nil {
		t.Fatalf("expected history payload trend, got %#v", gotPayload)
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "payments-history", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	status := nestedMap(t, reportObject.Object, "status")
	notification := nestedMap(t, status, "notification")
	if got := notification["historyWebhookDelivered"]; got != true {
		t.Fatalf("expected historyWebhookDelivered true, got %#v", got)
	}
	if notification["webhookDelivered"] == true || notification["slackDelivered"] == true || notification["eventEmitted"] == true {
		t.Fatalf("did not expect delta notification fields on initial history export, got %#v", notification)
	}
}

func TestUpsertReportMaintainsBoundedTrendHistory(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanReportGVR: "ScanReportList",
	})
	runner := &Runner{
		dynamicClient: client,
	}

	for i := 0; i < 14; i++ {
		generatedAt := metav1.NewTime(time.Date(2026, 3, 22, 11, i, 0, 0, time.UTC))
		findings := make([]policy.Finding, 0, i%3+1)
		for j := 0; j < i%3+1; j++ {
			findings = append(findings, testFinding(
				fmt.Sprintf("finding-%d-%d", i, j),
				"KS010",
				policy.SeverityHigh,
				policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
			))
		}
		result := report.BuildScanResult(findings)
		if err := runner.upsertReport(context.Background(), "payments-hardening", "payments", v1alpha1.ScanReportSpec{}, v1alpha1.ScanReportStatus{
			Phase:       "Ready",
			GeneratedAt: &generatedAt,
			Result:      &result,
		}); err != nil {
			t.Fatalf("upsertReport run %d returned error: %v", i, err)
		}
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "payments-hardening", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	status := nestedMap(t, reportObject.Object, "status")
	trend := nestedMap(t, status, "trend")
	if got := trend["totalRuns"]; got != int64(14) {
		t.Fatalf("expected totalRuns 14, got %#v", got)
	}
	if got := trend["windowSize"]; got != int64(12) {
		t.Fatalf("expected windowSize 12, got %#v", got)
	}
	if got := trend["highestRecentSeverity"]; got != "high" {
		t.Fatalf("expected highestRecentSeverity high, got %#v", got)
	}
	if got, ok := trend["consecutiveErrorRuns"]; ok && got != int64(0) {
		t.Fatalf("expected consecutiveErrorRuns 0, got %#v", got)
	}
	recentRuns, ok := trend["recentRuns"].([]any)
	if !ok || len(recentRuns) != 12 {
		t.Fatalf("expected 12 recent runs, got %#v", trend["recentRuns"])
	}
	firstRun, ok := recentRuns[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first recent run object, got %#v", recentRuns[0])
	}
	if got := firstRun["generatedAt"]; got != "2026-03-22T11:02:00Z" {
		t.Fatalf("expected earliest retained run at 11:02Z, got %#v", got)
	}
	lastRun, ok := recentRuns[len(recentRuns)-1].(map[string]any)
	if !ok {
		t.Fatalf("expected last recent run object, got %#v", recentRuns[len(recentRuns)-1])
	}
	if got := lastRun["generatedAt"]; got != "2026-03-22T11:13:00Z" {
		t.Fatalf("expected latest retained run at 11:13Z, got %#v", got)
	}
	if got := lastRun["highFindings"]; got != int64(2) {
		t.Fatalf("expected latest retained run highFindings 2, got %#v", got)
	}
	if got := trend["findingsDeltaFromLatest"]; got != int64(1) {
		t.Fatalf("expected findingsDeltaFromLatest 1, got %#v", got)
	}
}

func TestLoadSBOMSourceCachesRemoteSourcesUntilRefreshInterval(t *testing.T) {
	runner := &Runner{
		now: func() time.Time {
			return time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC)
		},
		remoteSBOMCache: map[string]cachedRemoteSBOMState{},
	}
	fetches := 0
	runner.fetchHTTPSBOM = func(_ context.Context, _ string, _ map[string]string) (vuln.SBOM, error) {
		fetches++
		version := "1.0.0"
		if fetches > 1 {
			version = "1.0.1"
		}
		return vuln.SBOM{
			ImageRef: "ghcr.io/acme/api:1.0.0",
			Packages: []vuln.Package{
				{Name: "app", Version: version, Ecosystem: "npm"},
			},
		}, nil
	}

	named := namedPolicy{
		Name: "payments-policy",
		Spec: v1alpha1.ScanPolicySpec{
			Namespace:           "payments",
			SBOMRefreshInterval: "10m",
		},
	}
	ref := v1alpha1.BundleRef{
		Kind: "HTTP",
		Name: "https://example.internal/api.sbom.json",
	}

	firstSBOM, firstStatus, err := runner.loadSBOMSource(context.Background(), named, ref)
	if err != nil {
		t.Fatalf("first loadSBOMSource returned error: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("expected first call to fetch once, got %d", fetches)
	}
	if firstStatus.Cached {
		t.Fatalf("did not expect first status to be cached")
	}
	if firstStatus.Changed {
		t.Fatalf("did not expect first status to be marked changed")
	}
	if firstStatus.NextRefreshAt == nil || firstStatus.NextRefreshAt.Time.Format(time.RFC3339) != "2026-03-22T12:10:00Z" {
		t.Fatalf("unexpected first nextRefreshAt %#v", firstStatus.NextRefreshAt)
	}

	runner.now = func() time.Time {
		return time.Date(2026, 3, 22, 12, 5, 0, 0, time.UTC)
	}
	secondSBOM, secondStatus, err := runner.loadSBOMSource(context.Background(), named, ref)
	if err != nil {
		t.Fatalf("second loadSBOMSource returned error: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("expected cached second call, got %d fetches", fetches)
	}
	if !secondStatus.Cached {
		t.Fatalf("expected second status to be cached")
	}
	if secondStatus.Changed {
		t.Fatalf("did not expect cached status to be marked changed")
	}
	if secondSBOM.Packages[0].Version != firstSBOM.Packages[0].Version {
		t.Fatalf("expected cached sbom version %q, got %q", firstSBOM.Packages[0].Version, secondSBOM.Packages[0].Version)
	}

	runner.now = func() time.Time {
		return time.Date(2026, 3, 22, 12, 11, 0, 0, time.UTC)
	}
	thirdSBOM, thirdStatus, err := runner.loadSBOMSource(context.Background(), named, ref)
	if err != nil {
		t.Fatalf("third loadSBOMSource returned error: %v", err)
	}
	if fetches != 2 {
		t.Fatalf("expected refresh after interval, got %d fetches", fetches)
	}
	if thirdStatus.Cached {
		t.Fatalf("did not expect refreshed status to be cached")
	}
	if !thirdStatus.Changed {
		t.Fatalf("expected refreshed status to be marked changed")
	}
	if thirdSBOM.Packages[0].Version != "1.0.1" {
		t.Fatalf("expected refreshed sbom version 1.0.1, got %q", thirdSBOM.Packages[0].Version)
	}
}

func TestRunOnceDefaultOnlyUsesNamespacedOptions(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	})
	collectedOptions := k8s.ClusterOptions{}
	runner := &Runner{
		dynamicClient: client,
		collect: func(_ context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
			collectedOptions = options
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 10, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{
			ClusterOptions: k8s.ClusterOptions{
				Namespace:      "payments",
				NamespacedOnly: true,
			},
			DefaultProfile:      policy.RuleProfileHardening,
			DefaultReportName:   "payments-hardening",
			DisablePolicyLookup: true,
		}),
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if collectedOptions.Namespace != "payments" {
		t.Fatalf("expected namespace payments, got %q", collectedOptions.Namespace)
	}
	if !collectedOptions.NamespacedOnly {
		t.Fatalf("expected namespacedOnly collection to be enabled")
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "payments-hardening", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	spec := nestedMap(t, reportObject.Object, "spec")
	if got := spec["profile"]; got != "hardening" {
		t.Fatalf("expected hardening profile, got %#v", got)
	}
	if got := spec["namespace"]; got != "payments" {
		t.Fatalf("expected payments namespace in default-only report spec, got %#v", got)
	}
}

func TestWatchedResourcesRespectsNamespacedAndDefaultOnlyModes(t *testing.T) {
	runner := &Runner{
		options: normalizeOptions(Options{
			ClusterOptions: k8s.ClusterOptions{
				Namespace:      "payments",
				NamespacedOnly: true,
			},
			DisablePolicyLookup: true,
		}),
	}

	resources := runner.watchedResources()
	for _, resource := range resources {
		if resource.gvr == scanPolicyGVR {
			t.Fatalf("did not expect scanpolicy watch in default-only mode")
		}
		if resource.gvr.Resource == "nodes" || resource.gvr.Resource == "namespaces" || resource.gvr.Resource == "clusterroles" || resource.gvr.Resource == "clusterrolebindings" {
			t.Fatalf("did not expect cluster-scoped watch %s in namespaced-only mode", resource.gvr.Resource)
		}
	}
}

func TestRunLoopDebouncesWatchTriggeredRescans(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	})
	var collects atomic.Int32
	runner := &Runner{
		dynamicClient: client,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			collects.Add(1)
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 15, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{
			Interval:            time.Hour,
			Watch:               true,
			WatchDebounce:       20 * time.Millisecond,
			DefaultProfile:      policy.RuleProfileDefault,
			DefaultReportName:   "cluster-default",
			DisablePolicyLookup: true,
		}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	triggerCh := make(chan rescanTrigger, 4)
	done := make(chan error, 1)
	go func() {
		done <- runner.runLoop(ctx, triggerCh)
	}()

	time.Sleep(15 * time.Millisecond)
	sendTrigger(triggerCh, rescanTrigger{namespace: "payments"})
	sendTrigger(triggerCh, rescanTrigger{namespace: "payments"})
	sendTrigger(triggerCh, rescanTrigger{namespace: "payments"})
	time.Sleep(80 * time.Millisecond)
	cancel()

	err := <-done
	if err != context.Canceled {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if got := collects.Load(); got != 2 {
		t.Fatalf("expected initial scan plus one debounced rescan, got %d collects", got)
	}
}

func TestRunForPendingReconcilesOnlyMatchingPolicyNamespaces(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "payments-hardening",
			},
			"spec": map[string]any{
				"namespace": "payments",
				"profile":   "hardening",
			},
		},
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "shipping-hardening",
			},
			"spec": map[string]any{
				"namespace": "shipping",
				"profile":   "hardening",
			},
		},
	})

	var mu sync.Mutex
	collectedNamespaces := []string{}
	runner := &Runner{
		dynamicClient: client,
		collect: func(_ context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
			mu.Lock()
			collectedNamespaces = append(collectedNamespaces, options.Namespace)
			mu.Unlock()
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource: policy.ResourceRef{Kind: "Deployment", Namespace: options.Namespace, Name: "api"},
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 20, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{}),
	}

	if err := runner.runForPending(context.Background(), pendingRescan{}.with(rescanTrigger{namespace: "payments"})); err != nil {
		t.Fatalf("runForPending returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(collectedNamespaces) != 1 {
		t.Fatalf("expected 1 namespace-specific reconciliation, got %v", collectedNamespaces)
	}
	if collectedNamespaces[0] != "payments" {
		t.Fatalf("expected payments-only reconciliation, got %v", collectedNamespaces)
	}
}

func TestRunForPendingMatchesClusterWideIncludeNamespaces(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "public-scope",
			},
			"spec": map[string]any{
				"profile":           "hardening",
				"includeNamespaces": []any{"public"},
			},
		},
	})

	var collects atomic.Int32
	runner := &Runner{
		dynamicClient: client,
		collect: func(_ context.Context, _ k8s.ClusterOptions) (policy.Inventory, error) {
			collects.Add(1)
			return policy.Inventory{}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 25, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{}),
	}

	if err := runner.runForPending(context.Background(), pendingRescan{}.with(rescanTrigger{namespace: "private"})); err != nil {
		t.Fatalf("runForPending returned error: %v", err)
	}
	if collects.Load() != 0 {
		t.Fatalf("expected no reconciliation for excluded namespace event")
	}

	if err := runner.runForPending(context.Background(), pendingRescan{}.with(rescanTrigger{namespace: "public"})); err != nil {
		t.Fatalf("runForPending returned error: %v", err)
	}
	if collects.Load() != 1 {
		t.Fatalf("expected one reconciliation for included namespace event, got %d", collects.Load())
	}
}

func TestRunForPendingMatchesPolicyIncludeKinds(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "services-only",
			},
			"spec": map[string]any{
				"namespace":    "payments",
				"profile":      "hardening",
				"includeKinds": []any{"Service"},
			},
		},
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "deployments-only",
			},
			"spec": map[string]any{
				"namespace":    "payments",
				"profile":      "hardening",
				"includeKinds": []any{"Deployment"},
			},
		},
	})

	var mu sync.Mutex
	collectedNamespaces := []string{}
	runner := &Runner{
		dynamicClient: client,
		collect: func(_ context.Context, options k8s.ClusterOptions) (policy.Inventory, error) {
			mu.Lock()
			collectedNamespaces = append(collectedNamespaces, options.Namespace)
			mu.Unlock()
			return policy.Inventory{}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 22, 9, 0, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{}),
	}

	if err := runner.runForPending(context.Background(), pendingRescan{}.with(rescanTrigger{
		namespace: "payments",
		kind:      "Service",
		name:      "api",
	})); err != nil {
		t.Fatalf("runForPending returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(collectedNamespaces) != 1 {
		t.Fatalf("expected one reconciliation for matching kind, got %v", collectedNamespaces)
	}
}

func TestRunForPendingSkipsExcludedKinds(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "skip-services",
			},
			"spec": map[string]any{
				"namespace":    "payments",
				"profile":      "hardening",
				"excludeKinds": []any{"Service"},
			},
		},
	})

	var collects atomic.Int32
	runner := &Runner{
		dynamicClient: client,
		collect: func(_ context.Context, _ k8s.ClusterOptions) (policy.Inventory, error) {
			collects.Add(1)
			return policy.Inventory{}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 22, 9, 5, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{}),
	}

	if err := runner.runForPending(context.Background(), pendingRescan{}.with(rescanTrigger{
		namespace: "payments",
		kind:      "Service",
		name:      "api",
	})); err != nil {
		t.Fatalf("runForPending returned error: %v", err)
	}
	if collects.Load() != 0 {
		t.Fatalf("expected excluded kind to skip reconciliation, got %d collects", collects.Load())
	}
}

func TestTriggerFromEventCarriesKindAndNamespace(t *testing.T) {
	trigger := triggerFromEvent(watchedResource{scope: "namespace"}, watch.Event{
		Type: watch.Modified,
		Object: &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "api",
				"namespace": "payments",
			},
		}},
	})

	if trigger.full {
		t.Fatalf("did not expect full trigger")
	}
	if trigger.namespace != "payments" {
		t.Fatalf("expected payments namespace, got %q", trigger.namespace)
	}
	if trigger.kind != "deployment" {
		t.Fatalf("expected deployment kind, got %q", trigger.kind)
	}
	if trigger.name != "api" {
		t.Fatalf("expected api name, got %q", trigger.name)
	}
}

func TestEvaluatePolicyLoadsSignedBundlesFromClusterRefs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	policyBundle := mustSignedBundleYAML(t, privateKey, "policy-controls", map[string]any{
		"apiVersion": "kubescan.automatesecurity.github.io/v1alpha1",
		"kind":       "PolicyControls",
		"suppressions": []map[string]any{
			{"ruleId": "KS010"},
		},
	})
	rulesBundle := mustSignedBundleYAML(t, privateKey, "rules", map[string]any{
		"apiVersion": "kubescan.automatesecurity.github.io/v1alpha1",
		"kind":       "RuleBundle",
		"rules": []map[string]any{
			{"id": "KS003", "severity": "critical"},
		},
	})
	advisoriesBundle := mustSignedBundleYAML(t, privateKey, "advisories", vuln.AdvisoryBundle{
		Advisories: []vuln.Advisory{
			{
				ID:               "CVE-2026-9999",
				Summary:          "kubelet test advisory",
				PackageName:      "kubelet",
				Ecosystem:        "kubernetes",
				AffectedVersions: []string{"=v1.31.0"},
				Severity:         policy.SeverityHigh,
				FixedVersion:     "v1.31.1",
			},
			{
				ID:               "CVE-2026-4242",
				Summary:          "nginx package test advisory",
				PackageName:      "nginx",
				Ecosystem:        "deb",
				AffectedVersions: []string{"=1.25.0"},
				Severity:         policy.SeverityCritical,
				FixedVersion:     "1.25.1",
			},
		},
	})
	sbomContent := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "container",
      "name": "nginx:latest"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "nginx",
      "version": "1.25.0",
      "purl": "pkg:deb/debian/nginx@1.25.0"
    }
  ]
}`)
	publicKeyPEM, err := x509MarshalPublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.SBOMReportKind,
			"metadata": map[string]any{
				"name":      "nginx-workload",
				"namespace": "payments",
				"labels": map[string]any{
					"security.automatesecurity.github.io/sbom": "true",
				},
			},
			"spec": map[string]any{
				"imageRef": "nginx:latest",
				"format":   "cyclonedx-json",
				"content":  string(sbomContent),
			},
		},
	})

	coreClient := kubefake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-bundle", Namespace: "payments"},
			Data:       map[string]string{"bundle.yaml": string(policyBundle)},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "rules-bundle", Namespace: "payments"},
			Data:       map[string]string{"bundle.yaml": string(rulesBundle)},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "advisories-bundle", Namespace: "payments"},
			Data:       map[string]string{"bundle.yaml": string(advisoriesBundle)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "bundle-key", Namespace: "payments"},
			Data:       map[string][]byte{"public.pem": publicKeyPEM},
		},
	)

	runner := &Runner{
		dynamicClient: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			scanPolicyGVR: "ScanPolicyList",
			scanReportGVR: "ScanReportList",
			sbomReportGVR: "SBOMReportList",
		}),
		coreClient: coreClient,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			runAsNonRoot := false
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest", RunAsNonRoot: &runAsNonRoot},
						},
					},
				},
				Components: []policy.ClusterComponent{
					{
						Resource:  policy.ResourceRef{Kind: "Node", Name: "worker-1"},
						Name:      "kubelet",
						Version:   "v1.31.0",
						Ecosystem: "kubernetes",
						Source:    "node.status.nodeInfo.kubeletVersion",
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 30, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{}),
	}
	runner.dynamicClient = dynamicClient

	result, statuses, usedCachedSources, err := runner.evaluatePolicy(context.Background(), namedPolicy{
		Name: "payments-bundles",
		Spec: v1alpha1.ScanPolicySpec{
			Namespace:      "payments",
			Profile:        "hardening",
			ComponentVulns: true,
			BundleKeyRef: &v1alpha1.BundleRef{
				Kind: "Secret", Name: "bundle-key", Key: "public.pem",
			},
			PolicyBundleRef: &v1alpha1.BundleRef{
				Kind: "ConfigMap", Name: "policy-bundle", Key: "bundle.yaml",
			},
			RulesBundleRef: &v1alpha1.BundleRef{
				Kind: "ConfigMap", Name: "rules-bundle", Key: "bundle.yaml",
			},
			AdvisoriesBundleRef: &v1alpha1.BundleRef{
				Kind: "ConfigMap", Name: "advisories-bundle", Key: "bundle.yaml",
			},
			SBOMSelector: "security.automatesecurity.github.io/sbom=true",
		},
	})
	if err != nil {
		t.Fatalf("evaluatePolicy returned error: %v", err)
	}
	if usedCachedSources {
		t.Fatalf("did not expect cached bundle sources on initial evaluation")
	}
	if len(statuses) == 0 {
		t.Fatalf("expected populated source statuses")
	}

	if hasRule(result.Findings, "KS010") {
		t.Fatalf("expected KS010 to be suppressed by policy bundle, got %+v", result.Findings)
	}
	if !hasRuleSeverity(result.Findings, "KS003", policy.SeverityCritical) {
		t.Fatalf("expected KS003 critical from rules bundle, got %+v", result.Findings)
	}
	if !hasRule(result.Findings, "CVE-2026-9999") {
		t.Fatalf("expected component advisory finding from advisories bundle, got %+v", result.Findings)
	}
	if !hasRule(result.Findings, "CVE-2026-4242") {
		t.Fatalf("expected workload advisory finding from sbom refs and advisories bundle, got %+v", result.Findings)
	}
}

func TestEvaluatePolicyUsesCachedBundlesOnFailureWhenConfigured(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	policyBundle := mustSignedBundleYAML(t, privateKey, "policy-controls", map[string]any{
		"apiVersion": "kubescan.automatesecurity.github.io/v1alpha1",
		"kind":       "PolicyControls",
		"suppressions": []map[string]any{
			{"ruleId": "KS010"},
		},
	})
	publicKeyPEM, err := x509MarshalPublicKeyPEM(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	coreClient := kubefake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-bundle", Namespace: "payments"},
			Data:       map[string]string{"bundle.yaml": string(policyBundle)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "bundle-key", Namespace: "payments"},
			Data:       map[string][]byte{"public.pem": publicKeyPEM},
		},
	)

	runner := &Runner{
		dynamicClient: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			scanPolicyGVR: "ScanPolicyList",
			scanReportGVR: "ScanReportList",
			sbomReportGVR: "SBOMReportList",
		}),
		coreClient: coreClient,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			return policy.Inventory{
				Workloads: []policy.Workload{
					{
						Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
						Containers: []policy.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
			}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 40, 0, 0, time.UTC)
		},
		options:     normalizeOptions(Options{}),
		bundleCache: map[string]cachedSourceState{},
	}

	named := namedPolicy{
		Name: "payments-bundles",
		Spec: v1alpha1.ScanPolicySpec{
			Namespace:           "payments",
			Profile:             "hardening",
			BundleFailurePolicy: bundleFailurePolicyUseLastGood,
			BundleKeyRef: &v1alpha1.BundleRef{
				Kind: "Secret", Name: "bundle-key", Key: "public.pem",
			},
			PolicyBundleRef: &v1alpha1.BundleRef{
				Kind: "ConfigMap", Name: "policy-bundle", Key: "bundle.yaml",
			},
		},
	}

	firstResult, _, usedCachedSources, err := runner.evaluatePolicy(context.Background(), named)
	if err != nil {
		t.Fatalf("initial evaluatePolicy returned error: %v", err)
	}
	if usedCachedSources {
		t.Fatalf("did not expect cached bundles on first evaluation")
	}
	if hasRule(firstResult.Findings, "KS010") {
		t.Fatalf("expected KS010 to be suppressed by fresh policy bundle")
	}

	if err := coreClient.CoreV1().ConfigMaps("payments").Delete(context.Background(), "policy-bundle", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete policy bundle configmap: %v", err)
	}

	secondResult, statuses, usedCachedSources, err := runner.evaluatePolicy(context.Background(), named)
	if err != nil {
		t.Fatalf("cached evaluatePolicy returned error: %v", err)
	}
	if !usedCachedSources {
		t.Fatalf("expected cached sources to be used after bundle load failure")
	}
	if hasRule(secondResult.Findings, "KS010") {
		t.Fatalf("expected cached policy bundle to keep suppressing KS010")
	}
	if len(statuses) == 0 || !statuses[0].Cached || statuses[0].Phase != "UsingCached" {
		t.Fatalf("expected cached source statuses, got %#v", statuses)
	}
	if statuses[0].LastError == "" {
		t.Fatalf("expected cached source status to record the fresh load error")
	}
}

func TestLoadSBOMSourceFromHTTPUsesSecretHeaders(t *testing.T) {
	coreClient := kubefake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "http-auth", Namespace: "payments"},
			Data:       map[string][]byte{"token": []byte("secret-token")},
		},
	)

	var receivedURL string
	var receivedHeaders map[string]string
	runner := &Runner{
		coreClient: coreClient,
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 45, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{ClusterOptions: k8s.ClusterOptions{Namespace: "payments"}}),
		fetchHTTPSBOM: func(_ context.Context, targetURL string, headers map[string]string) (vuln.SBOM, error) {
			receivedURL = targetURL
			receivedHeaders = headers
			return vuln.SBOM{
				ImageRef: "registry.internal/acme/api@sha256:1234",
				Packages: []vuln.Package{{Name: "nginx", Version: "1.25.0", Ecosystem: "deb"}},
			}, nil
		},
	}

	sbom, status, err := runner.loadSBOMSource(context.Background(), namedPolicy{
		Name: "remote-sbom",
		Spec: v1alpha1.ScanPolicySpec{Namespace: "payments"},
	}, v1alpha1.BundleRef{
		Kind: "HTTP",
		Name: "https://sboms.example.com/api.json",
		AuthSecretRef: &v1alpha1.SecretKeyRef{
			Name: "http-auth",
			Key:  "token",
		},
	})
	if err != nil {
		t.Fatalf("loadSBOMSource returned error: %v", err)
	}
	if receivedURL != "https://sboms.example.com/api.json" {
		t.Fatalf("unexpected URL %q", receivedURL)
	}
	if got := receivedHeaders["Authorization"]; got != "Bearer secret-token" {
		t.Fatalf("expected bearer auth header, got %#v", receivedHeaders)
	}
	if sbom.ImageRef != "registry.internal/acme/api@sha256:1234" {
		t.Fatalf("unexpected normalized sbom image ref %q", sbom.ImageRef)
	}
	if status.Phase != "Ready" || status.Description == "" {
		t.Fatalf("expected ready status with description, got %#v", status)
	}
}

func TestLoadSBOMSourceFromGitHubReleaseAsset(t *testing.T) {
	coreClient := kubefake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "github-auth", Namespace: "security"},
		Data:       map[string][]byte{"token": []byte("ghp_test")},
	})
	var gotReleaseRef string
	var gotAssetName string
	var gotHeaders map[string]string
	runner := &Runner{
		coreClient: coreClient,
		now: func() time.Time {
			return time.Date(2026, 3, 22, 14, 0, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{ClusterOptions: k8s.ClusterOptions{Namespace: "security"}}),
		fetchGitHubSBOM: func(_ context.Context, releaseRef string, assetName string, headers map[string]string) (vuln.SBOM, error) {
			gotReleaseRef = releaseRef
			gotAssetName = assetName
			gotHeaders = headers
			return vuln.SBOM{
				ImageRef: "ghcr.io/acme/api@sha256:beef",
				Packages: []vuln.Package{{Name: "app", Version: "1.2.3", Ecosystem: "npm"}},
			}, nil
		},
	}

	sbom, status, err := runner.loadSBOMSource(context.Background(), namedPolicy{
		Name: "remote-github-sbom",
		Spec: v1alpha1.ScanPolicySpec{
			Namespace:           "security",
			SBOMRefreshInterval: "30m",
		},
	}, v1alpha1.BundleRef{
		Kind: "GitHubReleaseAsset",
		Name: "automatesecurity/kubescan@v1.0.0",
		Key:  "kubescan.sbom.json",
		AuthSecretRef: &v1alpha1.SecretKeyRef{
			Name:      "github-auth",
			Namespace: "security",
			Key:       "token",
		},
	})
	if err != nil {
		t.Fatalf("loadSBOMSource returned error: %v", err)
	}
	if gotReleaseRef != "automatesecurity/kubescan@v1.0.0" || gotAssetName != "kubescan.sbom.json" {
		t.Fatalf("unexpected github release inputs %q %q", gotReleaseRef, gotAssetName)
	}
	if gotHeaders["Authorization"] != "Bearer ghp_test" {
		t.Fatalf("unexpected github auth headers %#v", gotHeaders)
	}
	if sbom.ImageRef != "ghcr.io/acme/api@sha256:beef" {
		t.Fatalf("unexpected sbom image ref %q", sbom.ImageRef)
	}
	if status.Kind != "GitHubReleaseAsset" || status.Phase != "Ready" || status.NextRefreshAt == nil {
		t.Fatalf("unexpected source status %#v", status)
	}
}

func TestLoadSBOMSourceFromOCIImageUsesSecretCredentials(t *testing.T) {
	coreClient := kubefake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "oci-auth", Namespace: "payments"},
			Data: map[string][]byte{
				"creds": []byte(`{"username":"robot","password":"s3cr3t"}`),
			},
		},
	)

	var receivedImage string
	var receivedAuth imagescan.AuthOptions
	runner := &Runner{
		coreClient: coreClient,
		now: func() time.Time {
			return time.Date(2026, 3, 21, 12, 50, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{ClusterOptions: k8s.ClusterOptions{Namespace: "payments"}}),
		extractSBOM: func(_ context.Context, imageRef string, auth imagescan.AuthOptions) (vuln.SBOM, error) {
			receivedImage = imageRef
			receivedAuth = auth
			return vuln.SBOM{
				ImageRef: imageRef,
				Packages: []vuln.Package{{Name: "openssl", Version: "3.0.0", Ecosystem: "rpm"}},
			}, nil
		},
	}

	sbom, status, err := runner.loadSBOMSource(context.Background(), namedPolicy{
		Name: "oci-sbom",
		Spec: v1alpha1.ScanPolicySpec{Namespace: "payments"},
	}, v1alpha1.BundleRef{
		Kind: "OCIImage",
		Name: "registry.internal/acme/api:1.0.0",
		AuthSecretRef: &v1alpha1.SecretKeyRef{
			Name: "oci-auth",
			Key:  "creds",
		},
	})
	if err != nil {
		t.Fatalf("loadSBOMSource returned error: %v", err)
	}
	if receivedImage != "registry.internal/acme/api:1.0.0" {
		t.Fatalf("unexpected image ref %q", receivedImage)
	}
	if receivedAuth.Username != "robot" || receivedAuth.Password != "s3cr3t" {
		t.Fatalf("unexpected extracted auth %#v", receivedAuth)
	}
	if sbom.ImageRef != "registry.internal/acme/api:1.0.0" {
		t.Fatalf("unexpected sbom image ref %q", sbom.ImageRef)
	}
	if status.Phase != "Ready" || status.Description == "" {
		t.Fatalf("expected ready status with description, got %#v", status)
	}
}

func TestRunBackgroundSourceRefreshReconcilesWhenRemoteSBOMChanges(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "remote-sbom",
			},
			"spec": map[string]any{
				"namespace":           "payments",
				"profile":             "default",
				"sbomRefreshInterval": "30m",
				"sbomRefs": []any{
					map[string]any{
						"kind": "HTTP",
						"name": "https://sboms.example.com/api.json",
					},
				},
			},
		},
	})

	var collects atomic.Int32
	var fetches atomic.Int32
	currentTime := time.Date(2026, 3, 22, 15, 0, 0, 0, time.UTC)
	runner := &Runner{
		dynamicClient: client,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			collects.Add(1)
			return policy.Inventory{}, nil
		},
		now: func() time.Time {
			return currentTime
		},
		options: normalizeOptions(Options{}),
		fetchHTTPSBOM: func(_ context.Context, _ string, _ map[string]string) (vuln.SBOM, error) {
			call := fetches.Add(1)
			imageRef := "registry.internal/acme/api@sha256:1111"
			if call > 1 {
				imageRef = "registry.internal/acme/api@sha256:2222"
			}
			return vuln.SBOM{
				ImageRef: imageRef,
				Packages: []vuln.Package{{Name: "openssl", Version: "3.0.0", Ecosystem: "rpm"}},
			}, nil
		},
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if collects.Load() != 1 {
		t.Fatalf("expected one initial collect, got %d", collects.Load())
	}
	currentTime = currentTime.Add(31 * time.Minute)

	if err := runner.runBackgroundSourceRefresh(context.Background()); err != nil {
		t.Fatalf("runBackgroundSourceRefresh returned error: %v", err)
	}
	if collects.Load() != 2 {
		t.Fatalf("expected background refresh to trigger one additional reconcile, got %d collects", collects.Load())
	}
	if fetches.Load() != 2 {
		t.Fatalf("expected two remote fetches total, got %d", fetches.Load())
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "remote-sbom", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	status := nestedMap(t, reportObject.Object, "status")
	sourceStatuses, ok := status["sourceStatuses"].([]any)
	if !ok || len(sourceStatuses) != 1 {
		t.Fatalf("expected one source status, got %#v", status["sourceStatuses"])
	}
	sourceStatus, ok := sourceStatuses[0].(map[string]any)
	if !ok {
		t.Fatalf("expected source status object, got %#v", sourceStatuses[0])
	}
	if sourceStatus["changed"] != true {
		t.Fatalf("expected changed=true after background refresh, got %#v", sourceStatus["changed"])
	}
	if got := sourceStatus["digest"]; got == nil || got == "sha256:1111" {
		t.Fatalf("expected updated source digest, got %#v", got)
	}
}

func TestRunBackgroundSourceRefreshCachesRemoteSBOMErrorsUntilNextWindow(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "remote-sbom-error",
			},
			"spec": map[string]any{
				"namespace":           "payments",
				"profile":             "default",
				"sbomRefreshInterval": "30m",
				"sbomRefs": []any{
					map[string]any{
						"kind": "HTTP",
						"name": "https://sboms.example.com/api.json",
					},
				},
			},
		},
	})

	var collects atomic.Int32
	var fetches atomic.Int32
	currentTime := time.Date(2026, 3, 22, 16, 0, 0, 0, time.UTC)
	runner := &Runner{
		dynamicClient: client,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			collects.Add(1)
			return policy.Inventory{}, nil
		},
		now: func() time.Time {
			return currentTime
		},
		options: normalizeOptions(Options{}),
		fetchHTTPSBOM: func(_ context.Context, _ string, _ map[string]string) (vuln.SBOM, error) {
			call := fetches.Add(1)
			if call == 1 {
				return vuln.SBOM{
					ImageRef: "registry.internal/acme/api@sha256:1111",
					Packages: []vuln.Package{{Name: "openssl", Version: "3.0.0", Ecosystem: "rpm"}},
				}, nil
			}
			return vuln.SBOM{}, fmt.Errorf("upstream temporarily unavailable")
		},
	}

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	currentTime = currentTime.Add(31 * time.Minute)

	err := runner.runBackgroundSourceRefresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "upstream temporarily unavailable") {
		t.Fatalf("expected background refresh error, got %v", err)
	}
	if collects.Load() != 2 {
		t.Fatalf("expected one error-driven reconcile after refresh failure, got %d collects", collects.Load())
	}
	if fetches.Load() != 2 {
		t.Fatalf("expected a single failed refresh fetch, got %d fetches", fetches.Load())
	}

	reportObject, err := client.Resource(scanReportGVR).Get(context.Background(), "remote-sbom-error", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get scan report: %v", err)
	}
	status := nestedMap(t, reportObject.Object, "status")
	if got := status["phase"]; got != "Error" {
		t.Fatalf("expected report phase Error after cached refresh failure, got %#v", got)
	}
	if got := status["lastError"]; !strings.Contains(fmt.Sprint(got), "upstream temporarily unavailable") {
		t.Fatalf("expected report lastError to include refresh failure, got %#v", got)
	}

	currentTime = currentTime.Add(5 * time.Minute)
	err = runner.runBackgroundSourceRefresh(context.Background())
	if err != nil {
		t.Fatalf("expected no second refresh attempt before next window, got %v", err)
	}
	if collects.Load() != 2 {
		t.Fatalf("expected no additional reconcile before next refresh window, got %d collects", collects.Load())
	}
	if fetches.Load() != 2 {
		t.Fatalf("expected no additional fetch before next refresh window, got %d fetches", fetches.Load())
	}
}

func TestRunForPendingPrunesStaleManagedReports(t *testing.T) {
	oldTime := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		scanPolicyGVR: "ScanPolicyList",
		scanReportGVR: "ScanReportList",
		sbomReportGVR: "SBOMReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanPolicyKind,
			"metadata": map[string]any{
				"name": "active",
			},
			"spec": map[string]any{
				"namespace": "payments",
				"profile":   "default",
			},
		},
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.ScanReportKind,
			"metadata": map[string]any{
				"name": "orphaned",
				"labels": map[string]any{
					"app.kubernetes.io/managed-by": "kubescan",
				},
			},
			"spec": map[string]any{
				"policyName": "orphaned",
				"profile":    "default",
			},
			"status": map[string]any{
				"generatedAt": oldTime.Format(time.RFC3339),
			},
		},
	})

	runner := &Runner{
		dynamicClient: client,
		collect: func(context.Context, k8s.ClusterOptions) (policy.Inventory, error) {
			return policy.Inventory{}, nil
		},
		now: func() time.Time {
			return time.Date(2026, 3, 21, 13, 0, 0, 0, time.UTC)
		},
		options: normalizeOptions(Options{
			PruneStaleReports: true,
			ReportTTL:         6 * time.Hour,
		}),
	}

	if err := runner.runForPending(context.Background(), pendingRescan{full: true}); err != nil {
		t.Fatalf("runForPending returned error: %v", err)
	}

	if _, err := client.Resource(scanReportGVR).Get(context.Background(), "active", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected active report to exist: %v", err)
	}
	if _, err := client.Resource(scanReportGVR).Get(context.Background(), "orphaned", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected orphaned report to be deleted, got %v", err)
	}
}

func nestedMap(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	nested, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected map for key %q, got %#v", key, value)
	}
	return nested
}

func hasRule(findings []policy.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func hasRuleSeverity(findings []policy.Finding, ruleID string, severity policy.Severity) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID && finding.Severity == severity {
			return true
		}
	}
	return false
}

func testFinding(id, ruleID string, severity policy.Severity, resource policy.ResourceRef) policy.Finding {
	return policy.Finding{
		ID:          id,
		Category:    policy.CategoryMisconfig,
		RuleID:      ruleID,
		Title:       ruleID,
		Severity:    severity,
		RuleVersion: "1.0.0",
		Resource:    resource,
		Message:     ruleID + " message",
		Remediation: "fix it",
		Timestamp:   time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC),
	}
}

func mustSignedBundleYAML(t *testing.T, privateKey ed25519.PrivateKey, bundleType string, payload any) []byte {
	t.Helper()
	payloadBytes, err := yaml.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal bundle payload: %v", err)
	}
	signedBundle := bundle.SignedBundle{
		APIVersion: bundle.SignedBundleAPIVersion,
		Kind:       "SignedBundle",
		Metadata: bundle.BundleMetadata{
			Type:      bundleType,
			Algorithm: "ed25519",
		},
		Payload: string(payloadBytes),
	}
	envelope, err := signedBundleContent(signedBundle)
	if err != nil {
		t.Fatalf("encode signed bundle envelope: %v", err)
	}
	signedBundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, envelope))
	content, err := yaml.Marshal(signedBundle)
	if err != nil {
		t.Fatalf("marshal signed bundle: %v", err)
	}
	return content
}

func signedBundleContent(bundleObject bundle.SignedBundle) ([]byte, error) {
	envelope := struct {
		APIVersion string                `json:"apiVersion,omitempty"`
		Kind       string                `json:"kind"`
		Metadata   bundle.BundleMetadata `json:"metadata"`
		Payload    string                `json:"payload"`
	}{
		APIVersion: bundleObject.APIVersion,
		Kind:       bundleObject.Kind,
		Metadata:   bundleObject.Metadata,
		Payload:    bundleObject.Payload,
	}
	return json.Marshal(envelope)
}

func x509MarshalPublicKeyPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	block := pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return pem.EncodeToMemory(&block), nil
}
