package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubescan/pkg/report"
)

const (
	GroupName      = "security.automatesecurity.github.io"
	Version        = "v1alpha1"
	ScanPolicyKind = "ScanPolicy"
	ScanReportKind = "ScanReport"
	SBOMReportKind = "SBOMReport"
	NodeReportKind = "NodeReport"
)

type ScanPolicy struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec       ScanPolicySpec    `json:"spec,omitempty"`
}

type ScanPolicySpec struct {
	Namespace           string            `json:"namespace,omitempty"`
	Profile             string            `json:"profile,omitempty"`
	Compliance          string            `json:"compliance,omitempty"`
	AttackPaths         bool              `json:"attackPaths,omitempty"`
	ComponentVulns      bool              `json:"componentVulns,omitempty"`
	Notification        *NotificationSpec `json:"notification,omitempty"`
	SBOMRefreshInterval string            `json:"sbomRefreshInterval,omitempty"`
	BundleFailurePolicy string            `json:"bundleFailurePolicy,omitempty"`
	Suspend             bool              `json:"suspend,omitempty"`
	IncludeKinds        []string          `json:"includeKinds,omitempty"`
	ExcludeKinds        []string          `json:"excludeKinds,omitempty"`
	IncludeNamespaces   []string          `json:"includeNamespaces,omitempty"`
	ExcludeNamespaces   []string          `json:"excludeNamespaces,omitempty"`
	BundleKeyRef        *BundleRef        `json:"bundleKeyRef,omitempty"`
	PolicyBundleRef     *BundleRef        `json:"policyBundleRef,omitempty"`
	RulesBundleRef      *BundleRef        `json:"rulesBundleRef,omitempty"`
	AdvisoriesBundleRef *BundleRef        `json:"advisoriesBundleRef,omitempty"`
	SBOMRefs            []BundleRef       `json:"sbomRefs,omitempty"`
	SBOMSelector        string            `json:"sbomSelector,omitempty"`
}

type ScanReport struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec       ScanReportSpec    `json:"spec,omitempty"`
	Status     ScanReportStatus  `json:"status,omitempty"`
}

type ScanReportSpec struct {
	PolicyName          string            `json:"policyName,omitempty"`
	Namespace           string            `json:"namespace,omitempty"`
	Profile             string            `json:"profile,omitempty"`
	Compliance          string            `json:"compliance,omitempty"`
	AttackPaths         bool              `json:"attackPaths,omitempty"`
	ComponentVulns      bool              `json:"componentVulns,omitempty"`
	Notification        *NotificationSpec `json:"notification,omitempty"`
	SBOMRefreshInterval string            `json:"sbomRefreshInterval,omitempty"`
	BundleFailurePolicy string            `json:"bundleFailurePolicy,omitempty"`
	IncludeKinds        []string          `json:"includeKinds,omitempty"`
	ExcludeKinds        []string          `json:"excludeKinds,omitempty"`
	IncludeNamespaces   []string          `json:"includeNamespaces,omitempty"`
	ExcludeNamespaces   []string          `json:"excludeNamespaces,omitempty"`
	BundleKeyRef        *BundleRef        `json:"bundleKeyRef,omitempty"`
	PolicyBundleRef     *BundleRef        `json:"policyBundleRef,omitempty"`
	RulesBundleRef      *BundleRef        `json:"rulesBundleRef,omitempty"`
	AdvisoriesBundleRef *BundleRef        `json:"advisoriesBundleRef,omitempty"`
	SBOMRefs            []BundleRef       `json:"sbomRefs,omitempty"`
	SBOMSelector        string            `json:"sbomSelector,omitempty"`
}

type BundleRef struct {
	Kind          string        `json:"kind,omitempty"`
	Name          string        `json:"name,omitempty"`
	Namespace     string        `json:"namespace,omitempty"`
	Key           string        `json:"key,omitempty"`
	AuthSecretRef *SecretKeyRef `json:"authSecretRef,omitempty"`
}

type SecretKeyRef struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key,omitempty"`
}

type NotificationSpec struct {
	EmitEvents        bool          `json:"emitEvents,omitempty"`
	WebhookURL        string        `json:"webhookUrl,omitempty"`
	SlackWebhookURL   string        `json:"slackWebhookUrl,omitempty"`
	HistoryWebhookURL string        `json:"historyWebhookUrl,omitempty"`
	MinimumSeverity   string        `json:"minimumSeverity,omitempty"`
	AuthSecretRef     *SecretKeyRef `json:"authSecretRef,omitempty"`
}

type SourceStatus struct {
	Type          string       `json:"type,omitempty"`
	Kind          string       `json:"kind,omitempty"`
	Name          string       `json:"name,omitempty"`
	Namespace     string       `json:"namespace,omitempty"`
	Key           string       `json:"key,omitempty"`
	Digest        string       `json:"digest,omitempty"`
	Phase         string       `json:"phase,omitempty"`
	Cached        bool         `json:"cached,omitempty"`
	Changed       bool         `json:"changed,omitempty"`
	VerifiedAt    *metav1.Time `json:"verifiedAt,omitempty"`
	NextRefreshAt *metav1.Time `json:"nextRefreshAt,omitempty"`
	LastError     string       `json:"lastError,omitempty"`
	Description   string       `json:"description,omitempty"`
}

type ScanReportStatus struct {
	Phase                string              `json:"phase,omitempty"`
	GeneratedAt          *metav1.Time        `json:"generatedAt,omitempty"`
	Delta                *ScanReportDelta    `json:"delta,omitempty"`
	Notification         *NotificationStatus `json:"notification,omitempty"`
	Trend                *ScanReportTrend    `json:"trend,omitempty"`
	LastError            string              `json:"lastError,omitempty"`
	UsedCachedSources    bool                `json:"usedCachedSources,omitempty"`
	StoredFindings       int                 `json:"storedFindings,omitempty"`
	StoredAttackPaths    int                 `json:"storedAttackPaths,omitempty"`
	TotalFindings        int                 `json:"totalFindings,omitempty"`
	TotalAttackPaths     int                 `json:"totalAttackPaths,omitempty"`
	FindingsTruncated    bool                `json:"findingsTruncated,omitempty"`
	AttackPathsTruncated bool                `json:"attackPathsTruncated,omitempty"`
	SourceStatuses       []SourceStatus      `json:"sourceStatuses,omitempty"`
	Result               *report.ScanResult  `json:"result,omitempty"`
}

type NotificationStatus struct {
	LastAttemptAt           *metav1.Time `json:"lastAttemptAt,omitempty"`
	EventEmitted            bool         `json:"eventEmitted,omitempty"`
	WebhookDelivered        bool         `json:"webhookDelivered,omitempty"`
	SlackDelivered          bool         `json:"slackDelivered,omitempty"`
	HistoryWebhookDelivered bool         `json:"historyWebhookDelivered,omitempty"`
	LastError               string       `json:"lastError,omitempty"`
}

type ScanReportTrend struct {
	TotalRuns               int                    `json:"totalRuns,omitempty"`
	WindowSize              int                    `json:"windowSize,omitempty"`
	HighestRecentSeverity   string                 `json:"highestRecentSeverity,omitempty"`
	ConsecutiveCleanRuns    int                    `json:"consecutiveCleanRuns,omitempty"`
	ConsecutiveErrorRuns    int                    `json:"consecutiveErrorRuns,omitempty"`
	FindingsDeltaFromLatest int                    `json:"findingsDeltaFromLatest,omitempty"`
	AttackPathsDeltaLatest  int                    `json:"attackPathsDeltaFromLatest,omitempty"`
	RecentRuns              []ScanReportTrendPoint `json:"recentRuns,omitempty"`
}

type ScanReportTrendPoint struct {
	GeneratedAt       *metav1.Time `json:"generatedAt,omitempty"`
	Phase             string       `json:"phase,omitempty"`
	UsedCachedSources bool         `json:"usedCachedSources,omitempty"`
	TotalFindings     int          `json:"totalFindings,omitempty"`
	TotalAttackPaths  int          `json:"totalAttackPaths,omitempty"`
	CriticalFindings  int          `json:"criticalFindings,omitempty"`
	HighFindings      int          `json:"highFindings,omitempty"`
	MediumFindings    int          `json:"mediumFindings,omitempty"`
	LowFindings       int          `json:"lowFindings,omitempty"`
}

type ScanReportDelta struct {
	HasChanges              bool                `json:"hasChanges,omitempty"`
	PreviousGeneratedAt     *metav1.Time        `json:"previousGeneratedAt,omitempty"`
	FindingsAdded           int                 `json:"findingsAdded,omitempty"`
	FindingsRemoved         int                 `json:"findingsRemoved,omitempty"`
	FindingsSeverityChanged int                 `json:"findingsSeverityChanged,omitempty"`
	AttackPathsAdded        int                 `json:"attackPathsAdded,omitempty"`
	AttackPathsRemoved      int                 `json:"attackPathsRemoved,omitempty"`
	ResourcesChanged        int                 `json:"resourcesChanged,omitempty"`
	ResourcesTruncated      bool                `json:"resourcesTruncated,omitempty"`
	ResourceDeltas          []ScanResourceDelta `json:"resourceDeltas,omitempty"`
}

type ScanResourceDelta struct {
	Kind                    string `json:"kind,omitempty"`
	Namespace               string `json:"namespace,omitempty"`
	Name                    string `json:"name,omitempty"`
	FindingsAdded           int    `json:"findingsAdded,omitempty"`
	FindingsRemoved         int    `json:"findingsRemoved,omitempty"`
	FindingsSeverityChanged int    `json:"findingsSeverityChanged,omitempty"`
}

type SBOMReport struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec       SBOMReportSpec    `json:"spec,omitempty"`
	Status     SBOMReportStatus  `json:"status,omitempty"`
}

type SBOMReportSpec struct {
	ImageRef string `json:"imageRef,omitempty"`
	Format   string `json:"format,omitempty"`
	Content  string `json:"content,omitempty"`
}

type SBOMReportStatus struct {
	Phase       string       `json:"phase,omitempty"`
	GeneratedAt *metav1.Time `json:"generatedAt,omitempty"`
	LastError   string       `json:"lastError,omitempty"`
}

type NodeReport struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec       NodeReportSpec    `json:"spec,omitempty"`
	Status     NodeReportStatus  `json:"status,omitempty"`
}

type NodeReportSpec struct {
	NodeName                       string `json:"nodeName,omitempty"`
	KubeletConfigPath              string `json:"kubeletConfigPath,omitempty"`
	AnonymousAuthEnabled           *bool  `json:"anonymousAuthEnabled,omitempty"`
	WebhookAuthenticationEnabled   *bool  `json:"webhookAuthenticationEnabled,omitempty"`
	AuthorizationMode              string `json:"authorizationMode,omitempty"`
	AuthenticationX509ClientCAFile string `json:"authenticationX509ClientCAFile,omitempty"`
	ReadOnlyPort                   *int32 `json:"readOnlyPort,omitempty"`
	ProtectKernelDefaults          *bool  `json:"protectKernelDefaults,omitempty"`
	FailSwapOn                     *bool  `json:"failSwapOn,omitempty"`
	RotateCertificates             *bool  `json:"rotateCertificates,omitempty"`
	ServerTLSBootstrap             *bool  `json:"serverTLSBootstrap,omitempty"`
	SeccompDefault                 *bool  `json:"seccompDefault,omitempty"`
}

type NodeReportStatus struct {
	Phase       string       `json:"phase,omitempty"`
	GeneratedAt *metav1.Time `json:"generatedAt,omitempty"`
	LastError   string       `json:"lastError,omitempty"`
}
