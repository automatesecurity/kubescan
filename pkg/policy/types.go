package policy

import "time"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Category string

const (
	CategoryVuln        Category = "vuln"
	CategoryMisconfig   Category = "misconfig"
	CategoryExposure    Category = "exposure"
	CategoryIdentity    Category = "identity"
	CategoryResilience  Category = "resilience"
	CategorySupplyChain Category = "supply-chain"
)

type ResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

type Finding struct {
	ID               string         `json:"id"`
	Category         Category       `json:"category"`
	RuleID           string         `json:"ruleId"`
	Title            string         `json:"title"`
	Severity         Severity       `json:"severity"`
	OriginalSeverity Severity       `json:"originalSeverity,omitempty"`
	RuleVersion      string         `json:"ruleVersion"`
	Resource         ResourceRef    `json:"resource"`
	Message          string         `json:"message"`
	Evidence         map[string]any `json:"evidence,omitempty"`
	Remediation      string         `json:"remediation"`
	Timestamp        time.Time      `json:"timestamp"`
}

type Inventory struct {
	Workloads       []Workload
	Nodes           []Node
	Services        []Service
	ConfigMaps      []ConfigMap
	Roles           []Role
	Bindings        []Binding
	NetworkPolicies []NetworkPolicy
	Namespaces      []Namespace
	Components      []ClusterComponent
}

type Workload struct {
	Resource                     ResourceRef
	Labels                       map[string]string
	ServiceAccountName           string
	AutomountServiceAccountToken *bool
	NodeName                     string
	HostNetwork                  bool
	HostPID                      bool
	HostIPC                      bool
	SecretVolumes                []string
	HostPathVolumes              []HostPathVolume
	Tolerations                  []Toleration
	Containers                   []Container
}

type Node struct {
	Resource                            ResourceRef
	Labels                              map[string]string
	Unschedulable                       bool
	Taints                              []Taint
	ExternalIPs                         []string
	ContainerRuntime                    string
	KernelVersion                       string
	OSImage                             string
	KubeletVersion                      string
	KubeProxyVersion                    string
	Ready                               bool
	MemoryPressure                      bool
	DiskPressure                        bool
	PIDPressure                         bool
	NetworkUnavailable                  bool
	KubeletConfigPath                   string
	KubeletAnonymousAuthEnabled         *bool
	KubeletWebhookAuthenticationEnabled *bool
	KubeletAuthorizationMode            string
	KubeletAuthenticationX509ClientCAFile string
	KubeletReadOnlyPort                 *int32
	KubeletProtectKernelDefaults        *bool
	KubeletFailSwapOn                   *bool
	KubeletRotateCertificates           *bool
	KubeletServerTLSBootstrap           *bool
	KubeletSeccompDefault               *bool
}

type Container struct {
	Name                     string
	Image                    string
	ImageDigest              string
	Privileged               *bool
	AllowPrivilegeEscalation *bool
	RunAsNonRoot             *bool
	RunAsUser                *int64
	ReadOnlyRootFilesystem   *bool
	SeccompProfileType       string
	CapabilitiesAdd          []string
	HostPorts                []int32
	HasLivenessProbe         bool
	HasReadinessProbe        bool
	HasResourceRequests      bool
	HasResourceLimits        bool
	SecretEnvRefs            []SecretRef
	SecretEnvFromRefs        []string
	EnvVars                  []EnvVar
}

type Service struct {
	Resource ResourceRef
	Type     string
	Selector map[string]string
}

type ConfigMap struct {
	Resource ResourceRef
	Data     map[string]string
}

type Role struct {
	Resource ResourceRef
	Rules    []PolicyRule
}

type PolicyRule struct {
	Verbs           []string
	Resources       []string
	NonResourceURLs []string
}

type Binding struct {
	Resource    ResourceRef
	RoleRefKind string
	RoleRefName string
	Subjects    []Subject
}

type Subject struct {
	Kind      string
	Name      string
	Namespace string
}

type SecretRef struct {
	Name string
	Key  string
}

type EnvVar struct {
	Name      string
	Value     string
	ValueFrom string
}

type HostPathVolume struct {
	Name string
	Path string
}

type Toleration struct {
	Key      string
	Operator string
	Value    string
	Effect   string
}

type Taint struct {
	Key    string
	Value  string
	Effect string
}

type NetworkPolicy struct {
	Resource    ResourceRef
	PolicyTypes []string
	HasIngress  bool
	HasEgress   bool
}

type Namespace struct {
	Resource ResourceRef
	Labels   map[string]string
}

type ClusterComponent struct {
	Resource  ResourceRef
	Name      string
	Version   string
	Ecosystem string
	Source    string
}
