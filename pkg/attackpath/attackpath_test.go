package attackpath

import (
	"testing"

	"kubescan/pkg/policy"
)

func TestBuildGraphConnectsReachabilityAndIdentityEdges(t *testing.T) {
	trueValue := true
	inventory := policy.Inventory{
		Workloads: []policy.Workload{
			{
				Resource:           policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Labels:             map[string]string{"app": "api"},
				ServiceAccountName: "api",
				HostPID:            true,
				Containers: []policy.Container{
					{Name: "api", Privileged: &trueValue},
				},
			},
		},
		Services: []policy.Service{
			{
				Resource: policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "public-api"},
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
				Resource:    policy.ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "bind-api"},
				RoleRefKind: "Role",
				RoleRefName: "wildcard",
				Subjects: []policy.Subject{
					{Kind: "ServiceAccount", Namespace: "payments", Name: "api"},
				},
			},
		},
	}

	graph := BuildGraph(inventory)
	assertEdgePresent(t, graph, internetNodeID, resourceNodeID(policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "public-api"}), relationCanReach)
	assertEdgePresent(t, graph, resourceNodeID(policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "public-api"}), resourceNodeID(policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}), relationRoutesTo)
	assertEdgePresent(t, graph, resourceNodeID(policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}), resourceNodeID(serviceAccountResource("payments", "api")), relationUsesSA)
	assertEdgePresent(t, graph, resourceNodeID(serviceAccountResource("payments", "api")), resourceNodeID(policy.ResourceRef{Kind: "Role", Namespace: "payments", Name: "wildcard"}), relationBoundTo)
	assertEdgePresent(t, graph, resourceNodeID(policy.ResourceRef{Kind: "Role", Namespace: "payments", Name: "wildcard"}), wildcardAccessID, relationGrants)
}

func TestAnalyzeBuildsExpectedAttackPaths(t *testing.T) {
	trueValue := true
	inventory := policy.Inventory{
		Workloads: []policy.Workload{
			{
				Resource:           policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Labels:             map[string]string{"app": "api"},
				ServiceAccountName: "api",
				HostPID:            true,
				Tolerations: []policy.Toleration{
					{Key: "node-role.kubernetes.io/control-plane", Operator: "Exists", Effect: "NoSchedule"},
				},
				HostPathVolumes: []policy.HostPathVolume{
					{Name: "kubelet", Path: "/var/lib/kubelet"},
				},
				Containers: []policy.Container{
					{Name: "api", Privileged: &trueValue},
				},
			},
		},
		Services: []policy.Service{
			{
				Resource: policy.ResourceRef{Kind: "Service", Namespace: "payments", Name: "public-api"},
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
			{
				Resource: policy.ResourceRef{Kind: "Role", Namespace: "payments", Name: "secret-reader"},
				Rules: []policy.PolicyRule{
					{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}},
				},
			},
			{
				Resource: policy.ResourceRef{Kind: "ClusterRole", Name: "cluster-admin"},
			},
		},
		Bindings: []policy.Binding{
			{
				Resource:    policy.ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "wildcard-bind"},
				RoleRefKind: "Role",
				RoleRefName: "wildcard",
				Subjects: []policy.Subject{
					{Kind: "ServiceAccount", Namespace: "payments", Name: "api"},
				},
			},
			{
				Resource:    policy.ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "secret-bind"},
				RoleRefKind: "Role",
				RoleRefName: "secret-reader",
				Subjects: []policy.Subject{
					{Kind: "ServiceAccount", Namespace: "payments", Name: "api"},
				},
			},
			{
				Resource:    policy.ResourceRef{Kind: "ClusterRoleBinding", Name: "cluster-admin-bind"},
				RoleRefKind: "ClusterRole",
				RoleRefName: "cluster-admin",
				Subjects: []policy.Subject{
					{Kind: "ServiceAccount", Namespace: "payments", Name: "api"},
				},
			},
		},
	}

	findings := policy.EvaluateWithProfile(inventory, policy.RuleProfileEnterprise)
	results := Analyze(inventory, findings)

	assertPathPresent(t, results, "AP001")
	assertPathPresent(t, results, "AP002")
	assertPathPresent(t, results, "AP003")
	assertPathPresent(t, results, "AP004")
	assertPathPresent(t, results, "AP005")
	assertPathPresent(t, results, "AP006")

	publicSecretPath := findPath(t, results, "AP004")
	if publicSecretPath.Entry.Kind != "Service" || publicSecretPath.Entry.Name != "public-api" {
		t.Fatalf("expected AP004 entry to be public service, got %+v", publicSecretPath.Entry)
	}
	if len(publicSecretPath.SupportingRules) == 0 {
		t.Fatalf("expected AP004 supporting rules to be populated")
	}
	if publicSecretPath.Path == "" {
		t.Fatalf("expected AP004 path string to be populated")
	}
}

func assertEdgePresent(t *testing.T, graph Graph, from, to, relationship string) {
	t.Helper()
	for _, edge := range graph.Edges {
		if edge.From == from && edge.To == to && edge.Relationship == relationship {
			return
		}
	}
	t.Fatalf("expected edge %s --%s--> %s", from, relationship, to)
}

func assertPathPresent(t *testing.T, results []Result, id string) {
	t.Helper()
	for _, result := range results {
		if result.ID == id {
			return
		}
	}
	t.Fatalf("expected attack path %s", id)
}

func findPath(t *testing.T, results []Result, id string) Result {
	t.Helper()
	for _, result := range results {
		if result.ID == id {
			return result
		}
	}
	t.Fatalf("expected attack path %s", id)
	return Result{}
}
