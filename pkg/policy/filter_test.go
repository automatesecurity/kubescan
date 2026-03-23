package policy

import "testing"

func TestApplyInventoryFilter(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "proxy"}},
		},
		Nodes: []Node{
			{Resource: ResourceRef{Kind: "Node", Name: "worker-1"}},
		},
		Services: []Service{
			{Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"}},
		},
		ConfigMaps: []ConfigMap{
			{Resource: ResourceRef{Kind: "ConfigMap", Namespace: "payments", Name: "app-config"}},
		},
		Roles: []Role{
			{Resource: ResourceRef{Kind: "ClusterRole", Name: "cluster-admin"}},
		},
		Namespaces: []Namespace{
			{Resource: ResourceRef{Kind: "Namespace", Name: "payments"}},
			{Resource: ResourceRef{Kind: "Namespace", Name: "platform"}},
		},
		Components: []ClusterComponent{
			{Resource: ResourceRef{Kind: "Node", Name: "worker-1"}, Name: "kubelet", Version: "v1.31.1", Ecosystem: "kubernetes"},
		},
	}

	filtered := ApplyInventoryFilter(inventory, InventoryFilter{
		IncludeKinds:      []string{"Deployment"},
		IncludeNamespaces: []string{"payments"},
	})

	if got := len(filtered.Workloads); got != 1 {
		t.Fatalf("expected 1 workload after filtering, got %d", got)
	}
	if filtered.Workloads[0].Resource.Name != "api" {
		t.Fatalf("expected payments workload to remain, got %q", filtered.Workloads[0].Resource.Name)
	}
	if got := len(filtered.Services); got != 0 {
		t.Fatalf("expected services to be filtered out, got %d", got)
	}
	if got := len(filtered.Nodes); got != 0 {
		t.Fatalf("expected nodes to be filtered out, got %d", got)
	}
	if got := len(filtered.ConfigMaps); got != 0 {
		t.Fatalf("expected configmaps to be filtered out, got %d", got)
	}
	if got := len(filtered.Roles); got != 0 {
		t.Fatalf("expected roles to be filtered out by kind include, got %d", got)
	}
	if got := len(filtered.Namespaces); got != 0 {
		t.Fatalf("expected namespaces to be filtered out by kind include, got %d", got)
	}
	if got := len(filtered.Components); got != 0 {
		t.Fatalf("expected components to be filtered out by kind include, got %d", got)
	}
}

func TestApplyInventoryFilterKeepsNamespacesAndConfigMaps(t *testing.T) {
	inventory := Inventory{
		ConfigMaps: []ConfigMap{
			{Resource: ResourceRef{Kind: "ConfigMap", Namespace: "payments", Name: "app-config"}},
			{Resource: ResourceRef{Kind: "ConfigMap", Namespace: "platform", Name: "proxy-config"}},
		},
		Namespaces: []Namespace{
			{Resource: ResourceRef{Kind: "Namespace", Name: "payments"}},
			{Resource: ResourceRef{Kind: "Namespace", Name: "platform"}},
		},
		Components: []ClusterComponent{
			{Resource: ResourceRef{Kind: "Node", Name: "worker-1"}, Name: "kubelet", Version: "v1.31.1", Ecosystem: "kubernetes"},
			{Resource: ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-master-0"}, Name: "kube-apiserver", Version: "v1.31.1", Ecosystem: "kubernetes"},
		},
		Nodes: []Node{
			{Resource: ResourceRef{Kind: "Node", Name: "worker-1"}},
			{Resource: ResourceRef{Kind: "Node", Name: "worker-2"}},
		},
	}

	filtered := ApplyInventoryFilter(inventory, InventoryFilter{
		IncludeKinds:      []string{"Namespace", "ConfigMap"},
		IncludeNamespaces: []string{"payments"},
	})

	if got := len(filtered.ConfigMaps); got != 1 {
		t.Fatalf("expected 1 configmap after filtering, got %d", got)
	}
	if filtered.ConfigMaps[0].Resource.Name != "app-config" {
		t.Fatalf("expected payments configmap to remain, got %q", filtered.ConfigMaps[0].Resource.Name)
	}
	if got := len(filtered.Namespaces); got != 1 {
		t.Fatalf("expected 1 namespace after filtering, got %d", got)
	}
	if filtered.Namespaces[0].Resource.Name != "payments" {
		t.Fatalf("expected payments namespace to remain, got %q", filtered.Namespaces[0].Resource.Name)
	}
	if got := len(filtered.Components); got != 0 {
		t.Fatalf("expected components to be filtered out by namespace include, got %d", got)
	}
}

func TestApplyInventoryFilterKeepsClusterComponents(t *testing.T) {
	inventory := Inventory{
		Nodes: []Node{
			{Resource: ResourceRef{Kind: "Node", Name: "worker-1"}},
			{Resource: ResourceRef{Kind: "Node", Name: "worker-2"}},
		},
		Components: []ClusterComponent{
			{Resource: ResourceRef{Kind: "Node", Name: "worker-1"}, Name: "kubelet", Version: "v1.31.1", Ecosystem: "kubernetes"},
			{Resource: ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-master-0"}, Name: "kube-apiserver", Version: "v1.31.1", Ecosystem: "kubernetes"},
		},
	}

	filtered := ApplyInventoryFilter(inventory, InventoryFilter{
		IncludeKinds:      []string{"Node"},
		IncludeNamespaces: []string{"kube-system"},
	})

	if got := len(filtered.Components); got != 1 {
		t.Fatalf("expected 1 component after filtering, got %d", got)
	}
	if filtered.Components[0].Name != "kubelet" {
		t.Fatalf("expected kubelet component to remain, got %q", filtered.Components[0].Name)
	}
	if got := len(filtered.Nodes); got != 2 {
		t.Fatalf("expected 2 nodes after filtering, got %d", got)
	}
}
