package k8s

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"kubescan/api/v1alpha1"
)

func TestInventoryCollectorCollectNamespace(t *testing.T) {
	trueValue := true
	falseValue := false
	root := int64(0)

	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api",
				Namespace: "payments",
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app":  "api",
							"tier": "frontend",
						},
					},
					Spec: corev1.PodSpec{
						AutomountServiceAccountToken: &trueValue,
						ServiceAccountName:           "api",
						NodeName:                     "worker-1",
						Tolerations: []corev1.Toleration{
							{
								Key:      "node-role.kubernetes.io/control-plane",
								Operator: corev1.TolerationOpExists,
								Effect:   corev1.TaintEffectNoSchedule,
							},
						},
						SecurityContext: &corev1.PodSecurityContext{
							SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
						Volumes: []corev1.Volume{
							{
								Name: "tls",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{SecretName: "api-tls"},
								},
							},
							{
								Name: "host-data",
								VolumeSource: corev1.VolumeSource{
									HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/data"},
								},
							},
						},
						Containers: []corev1.Container{
							{
								Name:  "api",
								Image: "nginx:latest",
								Ports: []corev1.ContainerPort{
									{ContainerPort: 8080, HostPort: 8080},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "PASSWORD",
										Value: "insecure-value",
									},
									{
										Name: "PASSWORD_FROM_SECRET",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
												Key:                  "password",
											},
										},
									},
								},
								EnvFrom: []corev1.EnvFromSource{
									{
										SecretRef: &corev1.SecretEnvSource{
											LocalObjectReference: corev1.LocalObjectReference{Name: "shared-config"},
										},
									},
								},
								SecurityContext: &corev1.SecurityContext{
									Privileged:               &trueValue,
									AllowPrivilegeEscalation: &falseValue,
									RunAsNonRoot:             &falseValue,
									RunAsUser:                &root,
									ReadOnlyRootFilesystem:   &falseValue,
									Capabilities: &corev1.Capabilities{
										Add: []corev1.Capability{"SYS_ADMIN"},
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("100m"),
										corev1.ResourceMemory: resource.MustParse("128Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("200m"),
										corev1.ResourceMemory: resource.MustParse("256Mi"),
									},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api",
				Namespace: "payments",
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Selector: map[string]string{
					"app": "api",
				},
			},
		},
		&corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-config",
				Namespace: "payments",
			},
			Data: map[string]string{
				"api_token": "super-secret",
			},
		},
		&corev1.Namespace{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "payments",
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "restricted",
					"pod-security.kubernetes.io/audit":   "restricted",
					"pod-security.kubernetes.io/warn":    "restricted",
				},
			},
		},
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "worker-1",
				Labels: map[string]string{
					"node-role.kubernetes.io/control-plane": "",
				},
			},
			Spec: corev1.NodeSpec{
				Taints: []corev1.Taint{
					{
						Key:    "node-role.kubernetes.io/control-plane",
						Effect: corev1.TaintEffectNoSchedule,
					},
				},
			},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "203.0.113.10"},
				},
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
					{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
					{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse},
					{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
					{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionTrue},
				},
				NodeInfo: corev1.NodeSystemInfo{
					KubeletVersion:          "v1.31.1",
					KubeProxyVersion:        "v1.31.1",
					ContainerRuntimeVersion: "containerd://1.7.18",
					KernelVersion:           "6.8.0",
					OSImage:                 "Test Linux",
				},
			},
		},
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wildcard",
				Namespace: "payments",
			},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"pods"}},
			},
		},
		&rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-admin",
				Namespace: "payments",
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "wildcard",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "api",
					Namespace: "payments",
				},
			},
		},
		&networkingv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default-deny",
				Namespace: "payments",
			},
		},
	)

	collector := NewInventoryCollector(client)
	inventory, err := collector.Collect(context.Background(), "payments")
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if got := len(inventory.Workloads); got != 1 {
		t.Fatalf("expected 1 workload, got %d", got)
	}
	if got := len(inventory.Nodes); got != 1 {
		t.Fatalf("expected 1 node, got %d", got)
	}
	if got := len(inventory.Services); got != 1 {
		t.Fatalf("expected 1 service, got %d", got)
	}
	if got := len(inventory.ConfigMaps); got != 1 {
		t.Fatalf("expected 1 configmap, got %d", got)
	}
	if got := len(inventory.Roles); got != 1 {
		t.Fatalf("expected 1 role, got %d", got)
	}
	if got := len(inventory.Bindings); got != 1 {
		t.Fatalf("expected 1 binding, got %d", got)
	}
	if got := len(inventory.NetworkPolicies); got != 1 {
		t.Fatalf("expected 1 network policy, got %d", got)
	}
	if got := len(inventory.Namespaces); got != 1 {
		t.Fatalf("expected 1 namespace, got %d", got)
	}
	if got := len(inventory.Components); got != 2 {
		t.Fatalf("expected 2 node components, got %d", got)
	}

	container := inventory.Workloads[0].Containers[0]
	if container.RunAsUser == nil || *container.RunAsUser != 0 {
		t.Fatalf("expected runAsUser=0 to be collected")
	}
	if inventory.Workloads[0].NodeName != "worker-1" {
		t.Fatalf("expected nodeName worker-1, got %q", inventory.Workloads[0].NodeName)
	}
	if inventory.Workloads[0].Labels["app"] != "api" {
		t.Fatalf("expected workload labels to be collected, got %v", inventory.Workloads[0].Labels)
	}
	if container.AllowPrivilegeEscalation == nil || *container.AllowPrivilegeEscalation {
		t.Fatalf("expected allowPrivilegeEscalation=false to be collected")
	}
	if container.SeccompProfileType != "RuntimeDefault" {
		t.Fatalf("expected RuntimeDefault seccomp profile, got %q", container.SeccompProfileType)
	}
	if got := len(container.CapabilitiesAdd); got != 1 || container.CapabilitiesAdd[0] != "SYS_ADMIN" {
		t.Fatalf("expected dangerous capability to be collected, got %v", container.CapabilitiesAdd)
	}
	if got := len(container.HostPorts); got != 1 || container.HostPorts[0] != 8080 {
		t.Fatalf("expected hostPort 8080 to be collected, got %v", container.HostPorts)
	}
	if got := len(container.EnvVars); got != 2 {
		t.Fatalf("expected 2 env vars to be collected, got %d", got)
	}
	if got := len(container.SecretEnvRefs); got != 1 {
		t.Fatalf("expected secret env ref to be collected, got %d", got)
	}
	if got := len(inventory.Workloads[0].SecretVolumes); got != 1 {
		t.Fatalf("expected secret volume to be collected, got %d", got)
	}
	if got := len(inventory.Workloads[0].HostPathVolumes); got != 1 || inventory.Workloads[0].HostPathVolumes[0].Path != "/var/lib/data" {
		t.Fatalf("expected hostPath volume /var/lib/data, got %+v", inventory.Workloads[0].HostPathVolumes)
	}
	if got := len(inventory.Workloads[0].Tolerations); got != 1 || inventory.Workloads[0].Tolerations[0].Key != "node-role.kubernetes.io/control-plane" {
		t.Fatalf("expected control-plane toleration, got %+v", inventory.Workloads[0].Tolerations)
	}
	if inventory.ConfigMaps[0].Data["api_token"] != "super-secret" {
		t.Fatalf("expected configmap data to be collected, got %v", inventory.ConfigMaps[0].Data)
	}
	if inventory.Services[0].Selector["app"] != "api" {
		t.Fatalf("expected service selector to be collected, got %v", inventory.Services[0].Selector)
	}
	if inventory.Namespaces[0].Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Fatalf("expected namespace labels to be collected, got %v", inventory.Namespaces[0].Labels)
	}
	if inventory.Nodes[0].ContainerRuntime != "containerd://1.7.18" {
		t.Fatalf("expected node runtime to be collected, got %q", inventory.Nodes[0].ContainerRuntime)
	}
	if !inventory.Nodes[0].Ready {
		t.Fatalf("expected node ready condition to be collected")
	}
	if !inventory.Nodes[0].MemoryPressure {
		t.Fatalf("expected node memory pressure condition to be collected")
	}
	if inventory.Nodes[0].DiskPressure {
		t.Fatalf("expected node disk pressure false, got true")
	}
	if inventory.Nodes[0].PIDPressure {
		t.Fatalf("expected node pid pressure false, got true")
	}
	if !inventory.Nodes[0].NetworkUnavailable {
		t.Fatalf("expected node network unavailable condition to be collected")
	}
	if got := len(inventory.Nodes[0].ExternalIPs); got != 1 || inventory.Nodes[0].ExternalIPs[0] != "203.0.113.10" {
		t.Fatalf("expected node external IP to be collected, got %+v", inventory.Nodes[0].ExternalIPs)
	}
	if got := len(inventory.Nodes[0].Taints); got != 1 || inventory.Nodes[0].Taints[0].Key != "node-role.kubernetes.io/control-plane" {
		t.Fatalf("expected node taints to be collected, got %+v", inventory.Nodes[0].Taints)
	}
	if !inventory.NetworkPolicies[0].HasIngress || inventory.NetworkPolicies[0].HasEgress {
		t.Fatalf("expected default network policy to collect ingress-only semantics, got %+v", inventory.NetworkPolicies[0])
	}
	if inventory.Bindings[0].Subjects[0].Name != "api" {
		t.Fatalf("expected role binding subject api, got %q", inventory.Bindings[0].Subjects[0].Name)
	}
	if inventory.Components[0].Resource.Kind != "Node" || inventory.Components[1].Resource.Kind != "Node" {
		t.Fatalf("expected node components, got %+v", inventory.Components)
	}
	if inventory.Components[0].Name != "kubelet" && inventory.Components[1].Name != "kubelet" {
		t.Fatalf("expected kubelet component, got %+v", inventory.Components)
	}
	if inventory.Components[0].Name != "kube-proxy" && inventory.Components[1].Name != "kube-proxy" {
		t.Fatalf("expected kube-proxy component, got %+v", inventory.Components)
	}
}

func TestInventoryCollectorCollectControlPlaneComponents(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kube-apiserver-control-plane",
				Namespace: "kube-system",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "kube-apiserver",
						Image: "registry.k8s.io/kube-apiserver:v1.31.2",
					},
				},
			},
		},
		&corev1.Pod{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "etcd-control-plane",
				Namespace: "kube-system",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "etcd",
						Image: "registry.k8s.io/etcd:3.5.13-0",
					},
				},
			},
		},
	)

	collector := NewInventoryCollector(client)
	inventory, err := collector.Collect(context.Background(), "")
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if got := len(inventory.Components); got != 2 {
		t.Fatalf("expected 2 control-plane components, got %d", got)
	}
	if inventory.Components[0].Name != "kube-apiserver" && inventory.Components[1].Name != "kube-apiserver" {
		t.Fatalf("expected kube-apiserver component, got %+v", inventory.Components)
	}
	if inventory.Components[0].Name != "etcd" && inventory.Components[1].Name != "etcd" {
		t.Fatalf("expected etcd component, got %+v", inventory.Components)
	}
}

func TestInventoryCollectorCollectPodImageDigest(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Pod{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-0",
				Namespace: "payments",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "api",
						Image: "ghcr.io/acme/api:1.0.0",
					},
				},
			},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:    "api",
						Image:   "ghcr.io/acme/api:1.0.0",
						ImageID: "docker-pullable://ghcr.io/acme/api@sha256:deadbeef",
					},
				},
			},
		},
	)

	collector := NewInventoryCollector(client)
	inventory, err := collector.Collect(context.Background(), "payments")
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(inventory.Workloads) != 1 || len(inventory.Workloads[0].Containers) != 1 {
		t.Fatalf("expected 1 workload with 1 container, got %+v", inventory.Workloads)
	}
	if inventory.Workloads[0].Containers[0].ImageDigest != "ghcr.io/acme/api@sha256:deadbeef" {
		t.Fatalf("expected normalized image digest, got %q", inventory.Workloads[0].Containers[0].ImageDigest)
	}
}

func TestInventoryCollectorNamespacedOnlySkipsClusterScopedInventory(t *testing.T) {
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api",
				Namespace: "payments",
			},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "api", Image: "nginx:latest"},
						},
					},
				},
			},
		},
		&corev1.Node{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
			ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		},
		&corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{Name: "payments"},
		},
		&rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		},
		&rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
			ObjectMeta: metav1.ObjectMeta{Name: "admins"},
		},
	)

	collector := NewInventoryCollectorWithOptions(client, true)
	inventory, err := collector.Collect(context.Background(), "payments")
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	if got := len(inventory.Workloads); got != 1 {
		t.Fatalf("expected 1 workload, got %d", got)
	}
	if got := len(inventory.Nodes); got != 0 {
		t.Fatalf("expected no nodes in namespacedOnly mode, got %d", got)
	}
	if got := len(inventory.Components); got != 0 {
		t.Fatalf("expected no cluster components in namespacedOnly mode, got %d", got)
	}
	if got := len(inventory.Roles); got != 0 {
		t.Fatalf("expected no cluster roles in namespacedOnly mode, got %d", got)
	}
	if got := len(inventory.Bindings); got != 0 {
		t.Fatalf("expected no cluster role bindings in namespacedOnly mode, got %d", got)
	}
	if got := len(inventory.Namespaces); got != 1 || inventory.Namespaces[0].Resource.Name != "payments" {
		t.Fatalf("expected synthetic payments namespace, got %+v", inventory.Namespaces)
	}
}

func TestInventoryCollectorAppliesNodeReports(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Node{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "worker-1",
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
			},
		},
	)

	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		nodeReportGVR: "NodeReportList",
	}, &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": v1alpha1.GroupName + "/" + v1alpha1.Version,
			"kind":       v1alpha1.NodeReportKind,
			"metadata": map[string]any{
				"name": "worker-1",
			},
			"spec": map[string]any{
				"nodeName":                     "worker-1",
				"kubeletConfigPath":            "/var/lib/kubelet/config.yaml",
				"anonymousAuthEnabled":         true,
				"webhookAuthenticationEnabled": false,
				"authorizationMode":            "AlwaysAllow",
				"authenticationX509ClientCAFile": "/etc/kubernetes/pki/ca.crt",
				"readOnlyPort":                 int64(10255),
				"protectKernelDefaults":        false,
				"failSwapOn":                   false,
			},
		},
	})

	collector := NewInventoryCollectorWithClients(client, dynamicClient, false)
	inventory, err := collector.Collect(context.Background(), "")
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(inventory.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(inventory.Nodes))
	}
	node := inventory.Nodes[0]
	if node.KubeletConfigPath != "/var/lib/kubelet/config.yaml" {
		t.Fatalf("expected kubelet config path to be applied, got %q", node.KubeletConfigPath)
	}
	if node.KubeletAnonymousAuthEnabled == nil || !*node.KubeletAnonymousAuthEnabled {
		t.Fatalf("expected kubelet anonymous auth to be applied")
	}
	if node.KubeletWebhookAuthenticationEnabled == nil || *node.KubeletWebhookAuthenticationEnabled {
		t.Fatalf("expected kubelet webhook authentication false to be applied")
	}
	if node.KubeletAuthorizationMode != "AlwaysAllow" {
		t.Fatalf("expected kubelet authorization mode, got %q", node.KubeletAuthorizationMode)
	}
	if node.KubeletAuthenticationX509ClientCAFile != "/etc/kubernetes/pki/ca.crt" {
		t.Fatalf("expected kubelet x509 client CA file, got %q", node.KubeletAuthenticationX509ClientCAFile)
	}
	if node.KubeletReadOnlyPort == nil || *node.KubeletReadOnlyPort != 10255 {
		t.Fatalf("expected kubelet readOnlyPort 10255, got %#v", node.KubeletReadOnlyPort)
	}
	if node.KubeletProtectKernelDefaults == nil || *node.KubeletProtectKernelDefaults {
		t.Fatalf("expected kubelet protectKernelDefaults false to be applied")
	}
	if node.KubeletFailSwapOn == nil || *node.KubeletFailSwapOn {
		t.Fatalf("expected kubelet failSwapOn false to be applied")
	}
}
