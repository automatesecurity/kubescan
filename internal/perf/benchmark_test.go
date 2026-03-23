package perf

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kubescan/pkg/attackpath"
	"kubescan/pkg/filescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/report"
	"kubescan/pkg/secretscan"
	"kubescan/pkg/vuln"
)

func BenchmarkEvaluateLargeInventory(b *testing.B) {
	inventory := largeInventoryFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := policy.EvaluateWithProfile(inventory, policy.RuleProfileEnterprise)
		if len(findings) == 0 {
			b.Fatal("expected findings")
		}
	}
}

func BenchmarkAnalyzeLargeInventory(b *testing.B) {
	inventory := largeInventoryFixture()
	findings := policy.EvaluateWithProfile(inventory, policy.RuleProfileEnterprise)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		paths := attackpath.Analyze(inventory, findings)
		if len(paths) == 0 {
			b.Fatal("expected attack paths")
		}
	}
}

func BenchmarkWriteJSONLargeResult(b *testing.B) {
	inventory := largeInventoryFixture()
	findings := policy.EvaluateWithProfile(inventory, policy.RuleProfileEnterprise)
	paths := attackpath.Analyze(inventory, findings)
	result := report.BuildScanResultWithAttackPaths(findings, paths)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := report.WriteJSON(io.Discard, result); err != nil {
			b.Fatalf("write json: %v", err)
		}
	}
}

func BenchmarkMatchInventoryLargeSBOMIndex(b *testing.B) {
	inventory := largeInventoryFixture()
	sboms, advisories := largeSBOMFixture(inventory)
	now := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := vuln.MatchInventory(inventory, sboms, advisories, now)
		if len(findings) == 0 {
			b.Fatal("expected vulnerability findings")
		}
	}
}

func BenchmarkScanLargeFilesystemTree(b *testing.B) {
	root := b.TempDir()
	createFilesystemFixture(b, root)
	now := time.Date(2026, 3, 21, 0, 0, 0, 0, time.UTC)
	options := filescan.Options{SecretScanMode: secretscan.ModeBalanced}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := filescan.ScanPathWithOptions(root, policy.RuleProfileHardening, now, options)
		if err != nil {
			b.Fatalf("scan path: %v", err)
		}
		if len(result.Findings) == 0 {
			b.Fatal("expected filesystem findings")
		}
	}
}

func largeInventoryFixture() policy.Inventory {
	var inventory policy.Inventory

	for i := 0; i < 20; i++ {
		namespace := "team-" + strconv.Itoa(i)
		inventory.Namespaces = append(inventory.Namespaces, policy.Namespace{
			Resource: policy.ResourceRef{APIVersion: "v1", Kind: "Namespace", Name: namespace},
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "baseline",
			},
		})
		inventory.ConfigMaps = append(inventory.ConfigMaps, policy.ConfigMap{
			Resource: policy.ResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: namespace, Name: "app-config"},
			Data: map[string]string{
				"api_token": "placeholder-token-value-" + strconv.Itoa(i),
			},
		})
	}

	for i := 0; i < 12; i++ {
		runtime := "containerd://1.7.18"
		if i%4 == 0 {
			runtime = "docker://24.0.7"
		}
		ready := i%5 != 0
		inventory.Nodes = append(inventory.Nodes, policy.Node{
			Resource:         policy.ResourceRef{APIVersion: "v1", Kind: "Node", Name: "node-" + strconv.Itoa(i)},
			Labels:           controlPlaneLabels(i),
			Unschedulable:    i%3 == 0,
			ExternalIPs:      nodeExternalIPs(i),
			ContainerRuntime: runtime,
			KernelVersion:    "6.8." + strconv.Itoa(i),
			OSImage:          "Ubuntu 24.04",
			KubeletVersion:   kubeletVersion(i),
			KubeProxyVersion: kubeProxyVersion(i),
			Ready:            ready,
		})
	}

	for i := 0; i < 6; i++ {
		inventory.Components = append(inventory.Components, policy.ClusterComponent{
			Resource:  policy.ResourceRef{APIVersion: "v1", Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-" + strconv.Itoa(i)},
			Name:      "kube-apiserver",
			Version:   controlPlaneVersion(i),
			Ecosystem: "kubernetes",
			Source:    "pod-image",
		})
	}

	for i := 0; i < 30; i++ {
		namespace := "team-" + strconv.Itoa(i%20)
		roleName := "wildcard-" + strconv.Itoa(i)
		inventory.Roles = append(inventory.Roles, policy.Role{
			Resource: policy.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: namespace, Name: roleName},
			Rules: []policy.PolicyRule{{
				Verbs:     []string{"*"},
				Resources: []string{"*"},
			}},
		})
		inventory.Bindings = append(inventory.Bindings, policy.Binding{
			Resource:    policy.ResourceRef{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: namespace, Name: "bind-" + strconv.Itoa(i)},
			RoleRefKind: "Role",
			RoleRefName: roleName,
			Subjects: []policy.Subject{{
				Kind:      "ServiceAccount",
				Name:      "default",
				Namespace: namespace,
			}},
		})
	}

	for i := 0; i < 250; i++ {
		namespace := "team-" + strconv.Itoa(i%20)
		app := "app-" + strconv.Itoa(i)
		labels := map[string]string{"app": app}
		privileged := i%3 == 0
		runAsNonRoot := false
		readOnlyRootFS := false
		allowPrivilegeEscalation := true
		runAsUser := int64(0)
		hostPorts := []int32{}
		if i%7 == 0 {
			hostPorts = []int32{8080}
		}

		inventory.Workloads = append(inventory.Workloads, policy.Workload{
			Resource: policy.ResourceRef{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Namespace:  namespace,
				Name:       app,
			},
			Labels:             labels,
			ServiceAccountName: "default",
			NodeName:           nodeNameForWorkload(i),
			HostNetwork:        i%5 == 0,
			HostPID:            i%4 == 0,
			HostIPC:            i%9 == 0,
			SecretVolumes:      []string{"db-creds"},
			HostPathVolumes: []policy.HostPathVolume{{
				Name: "host-root",
				Path: "/var/lib/kubelet",
			}},
			Tolerations: tolerationsForWorkload(i),
			Containers: []policy.Container{{
				Name:                     "main",
				Image:                    imageForWorkload(i),
				ImageDigest:              imageDigestForWorkload(i),
				Privileged:               &privileged,
				AllowPrivilegeEscalation: &allowPrivilegeEscalation,
				RunAsNonRoot:             &runAsNonRoot,
				RunAsUser:                &runAsUser,
				ReadOnlyRootFilesystem:   &readOnlyRootFS,
				SeccompProfileType:       seccompForWorkload(i),
				CapabilitiesAdd:          capabilitiesForWorkload(i),
				HostPorts:                hostPorts,
				HasLivenessProbe:         i%6 != 0,
				HasReadinessProbe:        i%5 != 0,
				HasResourceRequests:      i%4 != 0,
				HasResourceLimits:        i%3 != 0,
				SecretEnvRefs: []policy.SecretRef{{
					Name: "db-creds",
					Key:  "password",
				}},
				SecretEnvFromRefs: []string{"db-creds"},
				EnvVars: []policy.EnvVar{{
					Name:  "API_TOKEN",
					Value: "not-a-real-token-" + strconv.Itoa(i),
				}},
			}},
		})

		serviceType := "ClusterIP"
		if i%3 == 0 {
			serviceType = "LoadBalancer"
		}
		inventory.Services = append(inventory.Services, policy.Service{
			Resource: policy.ResourceRef{APIVersion: "v1", Kind: "Service", Namespace: namespace, Name: app},
			Type:     serviceType,
			Selector: labels,
		})
	}

	return inventory
}

func controlPlaneLabels(i int) map[string]string {
	labels := map[string]string{}
	if i%3 == 0 {
		labels["node-role.kubernetes.io/control-plane"] = ""
	}
	return labels
}

func nodeExternalIPs(i int) []string {
	if i%4 == 0 {
		return []string{"203.0.113." + strconv.Itoa(i+10)}
	}
	return nil
}

func kubeletVersion(i int) string {
	if i%5 == 0 {
		return "v1.30.2"
	}
	return "v1.31.1"
}

func kubeProxyVersion(i int) string {
	if i%6 == 0 {
		return "v1.30.2"
	}
	return "v1.31.1"
}

func controlPlaneVersion(i int) string {
	if i%2 == 0 {
		return "v1.31.1"
	}
	return "v1.30.2"
}

func nodeNameForWorkload(i int) string {
	if i%10 == 0 {
		return "node-0"
	}
	return ""
}

func tolerationsForWorkload(i int) []policy.Toleration {
	if i%8 == 0 {
		return []policy.Toleration{{
			Key:      "node-role.kubernetes.io/control-plane",
			Operator: "Exists",
			Effect:   "NoSchedule",
		}}
	}
	return nil
}

func imageForWorkload(i int) string {
	if i%2 == 0 {
		return "nginx:latest"
	}
	return "ghcr.io/example/app:" + strconv.Itoa(i)
}

func imageDigestForWorkload(i int) string {
	return "sha256:" + strconv.FormatInt(int64(100000+i), 16)
}

func seccompForWorkload(i int) string {
	if i%4 == 0 {
		return "Unconfined"
	}
	return ""
}

func capabilitiesForWorkload(i int) []string {
	if i%5 == 0 {
		return []string{"SYS_ADMIN", "NET_ADMIN"}
	}
	return []string{"NET_BIND_SERVICE"}
}

func largeSBOMFixture(inventory policy.Inventory) (vuln.SBOMIndex, vuln.AdvisoryBundle) {
	sboms := vuln.SBOMIndex{}
	advisories := vuln.AdvisoryBundle{
		APIVersion: vuln.AdvisoryBundleAPIVersion,
		Kind:       vuln.AdvisoryBundleKind,
	}
	for i, workload := range inventory.Workloads {
		if len(workload.Containers) == 0 {
			continue
		}
		container := workload.Containers[0]
		sboms[container.ImageDigest] = vuln.SBOM{
			ImageRef: container.ImageDigest,
			Packages: []vuln.Package{
				{
					Name:      "openssl-" + strconv.Itoa(i),
					Version:   "1.0." + strconv.Itoa(i%7),
					Ecosystem: "deb",
					PURL:      "pkg:deb/debian/openssl-" + strconv.Itoa(i) + "@1.0." + strconv.Itoa(i%7),
				},
			},
		}
		advisories.Advisories = append(advisories.Advisories, vuln.Advisory{
			ID:               "CVE-2026-" + strconv.Itoa(1000+i),
			Summary:          "Synthetic advisory",
			PackageName:      "openssl-" + strconv.Itoa(i),
			Ecosystem:        "deb",
			AffectedVersions: []string{"=1.0." + strconv.Itoa(i%7)},
			Severity:         policy.SeverityHigh,
			FixedVersion:     "1.0.99",
		})
	}
	return sboms, advisories
}

func createFilesystemFixture(b *testing.B, root string) {
	b.Helper()
	for i := 0; i < 120; i++ {
		namespace := "team-" + strconv.Itoa(i%12)
		dir := filepath.Join(root, namespace, "service-"+strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatalf("mkdir %s: %v", dir, err)
		}
		manifest := strings.TrimSpace(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: `+namespace+`
spec:
  template:
    spec:
      containers:
        - name: api
          image: nginx:latest
`) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "deployment.yaml"), []byte(manifest), 0o644); err != nil {
			b.Fatalf("write manifest: %v", err)
		}
		envContent := "API_TOKEN=synthetic-token-" + strconv.Itoa(i) + "\n"
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644); err != nil {
			b.Fatalf("write env: %v", err)
		}
		config := `{"name":"svc-` + strconv.Itoa(i) + `","license":"MIT"}`
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(config), 0o644); err != nil {
			b.Fatalf("write package json: %v", err)
		}
	}
}
