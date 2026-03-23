package k8s

import (
	"strings"
	"testing"
)

func TestLoadInventory(t *testing.T) {
	manifest := `---
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  template:
    metadata:
      labels:
        app: api
        tier: frontend
    spec:
      serviceAccountName: api
      nodeName: worker-1
      hostNetwork: true
      automountServiceAccountToken: true
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          operator: Exists
          effect: NoSchedule
      securityContext:
        runAsNonRoot: false
        runAsUser: 0
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: nginx:latest
          ports:
            - containerPort: 8080
              hostPort: 8080
          env:
            - name: PASSWORD
              value: insecure-value
            - name: PASSWORD_FROM_SECRET
              valueFrom:
                secretKeyRef:
                  name: db-creds
                  key: password
          envFrom:
            - secretRef:
                name: shared-config
          securityContext:
            privileged: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false
            capabilities:
              add: ["SYS_ADMIN"]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 100m
              memory: 128Mi
          livenessProbe:
            httpGet:
              path: /live
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
      volumes:
        - name: tls
          secret:
            secretName: api-tls
        - name: host-data
          hostPath:
            path: /var/lib/data
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: payments
spec:
  type: LoadBalancer
  selector:
    app: api
--- 
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: payments
data:
  api_token: super-secret
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: payments
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wildcard
  namespace: payments
rules:
  - verbs: ["*"]
    resources: ["pods"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-admin
  namespace: payments
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: wildcard
subjects:
  - kind: ServiceAccount
    name: api
`

	inventory, err := LoadInventory(strings.NewReader(manifest))
	if err != nil {
		t.Fatalf("LoadInventory returned error: %v", err)
	}

	if got := len(inventory.Workloads); got != 1 {
		t.Fatalf("expected 1 workload, got %d", got)
	}
	if got := len(inventory.Services); got != 1 {
		t.Fatalf("expected 1 service, got %d", got)
	}
	if got := len(inventory.ConfigMaps); got != 1 {
		t.Fatalf("expected 1 configmap, got %d", got)
	}
	if got := len(inventory.NetworkPolicies); got != 1 {
		t.Fatalf("expected 1 network policy, got %d", got)
	}
	if got := len(inventory.Namespaces); got != 1 {
		t.Fatalf("expected 1 namespace, got %d", got)
	}
	if got := len(inventory.Roles); got != 1 {
		t.Fatalf("expected 1 role, got %d", got)
	}
	if got := len(inventory.Bindings); got != 1 {
		t.Fatalf("expected 1 binding, got %d", got)
	}

	workload := inventory.Workloads[0]
	if workload.Resource.Kind != "Deployment" {
		t.Fatalf("unexpected workload kind %q", workload.Resource.Kind)
	}
	if workload.Labels["app"] != "api" || workload.Labels["tier"] != "frontend" {
		t.Fatalf("expected workload labels to be collected, got %v", workload.Labels)
	}
	if !workload.HostNetwork {
		t.Fatalf("expected hostNetwork to be true")
	}
	if workload.NodeName != "worker-1" {
		t.Fatalf("expected nodeName worker-1, got %q", workload.NodeName)
	}
	if len(workload.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(workload.Containers))
	}
	if workload.Containers[0].Image != "nginx:latest" {
		t.Fatalf("unexpected image %q", workload.Containers[0].Image)
	}
	if workload.Containers[0].RunAsNonRoot == nil || *workload.Containers[0].RunAsNonRoot {
		t.Fatalf("expected pod-level runAsNonRoot=false to be inherited")
	}
	if workload.Containers[0].RunAsUser == nil || *workload.Containers[0].RunAsUser != 0 {
		t.Fatalf("expected pod-level runAsUser=0 to be inherited")
	}
	if got := len(workload.Containers[0].CapabilitiesAdd); got != 1 {
		t.Fatalf("expected 1 added capability, got %d", got)
	}
	if workload.Containers[0].AllowPrivilegeEscalation == nil || *workload.Containers[0].AllowPrivilegeEscalation {
		t.Fatalf("expected allowPrivilegeEscalation=false to be collected")
	}
	if workload.Containers[0].SeccompProfileType != "RuntimeDefault" {
		t.Fatalf("expected RuntimeDefault seccomp profile, got %q", workload.Containers[0].SeccompProfileType)
	}
	if got := len(workload.Containers[0].HostPorts); got != 1 || workload.Containers[0].HostPorts[0] != 8080 {
		t.Fatalf("expected hostPort 8080 to be collected, got %v", workload.Containers[0].HostPorts)
	}
	if got := len(workload.Containers[0].EnvVars); got != 2 {
		t.Fatalf("expected 2 env vars, got %d", got)
	}
	if got := len(workload.Containers[0].SecretEnvRefs); got != 1 {
		t.Fatalf("expected 1 secret env ref, got %d", got)
	}
	if got := len(workload.SecretVolumes); got != 1 {
		t.Fatalf("expected 1 secret volume, got %d", got)
	}
	if got := len(workload.HostPathVolumes); got != 1 || workload.HostPathVolumes[0].Path != "/var/lib/data" {
		t.Fatalf("expected hostPath volume /var/lib/data, got %+v", workload.HostPathVolumes)
	}
	if got := len(workload.Tolerations); got != 1 || workload.Tolerations[0].Key != "node-role.kubernetes.io/control-plane" {
		t.Fatalf("expected control-plane toleration, got %+v", workload.Tolerations)
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
	if !inventory.NetworkPolicies[0].HasIngress || inventory.NetworkPolicies[0].HasEgress {
		t.Fatalf("expected default network policy to collect ingress-only semantics, got %+v", inventory.NetworkPolicies[0])
	}
	if inventory.Bindings[0].RoleRefName != "wildcard" {
		t.Fatalf("expected role binding to reference wildcard role, got %q", inventory.Bindings[0].RoleRefName)
	}
}
