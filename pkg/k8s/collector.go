package k8s

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"kubescan/api/v1alpha1"
	"kubescan/pkg/policy"
)

type ClusterOptions struct {
	Kubeconfig     string
	Context        string
	Namespace      string
	NamespacedOnly bool
}

type InventoryCollector struct {
	client         kubernetes.Interface
	dynamicClient  dynamic.Interface
	namespacedOnly bool
}

func NewInventoryCollector(client kubernetes.Interface) *InventoryCollector {
	return &InventoryCollector{client: client}
}

func NewInventoryCollectorWithOptions(client kubernetes.Interface, namespacedOnly bool) *InventoryCollector {
	return NewInventoryCollectorWithClients(client, nil, namespacedOnly)
}

func NewInventoryCollectorWithClients(client kubernetes.Interface, dynamicClient dynamic.Interface, namespacedOnly bool) *InventoryCollector {
	return &InventoryCollector{
		client:         client,
		dynamicClient:  dynamicClient,
		namespacedOnly: namespacedOnly,
	}
}

func NewCollectorFromOptions(options ClusterOptions) (*InventoryCollector, error) {
	config, err := RESTConfigFromOptions(options)
	if err != nil {
		return nil, err
	}
	return NewCollectorFromConfigWithOptions(config, options.NamespacedOnly)
}

func NewCollectorFromConfig(config *rest.Config) (*InventoryCollector, error) {
	return NewCollectorFromConfigWithOptions(config, false)
}

func NewCollectorFromConfigWithOptions(config *rest.Config, namespacedOnly bool) (*InventoryCollector, error) {
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	return NewInventoryCollectorWithClients(client, dynamicClient, namespacedOnly), nil
}

func RESTConfigFromOptions(options ClusterOptions) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = options.Kubeconfig

	overrides := &clientcmd.ConfigOverrides{}
	if options.Context != "" {
		overrides.CurrentContext = options.Context
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	if err == nil {
		return config, nil
	}
	inClusterConfig, inClusterErr := rest.InClusterConfig()
	if inClusterErr == nil {
		return inClusterConfig, nil
	}
	return nil, fmt.Errorf("build kubeconfig: %w", err)
}

func (c *InventoryCollector) Collect(ctx context.Context, namespace string) (policy.Inventory, error) {
	inventory := policy.Inventory{}
	targetNamespace := namespace
	if targetNamespace == "" {
		targetNamespace = metav1.NamespaceAll
	}

	pods, err := c.client.CoreV1().Pods(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list pods: %w", err)
	}
	for _, pod := range pods.Items {
		inventory.Workloads = append(inventory.Workloads, workloadFromPod(&pod))
		inventory.Components = append(inventory.Components, controlPlaneComponentsFromPod(&pod)...)
	}

	if !c.namespacedOnly {
		nodes, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return policy.Inventory{}, fmt.Errorf("list nodes: %w", err)
		}
		for _, node := range nodes.Items {
			inventory.Nodes = append(inventory.Nodes, nodeFromK8s(&node))
			inventory.Components = append(inventory.Components, componentsFromNode(&node)...)
		}
		if err := c.applyNodeReports(ctx, &inventory); err != nil {
			return policy.Inventory{}, err
		}
	}

	deployments, err := c.client.AppsV1().Deployments(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list deployments: %w", err)
	}
	for _, deployment := range deployments.Items {
		inventory.Workloads = append(inventory.Workloads, workloadFromDeployment(&deployment))
	}

	statefulSets, err := c.client.AppsV1().StatefulSets(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list statefulsets: %w", err)
	}
	for _, statefulSet := range statefulSets.Items {
		inventory.Workloads = append(inventory.Workloads, workloadFromStatefulSet(&statefulSet))
	}

	daemonSets, err := c.client.AppsV1().DaemonSets(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list daemonsets: %w", err)
	}
	for _, daemonSet := range daemonSets.Items {
		inventory.Workloads = append(inventory.Workloads, workloadFromDaemonSet(&daemonSet))
	}

	jobs, err := c.client.BatchV1().Jobs(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list jobs: %w", err)
	}
	for _, job := range jobs.Items {
		inventory.Workloads = append(inventory.Workloads, workloadFromJob(&job))
	}

	cronJobs, err := c.client.BatchV1().CronJobs(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list cronjobs: %w", err)
	}
	for _, cronJob := range cronJobs.Items {
		inventory.Workloads = append(inventory.Workloads, workloadFromCronJob(&cronJob))
	}

	services, err := c.client.CoreV1().Services(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list services: %w", err)
	}
	for _, service := range services.Items {
		inventory.Services = append(inventory.Services, serviceFromK8s(&service))
	}

	configMaps, err := c.client.CoreV1().ConfigMaps(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list configmaps: %w", err)
	}
	for _, configMap := range configMaps.Items {
		inventory.ConfigMaps = append(inventory.ConfigMaps, configMapFromK8s(&configMap))
	}

	roles, err := c.client.RbacV1().Roles(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list roles: %w", err)
	}
	for _, role := range roles.Items {
		inventory.Roles = append(inventory.Roles, roleFromRole(&role))
	}

	if !c.namespacedOnly {
		clusterRoles, err := c.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
		if err != nil {
			return policy.Inventory{}, fmt.Errorf("list clusterroles: %w", err)
		}
		for _, clusterRole := range clusterRoles.Items {
			inventory.Roles = append(inventory.Roles, roleFromClusterRole(&clusterRole))
		}
	}

	roleBindings, err := c.client.RbacV1().RoleBindings(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list rolebindings: %w", err)
	}
	for _, roleBinding := range roleBindings.Items {
		inventory.Bindings = append(inventory.Bindings, bindingFromRoleBinding(&roleBinding))
	}

	if !c.namespacedOnly {
		clusterRoleBindings, err := c.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return policy.Inventory{}, fmt.Errorf("list clusterrolebindings: %w", err)
		}
		for _, clusterRoleBinding := range clusterRoleBindings.Items {
			inventory.Bindings = append(inventory.Bindings, bindingFromClusterRoleBinding(&clusterRoleBinding))
		}
	}

	networkPolicies, err := c.client.NetworkingV1().NetworkPolicies(targetNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return policy.Inventory{}, fmt.Errorf("list networkpolicies: %w", err)
	}
	for _, networkPolicy := range networkPolicies.Items {
		inventory.NetworkPolicies = append(inventory.NetworkPolicies, networkPolicyFromK8s(&networkPolicy))
	}

	if !c.namespacedOnly {
		if targetNamespace == metav1.NamespaceAll {
			namespaces, err := c.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
			if err != nil {
				return policy.Inventory{}, fmt.Errorf("list namespaces: %w", err)
			}
			for _, namespace := range namespaces.Items {
				inventory.Namespaces = append(inventory.Namespaces, namespaceFromK8s(&namespace))
			}
		} else if namespace, err := c.client.CoreV1().Namespaces().Get(ctx, targetNamespace, metav1.GetOptions{}); err == nil {
			inventory.Namespaces = append(inventory.Namespaces, namespaceFromK8s(namespace))
		}
	} else if targetNamespace != metav1.NamespaceAll {
		inventory.Namespaces = append(inventory.Namespaces, policy.Namespace{
			Resource: policy.ResourceRef{Kind: "Namespace", Name: targetNamespace},
		})
	}

	return inventory, nil
}

var nodeReportGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.Version,
	Resource: "nodereports",
}

func (c *InventoryCollector) applyNodeReports(ctx context.Context, inventory *policy.Inventory) error {
	if c.dynamicClient == nil {
		return nil
	}
	list, err := c.dynamicClient.Resource(nodeReportGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) || meta.IsNoMatchError(err) {
			return nil
		}
		return fmt.Errorf("list node reports: %w", err)
	}

	nodesByName := make(map[string]*policy.Node, len(inventory.Nodes))
	for i := range inventory.Nodes {
		nodesByName[inventory.Nodes[i].Resource.Name] = &inventory.Nodes[i]
	}

	for _, item := range list.Items {
		var nodeReport v1alpha1.NodeReport
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &nodeReport); err != nil {
			return fmt.Errorf("decode node report %s: %w", item.GetName(), err)
		}
		nodeName := strings.TrimSpace(nodeReport.Spec.NodeName)
		if nodeName == "" {
			nodeName = strings.TrimSpace(item.GetName())
		}
		if nodeName == "" {
			continue
		}

		target, ok := nodesByName[nodeName]
		if !ok {
			inventory.Nodes = append(inventory.Nodes, policy.Node{
				Resource: policy.ResourceRef{
					APIVersion: "v1",
					Kind:       "Node",
					Name:       nodeName,
				},
			})
			target = &inventory.Nodes[len(inventory.Nodes)-1]
			nodesByName[nodeName] = target
		}

		target.KubeletConfigPath = strings.TrimSpace(nodeReport.Spec.KubeletConfigPath)
		target.KubeletAnonymousAuthEnabled = cloneBoolPointer(nodeReport.Spec.AnonymousAuthEnabled)
		target.KubeletWebhookAuthenticationEnabled = cloneBoolPointer(nodeReport.Spec.WebhookAuthenticationEnabled)
		target.KubeletAuthorizationMode = strings.TrimSpace(nodeReport.Spec.AuthorizationMode)
		target.KubeletAuthenticationX509ClientCAFile = strings.TrimSpace(nodeReport.Spec.AuthenticationX509ClientCAFile)
		target.KubeletReadOnlyPort = cloneInt32Pointer(nodeReport.Spec.ReadOnlyPort)
		target.KubeletProtectKernelDefaults = cloneBoolPointer(nodeReport.Spec.ProtectKernelDefaults)
		target.KubeletFailSwapOn = cloneBoolPointer(nodeReport.Spec.FailSwapOn)
		target.KubeletRotateCertificates = cloneBoolPointer(nodeReport.Spec.RotateCertificates)
		target.KubeletServerTLSBootstrap = cloneBoolPointer(nodeReport.Spec.ServerTLSBootstrap)
		target.KubeletSeccompDefault = cloneBoolPointer(nodeReport.Spec.SeccompDefault)
	}

	return nil
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt32Pointer(value *int32) *int32 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func workloadFromPod(pod *corev1.Pod) policy.Workload {
	workload := workloadFromPodSpec(resourceRef(pod.APIVersion, "Pod", pod.Namespace, pod.Name), pod.Labels, &pod.Spec)
	applyContainerStatuses(&workload, pod.Status.ContainerStatuses)
	return workload
}

func workloadFromDeployment(deployment *appsv1.Deployment) policy.Workload {
	return workloadFromPodSpec(resourceRef(deployment.APIVersion, "Deployment", deployment.Namespace, deployment.Name), deployment.Spec.Template.Labels, &deployment.Spec.Template.Spec)
}

func workloadFromStatefulSet(statefulSet *appsv1.StatefulSet) policy.Workload {
	return workloadFromPodSpec(resourceRef(statefulSet.APIVersion, "StatefulSet", statefulSet.Namespace, statefulSet.Name), statefulSet.Spec.Template.Labels, &statefulSet.Spec.Template.Spec)
}

func workloadFromDaemonSet(daemonSet *appsv1.DaemonSet) policy.Workload {
	return workloadFromPodSpec(resourceRef(daemonSet.APIVersion, "DaemonSet", daemonSet.Namespace, daemonSet.Name), daemonSet.Spec.Template.Labels, &daemonSet.Spec.Template.Spec)
}

func workloadFromJob(job *batchv1.Job) policy.Workload {
	return workloadFromPodSpec(resourceRef(job.APIVersion, "Job", job.Namespace, job.Name), job.Spec.Template.Labels, &job.Spec.Template.Spec)
}

func workloadFromCronJob(cronJob *batchv1.CronJob) policy.Workload {
	return workloadFromPodSpec(resourceRef(cronJob.APIVersion, "CronJob", cronJob.Namespace, cronJob.Name), cronJob.Spec.JobTemplate.Spec.Template.Labels, &cronJob.Spec.JobTemplate.Spec.Template.Spec)
}

func workloadFromPodSpec(resource policy.ResourceRef, labels map[string]string, spec *corev1.PodSpec) policy.Workload {
	workload := policy.Workload{
		Resource:           resource,
		Labels:             cloneStringMap(labels),
		ServiceAccountName: spec.ServiceAccountName,
		NodeName:           spec.NodeName,
		HostNetwork:        spec.HostNetwork,
		HostPID:            spec.HostPID,
		HostIPC:            spec.HostIPC,
	}
	if workload.ServiceAccountName == "" {
		workload.ServiceAccountName = "default"
	}
	if spec.AutomountServiceAccountToken != nil {
		value := *spec.AutomountServiceAccountToken
		workload.AutomountServiceAccountToken = &value
	}
	for _, container := range spec.Containers {
		workload.Containers = append(workload.Containers, containerFromCore(container, spec.SecurityContext))
	}
	for _, volume := range spec.Volumes {
		if volume.Secret != nil {
			workload.SecretVolumes = append(workload.SecretVolumes, volume.Secret.SecretName)
		}
		if volume.HostPath != nil {
			workload.HostPathVolumes = append(workload.HostPathVolumes, policy.HostPathVolume{
				Name: volume.Name,
				Path: volume.HostPath.Path,
			})
		}
	}
	for _, toleration := range spec.Tolerations {
		workload.Tolerations = append(workload.Tolerations, policy.Toleration{
			Key:      toleration.Key,
			Operator: string(toleration.Operator),
			Value:    toleration.Value,
			Effect:   string(toleration.Effect),
		})
	}
	return workload
}

func applyContainerStatuses(workload *policy.Workload, statuses []corev1.ContainerStatus) {
	if len(statuses) == 0 || len(workload.Containers) == 0 {
		return
	}
	byName := make(map[string]string, len(statuses))
	for _, status := range statuses {
		if digest := normalizeImageID(status.ImageID); digest != "" {
			byName[status.Name] = digest
		}
	}
	for i := range workload.Containers {
		if digest, ok := byName[workload.Containers[i].Name]; ok {
			workload.Containers[i].ImageDigest = digest
		}
	}
}

func normalizeImageID(imageID string) string {
	trimmed := strings.TrimSpace(imageID)
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

func containerFromCore(container corev1.Container, podSecurityContext *corev1.PodSecurityContext) policy.Container {
	result := policy.Container{
		Name:              container.Name,
		Image:             container.Image,
		HasLivenessProbe:  container.LivenessProbe != nil,
		HasReadinessProbe: container.ReadinessProbe != nil,
	}

	if container.SecurityContext != nil {
		if container.SecurityContext.Privileged != nil {
			value := *container.SecurityContext.Privileged
			result.Privileged = &value
		}
		if container.SecurityContext.AllowPrivilegeEscalation != nil {
			value := *container.SecurityContext.AllowPrivilegeEscalation
			result.AllowPrivilegeEscalation = &value
		}
		if container.SecurityContext.RunAsNonRoot != nil {
			value := *container.SecurityContext.RunAsNonRoot
			result.RunAsNonRoot = &value
		}
		if container.SecurityContext.RunAsUser != nil {
			value := *container.SecurityContext.RunAsUser
			result.RunAsUser = &value
		}
		if container.SecurityContext.ReadOnlyRootFilesystem != nil {
			value := *container.SecurityContext.ReadOnlyRootFilesystem
			result.ReadOnlyRootFilesystem = &value
		}
		if container.SecurityContext.Capabilities != nil {
			for _, capability := range container.SecurityContext.Capabilities.Add {
				result.CapabilitiesAdd = append(result.CapabilitiesAdd, string(capability))
			}
		}
		if container.SecurityContext.SeccompProfile != nil {
			result.SeccompProfileType = string(container.SecurityContext.SeccompProfile.Type)
		}
	}

	if result.RunAsNonRoot == nil && podSecurityContext != nil && podSecurityContext.RunAsNonRoot != nil {
		value := *podSecurityContext.RunAsNonRoot
		result.RunAsNonRoot = &value
	}
	if result.RunAsUser == nil && podSecurityContext != nil && podSecurityContext.RunAsUser != nil {
		value := *podSecurityContext.RunAsUser
		result.RunAsUser = &value
	}
	if result.SeccompProfileType == "" && podSecurityContext != nil && podSecurityContext.SeccompProfile != nil {
		result.SeccompProfileType = string(podSecurityContext.SeccompProfile.Type)
	}
	for _, env := range container.Env {
		source := ""
		if env.ValueFrom != nil {
			switch {
			case env.ValueFrom.SecretKeyRef != nil:
				source = "secretKeyRef"
			case env.ValueFrom.ConfigMapKeyRef != nil:
				source = "configMapKeyRef"
			case env.ValueFrom.FieldRef != nil:
				source = "fieldRef"
			case env.ValueFrom.ResourceFieldRef != nil:
				source = "resourceFieldRef"
			}
		}
		result.EnvVars = append(result.EnvVars, policy.EnvVar{
			Name:      env.Name,
			Value:     env.Value,
			ValueFrom: source,
		})
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			result.SecretEnvRefs = append(result.SecretEnvRefs, policy.SecretRef{
				Name: env.ValueFrom.SecretKeyRef.Name,
				Key:  env.ValueFrom.SecretKeyRef.Key,
			})
		}
	}
	for _, envFrom := range container.EnvFrom {
		if envFrom.SecretRef != nil {
			result.SecretEnvFromRefs = append(result.SecretEnvFromRefs, envFrom.SecretRef.Name)
		}
	}

	result.HasResourceRequests = hasResourceQuantity(container.Resources.Requests, corev1.ResourceCPU) && hasResourceQuantity(container.Resources.Requests, corev1.ResourceMemory)
	result.HasResourceLimits = hasResourceQuantity(container.Resources.Limits, corev1.ResourceCPU) && hasResourceQuantity(container.Resources.Limits, corev1.ResourceMemory)
	for _, port := range container.Ports {
		if port.HostPort > 0 {
			result.HostPorts = append(result.HostPorts, port.HostPort)
		}
	}

	return result
}

func serviceFromK8s(service *corev1.Service) policy.Service {
	serviceType := string(service.Spec.Type)
	if serviceType == "" {
		serviceType = string(corev1.ServiceTypeClusterIP)
	}
	return policy.Service{
		Resource: resourceRef(service.APIVersion, "Service", service.Namespace, service.Name),
		Type:     serviceType,
		Selector: cloneStringMap(service.Spec.Selector),
	}
}

func configMapFromK8s(configMap *corev1.ConfigMap) policy.ConfigMap {
	data := make(map[string]string, len(configMap.Data))
	for key, value := range configMap.Data {
		data[key] = value
	}
	return policy.ConfigMap{
		Resource: resourceRef(configMap.APIVersion, "ConfigMap", configMap.Namespace, configMap.Name),
		Data:     data,
	}
}

func roleFromRole(role *rbacv1.Role) policy.Role {
	return policy.Role{
		Resource: resourceRef(role.APIVersion, "Role", role.Namespace, role.Name),
		Rules:    convertRBACRules(role.Rules),
	}
}

func roleFromClusterRole(role *rbacv1.ClusterRole) policy.Role {
	return policy.Role{
		Resource: resourceRef(role.APIVersion, "ClusterRole", "", role.Name),
		Rules:    convertRBACRules(role.Rules),
	}
}

func convertRBACRules(rules []rbacv1.PolicyRule) []policy.PolicyRule {
	converted := make([]policy.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		converted = append(converted, policy.PolicyRule{
			Verbs:           append([]string(nil), rule.Verbs...),
			Resources:       append([]string(nil), rule.Resources...),
			NonResourceURLs: append([]string(nil), rule.NonResourceURLs...),
		})
	}
	return converted
}

func bindingFromRoleBinding(binding *rbacv1.RoleBinding) policy.Binding {
	return policy.Binding{
		Resource:    resourceRef(binding.APIVersion, "RoleBinding", binding.Namespace, binding.Name),
		RoleRefKind: binding.RoleRef.Kind,
		RoleRefName: binding.RoleRef.Name,
		Subjects:    convertSubjects(binding.Subjects),
	}
}

func bindingFromClusterRoleBinding(binding *rbacv1.ClusterRoleBinding) policy.Binding {
	return policy.Binding{
		Resource:    resourceRef(binding.APIVersion, "ClusterRoleBinding", "", binding.Name),
		RoleRefKind: binding.RoleRef.Kind,
		RoleRefName: binding.RoleRef.Name,
		Subjects:    convertSubjects(binding.Subjects),
	}
}

func convertSubjects(subjects []rbacv1.Subject) []policy.Subject {
	converted := make([]policy.Subject, 0, len(subjects))
	for _, subject := range subjects {
		converted = append(converted, policy.Subject{
			Kind:      subject.Kind,
			Name:      subject.Name,
			Namespace: subject.Namespace,
		})
	}
	return converted
}

func networkPolicyFromK8s(networkPolicy *networkingv1.NetworkPolicy) policy.NetworkPolicy {
	policyTypes := make([]string, 0, len(networkPolicy.Spec.PolicyTypes))
	for _, policyType := range networkPolicy.Spec.PolicyTypes {
		policyTypes = append(policyTypes, string(policyType))
	}
	return policy.NetworkPolicy{
		Resource:    resourceRef(networkPolicy.APIVersion, "NetworkPolicy", networkPolicy.Namespace, networkPolicy.Name),
		PolicyTypes: policyTypes,
		HasIngress:  len(policyTypes) == 0 || len(networkPolicy.Spec.Ingress) > 0 || containsPolicyType(policyTypes, string(networkingv1.PolicyTypeIngress)),
		HasEgress:   len(networkPolicy.Spec.Egress) > 0 || containsPolicyType(policyTypes, string(networkingv1.PolicyTypeEgress)),
	}
}

func namespaceFromK8s(namespace *corev1.Namespace) policy.Namespace {
	return policy.Namespace{
		Resource: resourceRef(namespace.APIVersion, "Namespace", "", namespace.Name),
		Labels:   cloneStringMap(namespace.Labels),
	}
}

func nodeFromK8s(node *corev1.Node) policy.Node {
	result := policy.Node{
		Resource:           resourceRef(node.APIVersion, "Node", "", node.Name),
		Labels:             cloneStringMap(node.Labels),
		Unschedulable:      node.Spec.Unschedulable,
		ContainerRuntime:   strings.TrimSpace(node.Status.NodeInfo.ContainerRuntimeVersion),
		KernelVersion:      strings.TrimSpace(node.Status.NodeInfo.KernelVersion),
		OSImage:            strings.TrimSpace(node.Status.NodeInfo.OSImage),
		KubeletVersion:     normalizeComponentVersion(node.Status.NodeInfo.KubeletVersion),
		KubeProxyVersion:   normalizeComponentVersion(node.Status.NodeInfo.KubeProxyVersion),
		Ready:              nodeConditionStatus(node.Status.Conditions, corev1.NodeReady) == corev1.ConditionTrue,
		MemoryPressure:     nodeConditionStatus(node.Status.Conditions, corev1.NodeMemoryPressure) == corev1.ConditionTrue,
		DiskPressure:       nodeConditionStatus(node.Status.Conditions, corev1.NodeDiskPressure) == corev1.ConditionTrue,
		PIDPressure:        nodeConditionStatus(node.Status.Conditions, corev1.NodePIDPressure) == corev1.ConditionTrue,
		NetworkUnavailable: nodeConditionStatus(node.Status.Conditions, corev1.NodeNetworkUnavailable) == corev1.ConditionTrue,
	}
	for _, taint := range node.Spec.Taints {
		result.Taints = append(result.Taints, policy.Taint{
			Key:    taint.Key,
			Value:  taint.Value,
			Effect: string(taint.Effect),
		})
	}
	for _, address := range node.Status.Addresses {
		if address.Type == corev1.NodeExternalIP && strings.TrimSpace(address.Address) != "" {
			result.ExternalIPs = append(result.ExternalIPs, strings.TrimSpace(address.Address))
		}
	}
	return result
}

func resourceRef(apiVersion, kind, namespace, name string) policy.ResourceRef {
	return policy.ResourceRef{
		APIVersion: apiVersion,
		Kind:       kind,
		Namespace:  namespace,
		Name:       name,
	}
}

func hasResourceQuantity(values corev1.ResourceList, key corev1.ResourceName) bool {
	quantity, ok := values[key]
	return ok && !quantity.IsZero()
}

func containsPolicyType(policyTypes []string, expected string) bool {
	for _, policyType := range policyTypes {
		if policyType == expected {
			return true
		}
	}
	return false
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func nodeConditionStatus(conditions []corev1.NodeCondition, conditionType corev1.NodeConditionType) corev1.ConditionStatus {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status
		}
	}
	return corev1.ConditionUnknown
}

func componentsFromNode(node *corev1.Node) []policy.ClusterComponent {
	ref := resourceRef(node.APIVersion, "Node", "", node.Name)
	var components []policy.ClusterComponent

	if version := normalizeComponentVersion(node.Status.NodeInfo.KubeletVersion); version != "" {
		components = append(components, policy.ClusterComponent{
			Resource:  ref,
			Name:      "kubelet",
			Version:   version,
			Ecosystem: "kubernetes",
			Source:    "node.status.nodeInfo.kubeletVersion",
		})
	}
	if version := normalizeComponentVersion(node.Status.NodeInfo.KubeProxyVersion); version != "" {
		components = append(components, policy.ClusterComponent{
			Resource:  ref,
			Name:      "kube-proxy",
			Version:   version,
			Ecosystem: "kubernetes",
			Source:    "node.status.nodeInfo.kubeProxyVersion",
		})
	}

	return components
}

func controlPlaneComponentsFromPod(pod *corev1.Pod) []policy.ClusterComponent {
	if pod.Namespace != "kube-system" {
		return nil
	}

	componentName := controlPlaneComponentName(pod.Name)
	if componentName == "" {
		return nil
	}

	resource := resourceRef(pod.APIVersion, "Pod", pod.Namespace, pod.Name)
	var components []policy.ClusterComponent
	for _, container := range pod.Spec.Containers {
		version, ok := versionFromImage(container.Image)
		if !ok {
			continue
		}
		components = append(components, policy.ClusterComponent{
			Resource:  resource,
			Name:      componentName,
			Version:   version,
			Ecosystem: "kubernetes",
			Source:    "pod.spec.containers[].image",
		})
		break
	}
	return components
}

func controlPlaneComponentName(podName string) string {
	name := strings.ToLower(podName)
	for _, prefix := range []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"} {
		if strings.HasPrefix(name, prefix) {
			return prefix
		}
	}
	return ""
}

func versionFromImage(image string) (string, bool) {
	trimmed := strings.TrimSpace(image)
	if trimmed == "" {
		return "", false
	}
	if at := strings.Index(trimmed, "@"); at >= 0 {
		trimmed = trimmed[:at]
	}
	lastSlash := strings.LastIndex(trimmed, "/")
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon <= lastSlash {
		return "", false
	}
	version := normalizeComponentVersion(trimmed[lastColon+1:])
	if version == "" {
		return "", false
	}
	return version, true
}

func normalizeComponentVersion(version string) string {
	trimmed := strings.TrimSpace(version)
	switch trimmed {
	case "", "<unknown>", "unknown", "v0.0.0":
		return ""
	default:
		return trimmed
	}
}
