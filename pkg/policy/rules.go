package policy

import (
	"sort"
	"strings"

	"kubescan/pkg/secretscan"
)

func allRules() []Rule {
	return []Rule{
		privilegedContainerRule(),
		privilegedHostPIDRule(),
		privilegedHostPathRule(),
		sensitiveHostPathRule(),
		hostNamespaceRule(),
		dangerousCapabilitiesRule(),
		allowPrivilegeEscalationRule(),
		seccompProfileRule(),
		runAsNonRootRule(),
		runAsRootRule(),
		readOnlyRootFilesystemRule(),
		hostPathVolumeRule(),
		hostPortRule(),
		resourceRequestsRule(),
		resourceLimitsRule(),
		livenessProbeRule(),
		readinessProbeRule(),
		mutableTagRule(),
		serviceExposureRule(),
		serviceAccountTokenRule(),
		wildcardRBACRule(),
		wildcardRBACSubjectRule(),
		clusterAdminSubjectRule(),
		privilegedServiceAccountWorkloadRule(),
		defaultServiceAccountWorkloadRule(),
		secretEnvExposureRule(),
		secretVolumeExposureRule(),
		secretReadSubjectRule(),
		secretReadServiceAccountWorkloadRule(),
		networkPolicyCoverageRule(),
		ingressPolicyCoverageRule(),
		egressPolicyCoverageRule(),
		podSecurityAdmissionLabelsRule(),
		plaintextCredentialRule(),
		publicRegistryImageRule(),
		controlPlaneSchedulingRule(),
		schedulableControlPlaneNodeRule(),
		legacyDockerRuntimeNodeRule(),
		externalIPNodeRule(),
		nodeNotReadyRule(),
		kubeletVersionSkewRule(),
		kubeProxyVersionSkewRule(),
		controlPlaneVersionSkewRule(),
		nodePressureRule(),
		nodeNetworkUnavailableRule(),
		kubeletAnonymousAuthRule(),
		kubeletWebhookAuthenticationRule(),
		kubeletAuthorizationModeRule(),
		kubeletReadOnlyPortRule(),
		kubeletProtectKernelDefaultsRule(),
		kubeletRotateCertificatesRule(),
		kubeletServerTLSBootstrapRule(),
		kubeletSeccompDefaultRule(),
		kubeletClientCAFileRule(),
		kubeletFailSwapOnRule(),
	}
}

func dangerousCapabilitiesRule() Rule {
	rule := Rule{
		ID:          "KS015",
		Category:    CategoryMisconfig,
		Title:       "Dangerous Linux capabilities",
		Severity:    SeverityHigh,
		Remediation: "Drop dangerous Linux capabilities unless the workload has a specific reviewed requirement for them.",
	}
	dangerous := map[string]struct{}{
		"SYS_ADMIN":       {},
		"NET_ADMIN":       {},
		"SYS_PTRACE":      {},
		"SYS_MODULE":      {},
		"SYS_RAWIO":       {},
		"DAC_READ_SEARCH": {},
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				var matched []string
				for _, capability := range container.CapabilitiesAdd {
					if _, ok := dangerous[capability]; ok {
						matched = append(matched, capability)
					}
				}
				if len(matched) == 0 {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "adds dangerous Linux capabilities"), map[string]any{
					"container":    container.Name,
					"capabilities": matched,
				}))
			}
		}
		return findings
	}
	return rule
}

func allowPrivilegeEscalationRule() Rule {
	rule := Rule{
		ID:          "KS022",
		Category:    CategoryMisconfig,
		Title:       "Privilege escalation allowed",
		Severity:    SeverityHigh,
		Remediation: "Set securityContext.allowPrivilegeEscalation=false on each container unless a reviewed exception is required.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if container.AllowPrivilegeEscalation != nil && !*container.AllowPrivilegeEscalation {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "allows privilege escalation"), map[string]any{
					"container":                container.Name,
					"allowPrivilegeEscalation": container.AllowPrivilegeEscalation,
				}))
			}
		}
		return findings
	}
	return rule
}

func seccompProfileRule() Rule {
	rule := Rule{
		ID:          "KS023",
		Category:    CategoryMisconfig,
		Title:       "Missing or unconfined seccomp profile",
		Severity:    SeverityHigh,
		Remediation: "Set securityContext.seccompProfile.type to RuntimeDefault or Localhost on each container or at the pod security context level.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if container.SeccompProfileType != "" && container.SeccompProfileType != "Unconfined" {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "does not enforce a restricted seccomp profile"), map[string]any{
					"container":          container.Name,
					"seccompProfileType": container.SeccompProfileType,
				}))
			}
		}
		return findings
	}
	return rule
}

func privilegedContainerRule() Rule {
	rule := Rule{
		ID:          "KS001",
		Category:    CategoryMisconfig,
		Title:       "Privileged container",
		Severity:    SeverityCritical,
		Remediation: "Disable privileged mode unless the workload has a documented and reviewed requirement.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if container.Privileged != nil && *container.Privileged {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "runs in privileged mode"), map[string]any{
						"container":  container.Name,
						"privileged": true,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func privilegedHostPIDRule() Rule {
	rule := Rule{
		ID:          "KS033",
		Category:    CategoryMisconfig,
		Title:       "Privileged container with hostPID access",
		Severity:    SeverityCritical,
		Remediation: "Do not combine privileged containers with hostPID access unless the workload is an explicitly trusted node-level admin tool.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			if !workload.HostPID {
				continue
			}
			for _, container := range workload.Containers {
				if container.Privileged == nil || !*container.Privileged {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "combines privileged mode with hostPID access"), map[string]any{
					"container":  container.Name,
					"privileged": true,
					"hostPID":    true,
				}))
			}
		}
		return findings
	}
	return rule
}

func privilegedHostPathRule() Rule {
	rule := Rule{
		ID:          "KS034",
		Category:    CategoryExposure,
		Title:       "Privileged workload with hostPath access",
		Severity:    SeverityCritical,
		Remediation: "Avoid combining privileged containers with hostPath mounts unless the workload is a tightly controlled node administration component.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			if len(workload.HostPathVolumes) == 0 {
				continue
			}
			for _, container := range workload.Containers {
				if container.Privileged == nil || !*container.Privileged {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "combines privileged mode with hostPath mounts"), map[string]any{
					"container":  container.Name,
					"privileged": true,
					"hostPaths":  hostPathList(workload.HostPathVolumes),
				}))
			}
		}
		return findings
	}
	return rule
}

func sensitiveHostPathRule() Rule {
	rule := Rule{
		ID:          "KS035",
		Category:    CategoryExposure,
		Title:       "Sensitive hostPath mount",
		Severity:    SeverityCritical,
		Remediation: "Do not mount sensitive host filesystem paths such as root, kubelet, etcd, Kubernetes config, or runtime sockets into application workloads.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			var matched []map[string]any
			for _, volume := range workload.HostPathVolumes {
				classification, ok := classifySensitiveHostPath(volume.Path)
				if !ok {
					continue
				}
				matched = append(matched, map[string]any{
					"name":           volume.Name,
					"path":           volume.Path,
					"classification": classification,
				})
			}
			if len(matched) == 0 {
				continue
			}
			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" mounts sensitive hostPath locations", map[string]any{
				"hostPaths": matched,
			}))
		}
		return findings
	}
	return rule
}

func hostNamespaceRule() Rule {
	rule := Rule{
		ID:          "KS002",
		Category:    CategoryMisconfig,
		Title:       "Host namespace access",
		Severity:    SeverityHigh,
		Remediation: "Avoid host network, PID, or IPC access unless the workload is explicitly trusted and isolated.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			if !workload.HostNetwork && !workload.HostPID && !workload.HostIPC {
				continue
			}

			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" shares host namespaces", map[string]any{
				"hostNetwork": workload.HostNetwork,
				"hostPID":     workload.HostPID,
				"hostIPC":     workload.HostIPC,
			}))
		}
		return findings
	}
	return rule
}

func runAsNonRootRule() Rule {
	rule := Rule{
		ID:          "KS003",
		Category:    CategoryMisconfig,
		Title:       "Missing runAsNonRoot",
		Severity:    SeverityHigh,
		Remediation: "Set securityContext.runAsNonRoot=true on each container or at the pod security context level.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if container.RunAsNonRoot == nil || !*container.RunAsNonRoot {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "does not enforce runAsNonRoot"), map[string]any{
						"container":    container.Name,
						"runAsNonRoot": container.RunAsNonRoot,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func runAsRootRule() Rule {
	rule := Rule{
		ID:          "KS004",
		Category:    CategoryMisconfig,
		Title:       "Container runs as root",
		Severity:    SeverityHigh,
		Remediation: "Configure a non-zero runAsUser and ensure the image supports a non-root runtime user.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if container.RunAsUser != nil && *container.RunAsUser == 0 {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "runs as UID 0"), map[string]any{
						"container": container.Name,
						"runAsUser": 0,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func readOnlyRootFilesystemRule() Rule {
	rule := Rule{
		ID:          "KS005",
		Category:    CategoryMisconfig,
		Title:       "Writable root filesystem",
		Severity:    SeverityMedium,
		Remediation: "Set securityContext.readOnlyRootFilesystem=true unless the workload requires a writable root filesystem.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if container.ReadOnlyRootFilesystem == nil || !*container.ReadOnlyRootFilesystem {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "uses a writable root filesystem"), map[string]any{
						"container":              container.Name,
						"readOnlyRootFilesystem": container.ReadOnlyRootFilesystem,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func hostPathVolumeRule() Rule {
	rule := Rule{
		ID:          "KS024",
		Category:    CategoryExposure,
		Title:       "HostPath volume mounted",
		Severity:    SeverityHigh,
		Remediation: "Avoid hostPath volumes unless the workload has a narrowly reviewed node-level access requirement.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			if len(workload.HostPathVolumes) == 0 {
				continue
			}
			paths := make([]string, 0, len(workload.HostPathVolumes))
			for _, volume := range workload.HostPathVolumes {
				if volume.Path != "" {
					paths = append(paths, volume.Path)
				}
			}
			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" mounts hostPath volumes", map[string]any{
				"hostPaths": compactStrings(paths),
			}))
		}
		return findings
	}
	return rule
}

func hostPortRule() Rule {
	rule := Rule{
		ID:          "KS025",
		Category:    CategoryExposure,
		Title:       "Host port exposure",
		Severity:    SeverityMedium,
		Remediation: "Avoid hostPort bindings unless direct node-level port exposure is explicitly required and isolated.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if len(container.HostPorts) == 0 {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "binds host ports"), map[string]any{
					"container": container.Name,
					"hostPorts": append([]int32(nil), container.HostPorts...),
				}))
			}
		}
		return findings
	}
	return rule
}

func controlPlaneSchedulingRule() Rule {
	rule := Rule{
		ID:          "KS036",
		Category:    CategoryIdentity,
		Title:       "Control-plane scheduling indicator",
		Severity:    SeverityHigh,
		Remediation: "Do not target control-plane nodes directly from application workloads; restrict such scheduling to tightly controlled administrative components.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			nodeName := strings.ToLower(workload.NodeName)
			hasNodeTarget := strings.Contains(nodeName, "control-plane") || strings.Contains(nodeName, "master")
			hasToleration := hasControlPlaneToleration(workload.Tolerations)
			if !hasNodeTarget && !hasToleration {
				continue
			}
			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" includes control-plane scheduling indicators", map[string]any{
				"nodeName":                  workload.NodeName,
				"hasControlPlaneToleration": hasToleration,
				"tolerationKeys":            tolerationKeys(workload.Tolerations),
			}))
		}
		return findings
	}
	return rule
}

func schedulableControlPlaneNodeRule() Rule {
	rule := Rule{
		ID:          "KS037",
		Category:    CategoryMisconfig,
		Title:       "Control-plane node is schedulable",
		Severity:    SeverityHigh,
		Remediation: "Apply a NoSchedule control-plane taint or mark the node unschedulable so regular workloads do not land on control-plane nodes.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if !isControlPlaneNode(node) {
				continue
			}
			if node.Unschedulable || hasNoScheduleTaint(node.Taints) {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" is labeled as control-plane but still allows general scheduling", map[string]any{
				"labels":        node.Labels,
				"unschedulable": node.Unschedulable,
				"taints":        nodeTaintEvidence(node.Taints),
			}))
		}
		return findings
	}
	return rule
}

func legacyDockerRuntimeNodeRule() Rule {
	rule := Rule{
		ID:          "KS038",
		Category:    CategoryMisconfig,
		Title:       "Node uses legacy Docker runtime",
		Severity:    SeverityMedium,
		Remediation: "Migrate worker nodes to a supported CRI runtime such as containerd or CRI-O.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if !strings.HasPrefix(strings.ToLower(node.ContainerRuntime), "docker://") {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" reports the legacy Docker runtime", map[string]any{
				"containerRuntime": node.ContainerRuntime,
				"osImage":          node.OSImage,
				"kernelVersion":    node.KernelVersion,
			}))
		}
		return findings
	}
	return rule
}

func externalIPNodeRule() Rule {
	rule := Rule{
		ID:          "KS039",
		Category:    CategoryExposure,
		Title:       "Node advertises an external IP",
		Severity:    SeverityMedium,
		Remediation: "Restrict direct node exposure where possible and prefer controlled ingress or load balancer paths over publicly reachable nodes.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if len(node.ExternalIPs) == 0 {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" advertises external IP addresses", map[string]any{
				"externalIPs": node.ExternalIPs,
				"ready":       node.Ready,
			}))
		}
		return findings
	}
	return rule
}

func nodeNotReadyRule() Rule {
	rule := Rule{
		ID:          "KS040",
		Category:    CategoryResilience,
		Title:       "Node is not Ready",
		Severity:    SeverityHigh,
		Remediation: "Investigate the node health issue, restore readiness, or drain and replace the node if it cannot return to service safely.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.Ready {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" is not reporting Ready", map[string]any{
				"ready":            node.Ready,
				"containerRuntime": node.ContainerRuntime,
				"kubeletVersion":   node.KubeletVersion,
				"externalIPs":      node.ExternalIPs,
			}))
		}
		return findings
	}
	return rule
}

func kubeletVersionSkewRule() Rule {
	rule := Rule{
		ID:          "KS041",
		Category:    CategoryResilience,
		Title:       "Kubelet version skew detected",
		Severity:    SeverityMedium,
		Remediation: "Keep node kubelet versions aligned within the supported upgrade skew window and complete rolling upgrades promptly.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		versions := map[string][]string{}
		for _, node := range inventory.Nodes {
			if node.KubeletVersion == "" {
				continue
			}
			versions[node.KubeletVersion] = append(versions[node.KubeletVersion], node.Resource.Name)
		}
		if len(versions) <= 1 {
			return nil
		}
		return []Finding{makeFinding(rule, ResourceRef{Kind: "Cluster", Name: "cluster"}, "Cluster reports kubelet version skew across nodes", map[string]any{
			"component":    "kubelet",
			"versionCount": len(versions),
			"nodeCount":    countVersionMembers(versions),
			"versions":     versionNodeEvidence(versions),
		})}
	}
	return rule
}

func kubeProxyVersionSkewRule() Rule {
	rule := Rule{
		ID:          "KS042",
		Category:    CategoryResilience,
		Title:       "kube-proxy version skew detected",
		Severity:    SeverityMedium,
		Remediation: "Keep kube-proxy versions aligned across nodes and complete cluster upgrades promptly so network components stay within a supported skew window.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		versions := map[string][]string{}
		for _, node := range inventory.Nodes {
			if node.KubeProxyVersion == "" {
				continue
			}
			versions[node.KubeProxyVersion] = append(versions[node.KubeProxyVersion], node.Resource.Name)
		}
		if len(versions) <= 1 {
			return nil
		}
		return []Finding{makeFinding(rule, ResourceRef{Kind: "Cluster", Name: "cluster"}, "Cluster reports kube-proxy version skew across nodes", map[string]any{
			"component":    "kube-proxy",
			"versionCount": len(versions),
			"nodeCount":    countVersionMembers(versions),
			"versions":     versionNodeEvidence(versions),
		})}
	}
	return rule
}

func controlPlaneVersionSkewRule() Rule {
	rule := Rule{
		ID:          "KS043",
		Category:    CategoryResilience,
		Title:       "Visible control-plane component version skew detected",
		Severity:    SeverityHigh,
		Remediation: "Keep control-plane components aligned on a supported version during upgrades and finish staged upgrades promptly.",
	}
	controlPlaneNames := map[string]struct{}{
		"kube-apiserver":          {},
		"kube-controller-manager": {},
		"kube-scheduler":          {},
		"etcd":                    {},
	}
	rule.Check = func(inventory Inventory) []Finding {
		componentVersions := map[string]map[string][]ResourceRef{}
		for _, component := range inventory.Components {
			if _, ok := controlPlaneNames[component.Name]; !ok || component.Version == "" {
				continue
			}
			versions := componentVersions[component.Name]
			if versions == nil {
				versions = map[string][]ResourceRef{}
				componentVersions[component.Name] = versions
			}
			versions[component.Version] = append(versions[component.Version], component.Resource)
		}

		var findings []Finding
		for _, componentName := range sortedStringKeys(componentVersions) {
			versions := componentVersions[componentName]
			if len(versions) <= 1 {
				continue
			}
			findings = append(findings, makeFinding(rule, ResourceRef{Kind: "Cluster", Name: "cluster"}, "Cluster reports "+componentName+" version skew across visible control-plane components", map[string]any{
				"component":      componentName,
				"versionCount":   len(versions),
				"instanceCount":  countVersionResourceMembers(versions),
				"visibleSources": versionResourceEvidence(versions),
			}))
		}
		return findings
	}
	return rule
}

func nodePressureRule() Rule {
	rule := Rule{
		ID:          "KS044",
		Category:    CategoryResilience,
		Title:       "Node reports resource pressure",
		Severity:    SeverityHigh,
		Remediation: "Investigate and relieve node pressure conditions such as memory, disk, or PID exhaustion before they cause workload instability or evictions.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			pressures := activeNodePressures(node)
			if len(pressures) == 0 {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" reports active pressure conditions", map[string]any{
				"pressures":        pressures,
				"ready":            node.Ready,
				"kubeletVersion":   node.KubeletVersion,
				"containerRuntime": node.ContainerRuntime,
			}))
		}
		return findings
	}
	return rule
}

func nodeNetworkUnavailableRule() Rule {
	rule := Rule{
		ID:          "KS045",
		Category:    CategoryResilience,
		Title:       "Node network is unavailable",
		Severity:    SeverityHigh,
		Remediation: "Investigate node networking, CNI state, and route programming so the node can participate safely in cluster networking.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if !node.NetworkUnavailable {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" reports network unavailable", map[string]any{
				"networkUnavailable": node.NetworkUnavailable,
				"ready":              node.Ready,
				"externalIPs":        node.ExternalIPs,
				"kubeletVersion":     node.KubeletVersion,
			}))
		}
		return findings
	}
	return rule
}

func kubeletAnonymousAuthRule() Rule {
	rule := Rule{
		ID:          "KS046",
		Category:    CategoryMisconfig,
		Title:       "Kubelet anonymous authentication enabled",
		Severity:    SeverityCritical,
		Remediation: "Set kubelet authentication.anonymous.enabled=false and redeploy node configuration through the node bootstrap or configuration management path.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletAnonymousAuthEnabled == nil || !*node.KubeletAnonymousAuthEnabled {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" enables kubelet anonymous authentication", map[string]any{
				"kubeletConfigPath":    node.KubeletConfigPath,
				"anonymousAuthEnabled": true,
			}))
		}
		return findings
	}
	return rule
}

func kubeletWebhookAuthenticationRule() Rule {
	rule := Rule{
		ID:          "KS047",
		Category:    CategoryMisconfig,
		Title:       "Kubelet webhook authentication disabled",
		Severity:    SeverityHigh,
		Remediation: "Enable kubelet authentication.webhook so bearer tokens are validated through the API server instead of relying on weaker local-only behavior.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletWebhookAuthenticationEnabled == nil || *node.KubeletWebhookAuthenticationEnabled {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" disables kubelet webhook authentication", map[string]any{
				"kubeletConfigPath":            node.KubeletConfigPath,
				"webhookAuthenticationEnabled": false,
			}))
		}
		return findings
	}
	return rule
}

func kubeletAuthorizationModeRule() Rule {
	rule := Rule{
		ID:          "KS048",
		Category:    CategoryMisconfig,
		Title:       "Kubelet authorization mode is not webhook",
		Severity:    SeverityHigh,
		Remediation: "Set kubelet authorization.mode=Webhook so kubelet requests are subject to Kubernetes RBAC rather than permissive local-only authorization modes.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if strings.EqualFold(strings.TrimSpace(node.KubeletAuthorizationMode), "webhook") || strings.TrimSpace(node.KubeletAuthorizationMode) == "" {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" uses a non-webhook kubelet authorization mode", map[string]any{
				"kubeletConfigPath": node.KubeletConfigPath,
				"authorizationMode": node.KubeletAuthorizationMode,
			}))
		}
		return findings
	}
	return rule
}

func kubeletReadOnlyPortRule() Rule {
	rule := Rule{
		ID:          "KS049",
		Category:    CategoryExposure,
		Title:       "Kubelet read-only port enabled",
		Severity:    SeverityHigh,
		Remediation: "Set kubelet readOnlyPort=0 to disable the unauthenticated read-only listener.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletReadOnlyPort == nil || *node.KubeletReadOnlyPort == 0 {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" exposes the kubelet read-only port", map[string]any{
				"kubeletConfigPath": node.KubeletConfigPath,
				"readOnlyPort":      *node.KubeletReadOnlyPort,
			}))
		}
		return findings
	}
	return rule
}

func kubeletProtectKernelDefaultsRule() Rule {
	rule := Rule{
		ID:          "KS050",
		Category:    CategoryMisconfig,
		Title:       "Kubelet protectKernelDefaults disabled",
		Severity:    SeverityMedium,
		Remediation: "Set kubelet protectKernelDefaults=true so the node fails closed instead of silently overriding hardened kernel sysctls.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletProtectKernelDefaults == nil || *node.KubeletProtectKernelDefaults {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" does not protect hardened kernel defaults", map[string]any{
				"kubeletConfigPath":     node.KubeletConfigPath,
				"protectKernelDefaults": false,
			}))
		}
		return findings
	}
	return rule
}

func kubeletRotateCertificatesRule() Rule {
	rule := Rule{
		ID:          "KS051",
		Category:    CategoryMisconfig,
		Title:       "Kubelet client certificate rotation disabled",
		Severity:    SeverityMedium,
		Remediation: "Set kubelet rotateCertificates=true so node client certificates are rotated automatically.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletRotateCertificates == nil || *node.KubeletRotateCertificates {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" does not rotate kubelet client certificates", map[string]any{
				"kubeletConfigPath":  node.KubeletConfigPath,
				"rotateCertificates": false,
			}))
		}
		return findings
	}
	return rule
}

func kubeletServerTLSBootstrapRule() Rule {
	rule := Rule{
		ID:          "KS052",
		Category:    CategoryExposure,
		Title:       "Kubelet server TLS bootstrap disabled",
		Severity:    SeverityMedium,
		Remediation: "Set kubelet serverTLSBootstrap=true so serving certificates are issued through the cluster trust path instead of long-lived local material.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletServerTLSBootstrap == nil || *node.KubeletServerTLSBootstrap {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" does not use kubelet server TLS bootstrap", map[string]any{
				"kubeletConfigPath":  node.KubeletConfigPath,
				"serverTLSBootstrap": false,
			}))
		}
		return findings
	}
	return rule
}

func kubeletSeccompDefaultRule() Rule {
	rule := Rule{
		ID:          "KS053",
		Category:    CategoryMisconfig,
		Title:       "Kubelet seccompDefault disabled",
		Severity:    SeverityHigh,
		Remediation: "Set kubelet seccompDefault=true so pods inherit RuntimeDefault seccomp unless they opt into a stricter profile.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletSeccompDefault == nil || *node.KubeletSeccompDefault {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" does not enable kubelet seccompDefault", map[string]any{
				"kubeletConfigPath": node.KubeletConfigPath,
				"seccompDefault":    false,
			}))
		}
		return findings
	}
	return rule
}

func kubeletClientCAFileRule() Rule {
	rule := Rule{
		ID:          "KS054",
		Severity:    SeverityHigh,
		Category:    CategoryMisconfig,
		Title:       "Kubelet client CA file missing",
		Remediation: "Set kubelet authentication.x509.clientCAFile to the trusted cluster client CA bundle so kubelet client certificate authentication validates against an explicit root of trust.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if strings.TrimSpace(node.KubeletAuthenticationX509ClientCAFile) != "" {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" does not configure kubelet authentication.x509.clientCAFile", map[string]any{
				"kubeletConfigPath": node.KubeletConfigPath,
			}))
		}
		return findings
	}
	return rule
}

func kubeletFailSwapOnRule() Rule {
	rule := Rule{
		ID:          "KS055",
		Severity:    SeverityMedium,
		Category:    CategoryResilience,
		Title:       "Kubelet failSwapOn disabled",
		Remediation: "Set kubelet failSwapOn=true unless you have explicitly designed and validated a swap-enabled node posture for the cluster.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, node := range inventory.Nodes {
			if node.KubeletFailSwapOn == nil || *node.KubeletFailSwapOn {
				continue
			}
			findings = append(findings, makeFinding(rule, node.Resource, "Node/"+node.Resource.Name+" disables kubelet failSwapOn", map[string]any{
				"kubeletConfigPath": node.KubeletConfigPath,
				"failSwapOn":        *node.KubeletFailSwapOn,
			}))
		}
		return findings
	}
	return rule
}

func resourceRequestsRule() Rule {
	rule := Rule{
		ID:          "KS006",
		Category:    CategoryMisconfig,
		Title:       "Missing resource requests",
		Severity:    SeverityMedium,
		Remediation: "Define CPU and memory requests for each container.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if !container.HasResourceRequests {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "is missing CPU or memory requests"), map[string]any{
						"container": container.Name,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func resourceLimitsRule() Rule {
	rule := Rule{
		ID:          "KS007",
		Category:    CategoryMisconfig,
		Title:       "Missing resource limits",
		Severity:    SeverityMedium,
		Remediation: "Define CPU and memory limits for each container.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if !container.HasResourceLimits {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "is missing CPU or memory limits"), map[string]any{
						"container": container.Name,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func livenessProbeRule() Rule {
	rule := Rule{
		ID:          "KS008",
		Category:    CategoryResilience,
		Title:       "Missing liveness probe",
		Severity:    SeverityMedium,
		Remediation: "Add a liveness probe so kubelet can restart unhealthy containers.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if !container.HasLivenessProbe {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "is missing a liveness probe"), map[string]any{
						"container": container.Name,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func readinessProbeRule() Rule {
	rule := Rule{
		ID:          "KS009",
		Category:    CategoryResilience,
		Title:       "Missing readiness probe",
		Severity:    SeverityMedium,
		Remediation: "Add a readiness probe so traffic is only sent to healthy containers.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if !container.HasReadinessProbe {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "is missing a readiness probe"), map[string]any{
						"container": container.Name,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func mutableTagRule() Rule {
	rule := Rule{
		ID:          "KS010",
		Category:    CategorySupplyChain,
		Title:       "Mutable image tag",
		Severity:    SeverityHigh,
		Remediation: "Pin images by digest or immutable version tags instead of relying on latest or floating tags.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if usesMutableTag(container.Image) {
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "uses a mutable image tag"), map[string]any{
						"container": container.Name,
						"image":     container.Image,
					}))
				}
			}
		}
		return findings
	}
	return rule
}

func serviceExposureRule() Rule {
	rule := Rule{
		ID:          "KS011",
		Category:    CategoryExposure,
		Title:       "Public service exposure",
		Severity:    SeverityHigh,
		Remediation: "Avoid NodePort and LoadBalancer services for internal workloads unless the exposure is explicitly required and protected.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, service := range inventory.Services {
			if service.Type != "LoadBalancer" && service.Type != "NodePort" {
				continue
			}
			findings = append(findings, makeFinding(rule, service.Resource, service.Resource.Kind+"/"+service.Resource.Name+" is publicly exposed through "+service.Type, map[string]any{
				"type": service.Type,
			}))
		}
		return findings
	}
	return rule
}

func serviceAccountTokenRule() Rule {
	rule := Rule{
		ID:          "KS012",
		Category:    CategoryIdentity,
		Title:       "Service account token auto-mounting",
		Severity:    SeverityMedium,
		Remediation: "Disable automountServiceAccountToken unless the workload needs Kubernetes API access.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			if workload.AutomountServiceAccountToken != nil && !*workload.AutomountServiceAccountToken {
				continue
			}
			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" may auto-mount a service account token", map[string]any{
				"serviceAccountName":           workload.ServiceAccountName,
				"automountServiceAccountToken": workload.AutomountServiceAccountToken,
			}))
		}
		return findings
	}
	return rule
}

func wildcardRBACRule() Rule {
	rule := Rule{
		ID:          "KS013",
		Category:    CategoryIdentity,
		Title:       "Wildcard RBAC permissions",
		Severity:    SeverityCritical,
		Remediation: "Replace wildcard verbs, resources, or non-resource URLs with the minimum required permissions.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, role := range inventory.Roles {
			for _, policyRule := range role.Rules {
				if containsWildcard(policyRule.Verbs) || containsWildcard(policyRule.Resources) || containsWildcard(policyRule.NonResourceURLs) {
					findings = append(findings, makeFinding(rule, role.Resource, role.Resource.Kind+"/"+role.Resource.Name+" grants wildcard permissions", map[string]any{
						"verbs":           policyRule.Verbs,
						"resources":       policyRule.Resources,
						"nonResourceURLs": policyRule.NonResourceURLs,
					}))
					break
				}
			}
		}
		return findings
	}
	return rule
}

func wildcardRBACSubjectRule() Rule {
	rule := Rule{
		ID:          "KS016",
		Category:    CategoryIdentity,
		Title:       "Subject reaches wildcard RBAC permissions",
		Severity:    SeverityCritical,
		Remediation: "Remove wildcard permissions from the bound role or narrow the binding subjects to the minimum required identities.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		resolutions := wildcardBindingResolutions(inventory)
		var findings []Finding
		for _, resolution := range resolutions {
			for _, subject := range resolution.Binding.Subjects {
				findings = append(findings, makeFinding(rule, subjectResource(subject, resolution.Binding.Resource.Namespace), subjectMessage(subject, resolution.Binding, resolution.Role), map[string]any{
					"binding": map[string]any{
						"kind":      resolution.Binding.Resource.Kind,
						"name":      resolution.Binding.Resource.Name,
						"namespace": resolution.Binding.Resource.Namespace,
					},
					"roleRef": map[string]any{
						"kind":      resolution.Role.Resource.Kind,
						"name":      resolution.Role.Resource.Name,
						"namespace": resolution.Role.Resource.Namespace,
					},
					"subject": map[string]any{
						"kind":      subject.Kind,
						"name":      subject.Name,
						"namespace": effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace),
					},
				}))
			}
		}
		return findings
	}
	return rule
}

func clusterAdminSubjectRule() Rule {
	rule := Rule{
		ID:          "KS026",
		Category:    CategoryIdentity,
		Title:       "Subject reaches cluster-admin",
		Severity:    SeverityCritical,
		Remediation: "Remove cluster-admin bindings from end-user and workload identities unless the access is explicitly required and tightly controlled.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		resolutions := clusterAdminBindingResolutions(inventory)
		var findings []Finding
		for _, resolution := range resolutions {
			for _, subject := range resolution.Binding.Subjects {
				findings = append(findings, makeFinding(rule, subjectResource(subject, resolution.Binding.Resource.Namespace), subject.Kind+"/"+subject.Name+" reaches cluster-admin through "+resolution.Binding.Resource.Kind+"/"+resolution.Binding.Resource.Name, map[string]any{
					"binding": map[string]any{
						"kind":      resolution.Binding.Resource.Kind,
						"name":      resolution.Binding.Resource.Name,
						"namespace": resolution.Binding.Resource.Namespace,
					},
					"subject": map[string]any{
						"kind":      subject.Kind,
						"name":      subject.Name,
						"namespace": effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace),
					},
				}))
			}
		}
		return findings
	}
	return rule
}

func privilegedServiceAccountWorkloadRule() Rule {
	rule := Rule{
		ID:          "KS017",
		Category:    CategoryIdentity,
		Title:       "Workload uses an over-privileged service account",
		Severity:    SeverityCritical,
		Remediation: "Bind the workload service account only to narrowly scoped roles, or move the workload to a less privileged service account.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		subjectBindings := wildcardBindingsByServiceAccount(inventory)
		var findings []Finding
		for _, workload := range inventory.Workloads {
			serviceAccountName := workload.ServiceAccountName
			if serviceAccountName == "" {
				serviceAccountName = "default"
			}
			key := workload.Resource.Namespace + "/" + serviceAccountName
			resolutions := subjectBindings[key]
			if len(resolutions) == 0 {
				continue
			}

			bindingRefs := make([]map[string]any, 0, len(resolutions))
			roleRefs := make([]map[string]any, 0, len(resolutions))
			for _, resolution := range resolutions {
				bindingRefs = append(bindingRefs, map[string]any{
					"kind":      resolution.Binding.Resource.Kind,
					"name":      resolution.Binding.Resource.Name,
					"namespace": resolution.Binding.Resource.Namespace,
				})
				roleRefs = append(roleRefs, map[string]any{
					"kind":      resolution.Role.Resource.Kind,
					"name":      resolution.Role.Resource.Name,
					"namespace": resolution.Role.Resource.Namespace,
				})
			}

			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" uses service account "+serviceAccountName+" with wildcard RBAC permissions", map[string]any{
				"serviceAccountName": serviceAccountName,
				"bindings":           bindingRefs,
				"roles":              roleRefs,
			}))
		}
		return findings
	}
	return rule
}

func defaultServiceAccountWorkloadRule() Rule {
	rule := Rule{
		ID:          "KS027",
		Category:    CategoryIdentity,
		Title:       "Workload uses the default service account",
		Severity:    SeverityMedium,
		Remediation: "Create a dedicated least-privilege service account for the workload and disable token automounting unless Kubernetes API access is required.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		wildcardBindings := wildcardBindingsByServiceAccount(inventory)
		secretBindings := bindingResolutionsByServiceAccount(inventory, roleHasSecretReadPermissions)
		clusterAdminBindings := clusterAdminBindingsByServiceAccount(inventory)

		var findings []Finding
		for _, workload := range inventory.Workloads {
			serviceAccountName := workload.ServiceAccountName
			if serviceAccountName == "" {
				serviceAccountName = "default"
			}
			if serviceAccountName != "default" || isSystemNamespace(workload.Resource.Namespace) {
				continue
			}

			key := workload.Resource.Namespace + "/" + serviceAccountName
			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" uses the namespace default service account", map[string]any{
				"serviceAccountName":           serviceAccountName,
				"automountServiceAccountToken": workload.AutomountServiceAccountToken,
				"hasWildcardPermissions":       len(wildcardBindings[key]) > 0,
				"hasSecretReadPermissions":     len(secretBindings[key]) > 0,
				"hasClusterAdminBinding":       len(clusterAdminBindings[key]) > 0,
			}))
		}
		return findings
	}
	return rule
}

func secretEnvExposureRule() Rule {
	rule := Rule{
		ID:          "KS018",
		Category:    CategoryExposure,
		Title:       "Secret exposed through environment variables",
		Severity:    SeverityHigh,
		Remediation: "Prefer short-lived mounted credentials or external secret delivery mechanisms over environment variable injection where possible.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				if len(container.SecretEnvRefs) == 0 && len(container.SecretEnvFromRefs) == 0 {
					continue
				}

				secrets := make([]string, 0, len(container.SecretEnvRefs)+len(container.SecretEnvFromRefs))
				for _, ref := range container.SecretEnvRefs {
					secrets = append(secrets, ref.Name)
				}
				secrets = append(secrets, container.SecretEnvFromRefs...)
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "references Secret data through environment variables"), map[string]any{
					"container": container.Name,
					"secrets":   compactStrings(secrets),
				}))
			}
		}
		return findings
	}
	return rule
}

func secretVolumeExposureRule() Rule {
	rule := Rule{
		ID:          "KS019",
		Category:    CategoryExposure,
		Title:       "Secret mounted into workload",
		Severity:    SeverityMedium,
		Remediation: "Mount only the minimum required Secret material and prefer scoped credentials with short lifetimes.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			if len(workload.SecretVolumes) == 0 {
				continue
			}
			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" mounts Secret-backed volumes", map[string]any{
				"secrets": compactStrings(workload.SecretVolumes),
			}))
		}
		return findings
	}
	return rule
}

func secretReadSubjectRule() Rule {
	rule := Rule{
		ID:          "KS020",
		Category:    CategoryIdentity,
		Title:       "Subject reaches secret-read RBAC permissions",
		Severity:    SeverityHigh,
		Remediation: "Limit secret read permissions to the smallest subject set and scope the role to the minimum required namespace and verbs.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		resolutions := roleBindingResolutions(inventory, roleHasSecretReadPermissions)
		var findings []Finding
		for _, resolution := range resolutions {
			for _, subject := range resolution.Binding.Subjects {
				findings = append(findings, makeFinding(rule, subjectResource(subject, resolution.Binding.Resource.Namespace), subject.Kind+"/"+subject.Name+" reaches secret read permissions through "+resolution.Binding.Resource.Kind+"/"+resolution.Binding.Resource.Name+" -> "+resolution.Role.Resource.Kind+"/"+resolution.Role.Resource.Name, map[string]any{
					"binding": map[string]any{
						"kind":      resolution.Binding.Resource.Kind,
						"name":      resolution.Binding.Resource.Name,
						"namespace": resolution.Binding.Resource.Namespace,
					},
					"roleRef": map[string]any{
						"kind":      resolution.Role.Resource.Kind,
						"name":      resolution.Role.Resource.Name,
						"namespace": resolution.Role.Resource.Namespace,
					},
					"subject": map[string]any{
						"kind":      subject.Kind,
						"name":      subject.Name,
						"namespace": effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace),
					},
				}))
			}
		}
		return findings
	}
	return rule
}

func secretReadServiceAccountWorkloadRule() Rule {
	rule := Rule{
		ID:          "KS021",
		Category:    CategoryIdentity,
		Title:       "Workload uses a service account with secret-read permissions",
		Severity:    SeverityHigh,
		Remediation: "Use a more narrowly scoped service account or remove secret read permissions from the bound roles.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		subjectBindings := bindingResolutionsByServiceAccount(inventory, roleHasSecretReadPermissions)
		var findings []Finding
		for _, workload := range inventory.Workloads {
			serviceAccountName := workload.ServiceAccountName
			if serviceAccountName == "" {
				serviceAccountName = "default"
			}
			key := workload.Resource.Namespace + "/" + serviceAccountName
			resolutions := subjectBindings[key]
			if len(resolutions) == 0 {
				continue
			}

			findings = append(findings, makeFinding(rule, workload.Resource, workload.Resource.Kind+"/"+workload.Resource.Name+" uses service account "+serviceAccountName+" with secret read permissions", map[string]any{
				"serviceAccountName": serviceAccountName,
				"bindings":           bindingEvidence(resolutions),
				"roles":              roleEvidence(resolutions),
			}))
		}
		return findings
	}
	return rule
}

func networkPolicyCoverageRule() Rule {
	rule := Rule{
		ID:          "KS014",
		Category:    CategoryExposure,
		Title:       "Missing namespace network policy",
		Severity:    SeverityMedium,
		Remediation: "Define baseline NetworkPolicies in namespaces that contain workloads.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		protectedNamespaces := map[string]struct{}{}
		for _, networkPolicy := range inventory.NetworkPolicies {
			protectedNamespaces[networkPolicy.Resource.Namespace] = struct{}{}
		}

		seenNamespaces := map[string]struct{}{}
		var findings []Finding
		for _, workload := range inventory.Workloads {
			namespace := workload.Resource.Namespace
			if namespace == "" || namespace == "kube-system" {
				continue
			}
			if _, seen := seenNamespaces[namespace]; seen {
				continue
			}
			seenNamespaces[namespace] = struct{}{}
			if _, protected := protectedNamespaces[namespace]; protected {
				continue
			}

			findings = append(findings, makeFinding(rule, ResourceRef{
				Kind:      "Namespace",
				Namespace: namespace,
				Name:      namespace,
			}, "Namespace/"+namespace+" contains workloads without any NetworkPolicy", map[string]any{
				"namespace": namespace,
			}))
		}
		return findings
	}
	return rule
}

func ingressPolicyCoverageRule() Rule {
	rule := Rule{
		ID:          "KS030",
		Category:    CategoryExposure,
		Title:       "Missing namespace ingress isolation",
		Severity:    SeverityMedium,
		Remediation: "Define ingress-isolating NetworkPolicies in namespaces that contain workloads.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		protectedNamespaces := map[string]struct{}{}
		for _, networkPolicy := range inventory.NetworkPolicies {
			if networkPolicy.HasIngress {
				protectedNamespaces[networkPolicy.Resource.Namespace] = struct{}{}
			}
		}
		return namespaceCoverageFindings(rule, inventory, protectedNamespaces, "without any ingress-isolating NetworkPolicy")
	}
	return rule
}

func egressPolicyCoverageRule() Rule {
	rule := Rule{
		ID:          "KS031",
		Category:    CategoryExposure,
		Title:       "Missing namespace egress isolation",
		Severity:    SeverityMedium,
		Remediation: "Define egress-isolating NetworkPolicies in namespaces that contain workloads.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		protectedNamespaces := map[string]struct{}{}
		for _, networkPolicy := range inventory.NetworkPolicies {
			if networkPolicy.HasEgress {
				protectedNamespaces[networkPolicy.Resource.Namespace] = struct{}{}
			}
		}
		return namespaceCoverageFindings(rule, inventory, protectedNamespaces, "without any egress-isolating NetworkPolicy")
	}
	return rule
}

func podSecurityAdmissionLabelsRule() Rule {
	rule := Rule{
		ID:          "KS028",
		Category:    CategoryMisconfig,
		Title:       "Missing or weak Pod Security Admission labels",
		Severity:    SeverityMedium,
		Remediation: "Set namespace Pod Security Admission enforce, audit, and warn labels to restricted unless a documented exception is required.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, namespace := range inventory.Namespaces {
			enforce := namespace.Labels["pod-security.kubernetes.io/enforce"]
			audit := namespace.Labels["pod-security.kubernetes.io/audit"]
			warn := namespace.Labels["pod-security.kubernetes.io/warn"]
			if enforce == "restricted" && audit == "restricted" && warn == "restricted" {
				continue
			}
			findings = append(findings, makeFinding(rule, namespace.Resource, "Namespace/"+namespace.Resource.Name+" is missing restricted Pod Security Admission labels", map[string]any{
				"enforce": enforce,
				"audit":   audit,
				"warn":    warn,
			}))
		}
		return findings
	}
	return rule
}

func plaintextCredentialRule() Rule {
	rule := Rule{
		ID:          "KS029",
		Category:    CategoryExposure,
		Title:       "Sensitive value detected in manifest data",
		Severity:    SeverityHigh,
		Remediation: "Remove secrets from manifests and ConfigMaps; use Secrets or an external secret delivery mechanism instead.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				for _, env := range container.EnvVars {
					if env.ValueFrom != "" {
						continue
					}
					match := secretscan.DetectNamedValue(env.Name, env.Value)
					if match == nil {
						continue
					}
					findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, manifestSecretMessage("environment variable "+env.Name, *match)), map[string]any{
						"container":   container.Name,
						"envVar":      env.Name,
						"detector":    match.Detector,
						"description": match.Description,
						"confidence":  string(match.Confidence),
					}))
				}
			}
		}
		for _, configMap := range inventory.ConfigMaps {
			for key, value := range configMap.Data {
				match := secretscan.DetectNamedValue(key, value)
				if match == nil {
					continue
				}
				findings = append(findings, makeFinding(rule, configMap.Resource, configMap.Resource.Kind+"/"+configMap.Resource.Name+" stores "+manifestSecretMessage("key "+key, *match), map[string]any{
					"key":         key,
					"detector":    match.Detector,
					"description": match.Description,
					"confidence":  string(match.Confidence),
				}))
			}
		}
		return findings
	}
	return rule
}

func publicRegistryImageRule() Rule {
	rule := Rule{
		ID:          "KS032",
		Category:    CategorySupplyChain,
		Title:       "Image sourced from a public or implicit registry",
		Severity:    SeverityMedium,
		Remediation: "Pull images from approved private registries or document an explicit exception for public registry usage.",
	}
	rule.Check = func(inventory Inventory) []Finding {
		var findings []Finding
		for _, workload := range inventory.Workloads {
			for _, container := range workload.Containers {
				registry, implicit := imageRegistry(container.Image)
				if !implicit && !isPublicRegistry(registry) {
					continue
				}
				findings = append(findings, makeFinding(rule, workload.Resource, containerMessage(workload, container, "pulls from a public or implicit registry"), map[string]any{
					"container":        container.Name,
					"image":            container.Image,
					"registry":         registry,
					"implicitRegistry": implicit,
				}))
			}
		}
		return findings
	}
	return rule
}

func usesMutableTag(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon <= lastSlash {
		return true
	}
	tag := image[lastColon+1:]
	return tag == "" || tag == "latest"
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

type wildcardBindingResolution struct {
	Binding Binding
	Role    Role
}

func wildcardBindingResolutions(inventory Inventory) []wildcardBindingResolution {
	return roleBindingResolutions(inventory, roleHasWildcardPermissions)
}

type clusterAdminBindingResolution struct {
	Binding Binding
}

func clusterAdminBindingResolutions(inventory Inventory) []clusterAdminBindingResolution {
	var resolutions []clusterAdminBindingResolution
	for _, binding := range inventory.Bindings {
		if binding.RoleRefKind != "ClusterRole" || binding.RoleRefName != "cluster-admin" {
			continue
		}
		resolutions = append(resolutions, clusterAdminBindingResolution{Binding: binding})
	}
	return resolutions
}

func clusterAdminBindingsByServiceAccount(inventory Inventory) map[string][]clusterAdminBindingResolution {
	resolutionsByServiceAccount := map[string][]clusterAdminBindingResolution{}
	for _, resolution := range clusterAdminBindingResolutions(inventory) {
		for _, subject := range resolution.Binding.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}
			key := effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace) + "/" + subject.Name
			resolutionsByServiceAccount[key] = append(resolutionsByServiceAccount[key], resolution)
		}
	}
	return resolutionsByServiceAccount
}

func wildcardBindingsByServiceAccount(inventory Inventory) map[string][]wildcardBindingResolution {
	return bindingResolutionsByServiceAccount(inventory, roleHasWildcardPermissions)
}

func roleHasWildcardPermissions(role Role) bool {
	for _, policyRule := range role.Rules {
		if containsWildcard(policyRule.Verbs) || containsWildcard(policyRule.Resources) || containsWildcard(policyRule.NonResourceURLs) {
			return true
		}
	}
	return false
}

func roleHasSecretReadPermissions(role Role) bool {
	for _, policyRule := range role.Rules {
		if containsWildcard(policyRule.Verbs) || containsWildcard(policyRule.Resources) {
			return true
		}
		if !containsValueString(policyRule.Resources, "secrets") {
			continue
		}
		if containsValueString(policyRule.Verbs, "get") || containsValueString(policyRule.Verbs, "list") || containsValueString(policyRule.Verbs, "watch") {
			return true
		}
	}
	return false
}

func roleBindingResolutions(inventory Inventory, roleMatch func(Role) bool) []wildcardBindingResolution {
	rolesByRef := map[string]Role{}
	for _, role := range inventory.Roles {
		rolesByRef[roleKey(role.Resource.Kind, role.Resource.Namespace, role.Resource.Name)] = role
	}

	var resolutions []wildcardBindingResolution
	for _, binding := range inventory.Bindings {
		roleNamespace := ""
		if binding.RoleRefKind == "Role" {
			roleNamespace = binding.Resource.Namespace
		}
		role, ok := rolesByRef[roleKey(binding.RoleRefKind, roleNamespace, binding.RoleRefName)]
		if !ok || !roleMatch(role) {
			continue
		}
		resolutions = append(resolutions, wildcardBindingResolution{
			Binding: binding,
			Role:    role,
		})
	}
	return resolutions
}

func bindingResolutionsByServiceAccount(inventory Inventory, roleMatch func(Role) bool) map[string][]wildcardBindingResolution {
	resolutionsByServiceAccount := map[string][]wildcardBindingResolution{}
	for _, resolution := range roleBindingResolutions(inventory, roleMatch) {
		for _, subject := range resolution.Binding.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}
			key := effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace) + "/" + subject.Name
			resolutionsByServiceAccount[key] = append(resolutionsByServiceAccount[key], resolution)
		}
	}
	return resolutionsByServiceAccount
}

func roleKey(kind, namespace, name string) string {
	return kind + "|" + namespace + "|" + name
}

func subjectResource(subject Subject, bindingNamespace string) ResourceRef {
	return ResourceRef{
		Kind:      subject.Kind,
		Namespace: effectiveSubjectNamespace(subject, bindingNamespace),
		Name:      subject.Name,
	}
}

func effectiveSubjectNamespace(subject Subject, bindingNamespace string) string {
	if subject.Namespace != "" {
		return subject.Namespace
	}
	if subject.Kind == "ServiceAccount" {
		return bindingNamespace
	}
	return ""
}

func subjectMessage(subject Subject, binding Binding, role Role) string {
	return subject.Kind + "/" + subject.Name + " reaches wildcard permissions through " + binding.Resource.Kind + "/" + binding.Resource.Name + " -> " + role.Resource.Kind + "/" + role.Resource.Name
}

func bindingEvidence(resolutions []wildcardBindingResolution) []map[string]any {
	refs := make([]map[string]any, 0, len(resolutions))
	for _, resolution := range resolutions {
		refs = append(refs, map[string]any{
			"kind":      resolution.Binding.Resource.Kind,
			"name":      resolution.Binding.Resource.Name,
			"namespace": resolution.Binding.Resource.Namespace,
		})
	}
	return refs
}

func roleEvidence(resolutions []wildcardBindingResolution) []map[string]any {
	refs := make([]map[string]any, 0, len(resolutions))
	for _, resolution := range resolutions {
		refs = append(refs, map[string]any{
			"kind":      resolution.Role.Resource.Kind,
			"name":      resolution.Role.Resource.Name,
			"namespace": resolution.Role.Resource.Namespace,
		})
	}
	return refs
}

func compactStrings(values []string) []string {
	seen := map[string]struct{}{}
	var compacted []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		compacted = append(compacted, value)
	}
	return compacted
}

func countVersionMembers(values map[string][]string) int {
	total := 0
	for _, members := range values {
		total += len(members)
	}
	return total
}

func countVersionResourceMembers(values map[string][]ResourceRef) int {
	total := 0
	for _, members := range values {
		total += len(members)
	}
	return total
}

func versionNodeEvidence(values map[string][]string) []map[string]any {
	var evidence []map[string]any
	for _, version := range sortedStringKeys(values) {
		nodes := append([]string(nil), values[version]...)
		sort.Strings(nodes)
		evidence = append(evidence, map[string]any{
			"version": version,
			"nodes":   nodes,
			"count":   len(nodes),
		})
	}
	return evidence
}

func versionResourceEvidence(values map[string][]ResourceRef) []map[string]any {
	var evidence []map[string]any
	for _, version := range sortedStringKeys(values) {
		resources := append([]ResourceRef(nil), values[version]...)
		sort.Slice(resources, func(i, j int) bool {
			if resources[i].Kind != resources[j].Kind {
				return resources[i].Kind < resources[j].Kind
			}
			if resources[i].Namespace != resources[j].Namespace {
				return resources[i].Namespace < resources[j].Namespace
			}
			return resources[i].Name < resources[j].Name
		})
		instances := make([]map[string]any, 0, len(resources))
		for _, resource := range resources {
			instances = append(instances, map[string]any{
				"kind":      resource.Kind,
				"namespace": resource.Namespace,
				"name":      resource.Name,
			})
		}
		evidence = append(evidence, map[string]any{
			"version":   version,
			"instances": instances,
			"count":     len(resources),
		})
	}
	return evidence
}

func sortedStringKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func namespaceCoverageFindings(rule Rule, inventory Inventory, protectedNamespaces map[string]struct{}, messageSuffix string) []Finding {
	seenNamespaces := map[string]struct{}{}
	var findings []Finding
	for _, workload := range inventory.Workloads {
		namespace := workload.Resource.Namespace
		if namespace == "" || isSystemNamespace(namespace) {
			continue
		}
		if _, seen := seenNamespaces[namespace]; seen {
			continue
		}
		seenNamespaces[namespace] = struct{}{}
		if _, protected := protectedNamespaces[namespace]; protected {
			continue
		}

		findings = append(findings, makeFinding(rule, ResourceRef{
			Kind:      "Namespace",
			Namespace: namespace,
			Name:      namespace,
		}, "Namespace/"+namespace+" contains workloads "+messageSuffix, map[string]any{
			"namespace": namespace,
		}))
	}
	return findings
}

func containsValueString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func isSystemNamespace(namespace string) bool {
	switch namespace {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	default:
		return false
	}
}

func hostPathList(volumes []HostPathVolume) []string {
	paths := make([]string, 0, len(volumes))
	for _, volume := range volumes {
		if volume.Path != "" {
			paths = append(paths, volume.Path)
		}
	}
	return compactStrings(paths)
}

func classifySensitiveHostPath(path string) (string, bool) {
	switch {
	case path == "/":
		return "host-root", true
	case path == "/var/lib/etcd" || strings.HasPrefix(path, "/var/lib/etcd/"):
		return "etcd-data", true
	case path == "/var/lib/kubelet" || strings.HasPrefix(path, "/var/lib/kubelet/"):
		return "kubelet-state", true
	case path == "/etc/kubernetes" || strings.HasPrefix(path, "/etc/kubernetes/"):
		return "kubernetes-config", true
	case path == "/var/run/docker.sock":
		return "docker-socket", true
	case path == "/run/containerd/containerd.sock", path == "/var/run/containerd/containerd.sock":
		return "containerd-socket", true
	case path == "/var/run/crio/crio.sock":
		return "crio-socket", true
	default:
		return "", false
	}
}

func hasControlPlaneToleration(tolerations []Toleration) bool {
	for _, toleration := range tolerations {
		switch toleration.Key {
		case "node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master":
			return true
		}
	}
	return false
}

func isControlPlaneNode(node Node) bool {
	for key := range node.Labels {
		switch key {
		case "node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master":
			return true
		}
	}
	return false
}

func hasNoScheduleTaint(taints []Taint) bool {
	for _, taint := range taints {
		switch taint.Key {
		case "node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master":
			if taint.Effect == "" || taint.Effect == "NoSchedule" {
				return true
			}
		}
	}
	return false
}

func activeNodePressures(node Node) []string {
	var pressures []string
	if node.MemoryPressure {
		pressures = append(pressures, "MemoryPressure")
	}
	if node.DiskPressure {
		pressures = append(pressures, "DiskPressure")
	}
	if node.PIDPressure {
		pressures = append(pressures, "PIDPressure")
	}
	return pressures
}

func nodeTaintEvidence(taints []Taint) []map[string]any {
	result := make([]map[string]any, 0, len(taints))
	for _, taint := range taints {
		result = append(result, map[string]any{
			"key":    taint.Key,
			"value":  taint.Value,
			"effect": taint.Effect,
		})
	}
	return result
}

func imageRegistry(image string) (string, bool) {
	repository := image
	if at := strings.Index(repository, "@"); at >= 0 {
		repository = repository[:at]
	}
	lastSlash := strings.LastIndex(repository, "/")
	lastColon := strings.LastIndex(repository, ":")
	if lastColon > lastSlash {
		repository = repository[:lastColon]
	}
	firstSegment := repository
	if slash := strings.Index(firstSegment, "/"); slash >= 0 {
		firstSegment = firstSegment[:slash]
	}
	if strings.Contains(firstSegment, ".") || strings.Contains(firstSegment, ":") || firstSegment == "localhost" {
		return firstSegment, false
	}
	return "docker.io", true
}

func isPublicRegistry(registry string) bool {
	switch strings.ToLower(registry) {
	case "docker.io", "index.docker.io", "registry-1.docker.io", "quay.io", "ghcr.io", "gcr.io", "k8s.gcr.io", "registry.k8s.io", "mcr.microsoft.com", "public.ecr.aws":
		return true
	default:
		return false
	}
}

func manifestSecretMessage(location string, match secretscan.Match) string {
	switch match.Detector {
	case "private-key":
		return "private key material in " + location
	default:
		return article(match.Description) + " in " + location
	}
}

func article(value string) string {
	if value == "" {
		return "a sensitive value"
	}
	first := strings.ToLower(value[:1])
	switch first {
	case "a", "e", "i", "o", "u":
		return "an " + value
	default:
		return "a " + value
	}
}
