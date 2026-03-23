package k8s

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"kubescan/pkg/policy"

	"sigs.k8s.io/yaml"
)

func LoadInventory(r io.Reader) (policy.Inventory, error) {
	documents, err := splitYAMLDocuments(r)
	if err != nil {
		return policy.Inventory{}, err
	}

	inventory := policy.Inventory{}
	for _, document := range documents {
		if len(strings.TrimSpace(string(document))) == 0 {
			continue
		}

		var obj map[string]any
		if err := yaml.Unmarshal(document, &obj); err != nil {
			return policy.Inventory{}, fmt.Errorf("decode manifest: %w", err)
		}
		if len(obj) == 0 {
			continue
		}

		apiVersion, _ := stringValue(obj, "apiVersion")
		kind, _ := stringValue(obj, "kind")
		metadata := nestedMap(obj, "metadata")
		namespace, _ := stringValue(metadata, "namespace")
		name, _ := stringValue(metadata, "name")
		resource := policy.ResourceRef{
			APIVersion: apiVersion,
			Kind:       kind,
			Namespace:  namespace,
			Name:       name,
		}

		switch kind {
		case "Namespace":
			inventory.Namespaces = append(inventory.Namespaces, policy.Namespace{
				Resource: resource,
				Labels:   stringMap(metadata["labels"]),
			})
		case "ConfigMap":
			inventory.ConfigMaps = append(inventory.ConfigMaps, policy.ConfigMap{
				Resource: resource,
				Data:     stringMap(obj["data"]),
			})
		case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			workload, ok := extractWorkload(resource, obj)
			if ok {
				inventory.Workloads = append(inventory.Workloads, workload)
			}
		case "Service":
			serviceType, _ := stringValue(nestedMap(obj, "spec"), "type")
			if serviceType == "" {
				serviceType = "ClusterIP"
			}
			inventory.Services = append(inventory.Services, policy.Service{
				Resource: resource,
				Type:     serviceType,
				Selector: stringMap(nestedMap(obj, "spec")["selector"]),
			})
		case "Role", "ClusterRole":
			role := policy.Role{Resource: resource}
			for _, item := range nestedSlice(obj, "rules") {
				ruleMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				role.Rules = append(role.Rules, policy.PolicyRule{
					Verbs:           stringSlice(ruleMap["verbs"]),
					Resources:       stringSlice(ruleMap["resources"]),
					NonResourceURLs: stringSlice(ruleMap["nonResourceURLs"]),
				})
			}
			inventory.Roles = append(inventory.Roles, role)
		case "RoleBinding", "ClusterRoleBinding":
			roleRef := nestedMap(obj, "roleRef")
			binding := policy.Binding{
				Resource:    resource,
				RoleRefKind: stringValueDefault(roleRef, "kind", ""),
				RoleRefName: stringValueDefault(roleRef, "name", ""),
			}
			for _, item := range nestedSlice(obj, "subjects") {
				subjectMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				binding.Subjects = append(binding.Subjects, policy.Subject{
					Kind:      stringValueDefault(subjectMap, "kind", ""),
					Name:      stringValueDefault(subjectMap, "name", ""),
					Namespace: stringValueDefault(subjectMap, "namespace", ""),
				})
			}
			inventory.Bindings = append(inventory.Bindings, binding)
		case "NetworkPolicy":
			spec := nestedMap(obj, "spec")
			policyTypes := stringSlice(spec["policyTypes"])
			hasIngress := hasField(spec, "ingress") || len(policyTypes) == 0 || containsString(policyTypes, "Ingress")
			hasEgress := hasField(spec, "egress") || containsString(policyTypes, "Egress")
			inventory.NetworkPolicies = append(inventory.NetworkPolicies, policy.NetworkPolicy{
				Resource:    resource,
				PolicyTypes: policyTypes,
				HasIngress:  hasIngress,
				HasEgress:   hasEgress,
			})
		}
	}

	return inventory, nil
}

func extractWorkload(resource policy.ResourceRef, obj map[string]any) (policy.Workload, bool) {
	spec := workloadSpec(obj)
	if spec == nil {
		return policy.Workload{}, false
	}

	workload := policy.Workload{
		Resource:           resource,
		Labels:             workloadLabels(obj),
		ServiceAccountName: stringValueDefault(spec, "serviceAccountName", "default"),
		NodeName:           stringValueDefault(spec, "nodeName", ""),
		HostNetwork:        boolValue(spec["hostNetwork"]),
		HostPID:            boolValue(spec["hostPID"]),
		HostIPC:            boolValue(spec["hostIPC"]),
	}
	podSecurityContext := nestedMap(spec, "securityContext")
	if value, ok := optionalBool(spec["automountServiceAccountToken"]); ok {
		workload.AutomountServiceAccountToken = &value
	}

	for _, item := range nestedSlice(spec, "containers") {
		containerMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		container := policy.Container{
			Name:              stringValueDefault(containerMap, "name", "unnamed"),
			Image:             stringValueDefault(containerMap, "image", ""),
			HasLivenessProbe:  nestedMap(containerMap, "livenessProbe") != nil,
			HasReadinessProbe: nestedMap(containerMap, "readinessProbe") != nil,
		}

		securityContext := nestedMap(containerMap, "securityContext")
		if value, ok := optionalBool(securityContext["privileged"]); ok {
			container.Privileged = &value
		}
		if value, ok := optionalBool(securityContext["allowPrivilegeEscalation"]); ok {
			container.AllowPrivilegeEscalation = &value
		}
		if value, ok := optionalBool(securityContext["runAsNonRoot"]); ok {
			container.RunAsNonRoot = &value
		} else if value, ok := optionalBool(podSecurityContext["runAsNonRoot"]); ok {
			container.RunAsNonRoot = &value
		}
		if value, ok := optionalInt64(securityContext["runAsUser"]); ok {
			container.RunAsUser = &value
		} else if value, ok := optionalInt64(podSecurityContext["runAsUser"]); ok {
			container.RunAsUser = &value
		}
		if value, ok := optionalBool(securityContext["readOnlyRootFilesystem"]); ok {
			container.ReadOnlyRootFilesystem = &value
		}
		if seccompType, ok := stringValue(nestedMap(securityContext, "seccompProfile"), "type"); ok {
			container.SeccompProfileType = seccompType
		} else if seccompType, ok := stringValue(nestedMap(podSecurityContext, "seccompProfile"), "type"); ok {
			container.SeccompProfileType = seccompType
		}
		container.CapabilitiesAdd = stringSlice(nestedMap(securityContext, "capabilities")["add"])
		for _, envItem := range nestedSlice(containerMap, "env") {
			envMap, ok := envItem.(map[string]any)
			if !ok {
				continue
			}
			container.EnvVars = append(container.EnvVars, policy.EnvVar{
				Name:      stringValueDefault(envMap, "name", ""),
				Value:     stringValueDefault(envMap, "value", ""),
				ValueFrom: valueFromSource(envMap["valueFrom"]),
			})
			secretKeyRef := nestedMap(envMap, "valueFrom", "secretKeyRef")
			if secretKeyRef != nil {
				container.SecretEnvRefs = append(container.SecretEnvRefs, policy.SecretRef{
					Name: stringValueDefault(secretKeyRef, "name", ""),
					Key:  stringValueDefault(secretKeyRef, "key", ""),
				})
			}
		}
		for _, envFromItem := range nestedSlice(containerMap, "envFrom") {
			envFromMap, ok := envFromItem.(map[string]any)
			if !ok {
				continue
			}
			secretRef := nestedMap(envFromMap, "secretRef")
			if secretRef != nil {
				container.SecretEnvFromRefs = append(container.SecretEnvFromRefs, stringValueDefault(secretRef, "name", ""))
			}
		}
		for _, portItem := range nestedSlice(containerMap, "ports") {
			portMap, ok := portItem.(map[string]any)
			if !ok {
				continue
			}
			if hostPort, ok := optionalInt64(portMap["hostPort"]); ok && hostPort > 0 {
				container.HostPorts = append(container.HostPorts, int32(hostPort))
			}
		}

		resources := nestedMap(containerMap, "resources")
		requests := nestedMap(resources, "requests")
		limits := nestedMap(resources, "limits")
		container.HasResourceRequests = hasQuantity(requests, "cpu") && hasQuantity(requests, "memory")
		container.HasResourceLimits = hasQuantity(limits, "cpu") && hasQuantity(limits, "memory")

		workload.Containers = append(workload.Containers, container)
	}
	for _, item := range nestedSlice(spec, "volumes") {
		volumeMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		secretVolume := nestedMap(volumeMap, "secret")
		if secretVolume != nil {
			workload.SecretVolumes = append(workload.SecretVolumes, stringValueDefault(secretVolume, "secretName", ""))
		}
		hostPathVolume := nestedMap(volumeMap, "hostPath")
		if hostPathVolume != nil {
			workload.HostPathVolumes = append(workload.HostPathVolumes, policy.HostPathVolume{
				Name: stringValueDefault(volumeMap, "name", ""),
				Path: stringValueDefault(hostPathVolume, "path", ""),
			})
		}
	}
	for _, item := range nestedSlice(spec, "tolerations") {
		tolerationMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		workload.Tolerations = append(workload.Tolerations, policy.Toleration{
			Key:      stringValueDefault(tolerationMap, "key", ""),
			Operator: stringValueDefault(tolerationMap, "operator", ""),
			Value:    stringValueDefault(tolerationMap, "value", ""),
			Effect:   stringValueDefault(tolerationMap, "effect", ""),
		})
	}

	return workload, true
}

func workloadSpec(obj map[string]any) map[string]any {
	switch kind, _ := stringValue(obj, "kind"); kind {
	case "Pod":
		return nestedMap(obj, "spec")
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		return nestedMap(obj, "spec", "template", "spec")
	case "CronJob":
		return nestedMap(obj, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return nil
	}
}

func workloadLabels(obj map[string]any) map[string]string {
	switch kind, _ := stringValue(obj, "kind"); kind {
	case "Pod":
		return stringMap(nestedMap(obj, "metadata")["labels"])
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		return stringMap(nestedMap(obj, "spec", "template", "metadata")["labels"])
	case "CronJob":
		return stringMap(nestedMap(obj, "spec", "jobTemplate", "spec", "template", "metadata")["labels"])
	default:
		return nil
	}
}

func splitYAMLDocuments(r io.Reader) ([][]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		documents []string
		builder   strings.Builder
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "---" {
			documents = append(documents, builder.String())
			builder.Reset()
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read manifests: %w", err)
	}
	documents = append(documents, builder.String())

	result := make([][]byte, 0, len(documents))
	for _, document := range documents {
		result = append(result, []byte(strings.TrimSpace(document)))
	}
	return result, nil
}

func nestedMap(m map[string]any, fields ...string) map[string]any {
	current := m
	for _, field := range fields {
		if current == nil {
			return nil
		}
		value, ok := current[field]
		if !ok {
			return nil
		}
		next, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

func nestedSlice(m map[string]any, field string) []any {
	if m == nil {
		return nil
	}
	value, ok := m[field]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	return items
}

func stringValue(m map[string]any, field string) (string, bool) {
	if m == nil {
		return "", false
	}
	value, ok := m[field]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func stringValueDefault(m map[string]any, field, fallback string) string {
	if value, ok := stringValue(m, field); ok && value != "" {
		return value
	}
	return fallback
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if ok {
			result = append(result, text)
		}
	}
	return result
}

func stringMap(value any) map[string]string {
	items, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(items))
	for key, item := range items {
		text, ok := item.(string)
		if ok {
			result[key] = text
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func valueFromSource(value any) string {
	m, ok := value.(map[string]any)
	if !ok || len(m) == 0 {
		return ""
	}
	for key := range m {
		return key
	}
	return ""
}

func optionalBool(value any) (bool, bool) {
	flag, ok := value.(bool)
	return flag, ok
}

func boolValue(value any) bool {
	flag, ok := optionalBool(value)
	return ok && flag
}

func optionalInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		return int64(typed), true
	default:
		return 0, false
	}
}

func hasQuantity(values map[string]any, field string) bool {
	if values == nil {
		return false
	}
	value, ok := values[field]
	if !ok {
		return false
	}
	text, ok := value.(string)
	return ok && text != ""
}

func hasField(m map[string]any, field string) bool {
	if m == nil {
		return false
	}
	_, ok := m[field]
	return ok
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
