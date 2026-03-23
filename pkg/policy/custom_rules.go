package policy

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

func evaluateCustomRules(inventory Inventory, specs []CustomRuleSpec) []Finding {
	var findings []Finding
	for _, spec := range specs {
		switch spec.Target {
		case "container":
			findings = append(findings, evaluateContainerCustomRule(inventory, spec)...)
		case "workload":
			findings = append(findings, evaluateWorkloadCustomRule(inventory, spec)...)
		case "service":
			findings = append(findings, evaluateServiceCustomRule(inventory, spec)...)
		case "namespace":
			findings = append(findings, evaluateNamespaceCustomRule(inventory, spec)...)
		case "serviceAccount":
			findings = append(findings, evaluateServiceAccountCustomRule(inventory, spec)...)
		}
	}
	return findings
}

func evaluateContainerCustomRule(inventory Inventory, spec CustomRuleSpec) []Finding {
	var findings []Finding
	for _, workload := range inventory.Workloads {
		for _, container := range workload.Containers {
			if !matchesContainerRule(workload, container, spec.Match) {
				continue
			}
			findings = append(findings, customFinding(spec, workload.Resource, map[string]any{
				"container": container.Name,
				"image":     container.Image,
				"target":    "container",
			}))
		}
	}
	return findings
}

func evaluateWorkloadCustomRule(inventory Inventory, spec CustomRuleSpec) []Finding {
	var findings []Finding
	for _, workload := range inventory.Workloads {
		if !matchesWorkloadRule(workload, spec.Match) {
			continue
		}
		findings = append(findings, customFinding(spec, workload.Resource, map[string]any{
			"target": "workload",
		}))
	}
	return findings
}

func evaluateServiceCustomRule(inventory Inventory, spec CustomRuleSpec) []Finding {
	var findings []Finding
	for _, service := range inventory.Services {
		if !matchesServiceRule(service, spec.Match) {
			continue
		}
		findings = append(findings, customFinding(spec, service.Resource, map[string]any{
			"type":   service.Type,
			"target": "service",
		}))
	}
	return findings
}

func evaluateNamespaceCustomRule(inventory Inventory, spec CustomRuleSpec) []Finding {
	var findings []Finding
	for _, summary := range namespaceSummaries(inventory) {
		if !matchesNamespaceRule(summary, spec.Match) {
			continue
		}
		findings = append(findings, customFinding(spec, summary.Resource, map[string]any{
			"target":             "namespace",
			"workloadCount":      summary.WorkloadCount,
			"serviceCount":       summary.ServiceCount,
			"publicServiceCount": summary.PublicServiceCount,
			"networkPolicyCount": summary.NetworkPolicyCount,
			"ingressPolicyCount": summary.IngressPolicyCount,
			"egressPolicyCount":  summary.EgressPolicyCount,
		}))
	}
	return findings
}

func evaluateServiceAccountCustomRule(inventory Inventory, spec CustomRuleSpec) []Finding {
	var findings []Finding
	for _, summary := range serviceAccountSummaries(inventory) {
		if !matchesServiceAccountRule(summary, spec.Match) {
			continue
		}
		findings = append(findings, customFinding(spec, summary.Resource, map[string]any{
			"target":                    "serviceAccount",
			"workloadCount":             summary.WorkloadCount,
			"automountingWorkloadCount": summary.AutomountingWorkloadCount,
			"bindingCount":              summary.BindingCount,
			"hasWildcardPermissions":    summary.HasWildcardPermissions,
			"hasSecretReadPermissions":  summary.HasSecretReadPermissions,
		}))
	}
	return findings
}

func customFinding(spec CustomRuleSpec, resource ResourceRef, evidence map[string]any) Finding {
	return makeFinding(Rule{
		ID:          spec.ID,
		Category:    spec.Category,
		Title:       spec.Title,
		Severity:    spec.Severity,
		Remediation: spec.Remediation,
	}, resource, spec.Message, evidence)
}

func matchesContainerRule(workload Workload, container Container, match MatchClause) bool {
	return matchClause(match, func(field string) any {
		return containerFieldValue(workload, container, field)
	})
}

func matchesWorkloadRule(workload Workload, match MatchClause) bool {
	return matchClause(match, func(field string) any {
		return workloadFieldValue(workload, field)
	})
}

func matchesServiceRule(service Service, match MatchClause) bool {
	return matchClause(match, func(field string) any {
		return serviceFieldValue(service, field)
	})
}

func matchesNamespaceRule(summary namespaceSummary, match MatchClause) bool {
	return matchClause(match, func(field string) any {
		return namespaceFieldValue(summary, field)
	})
}

func matchesServiceAccountRule(summary serviceAccountSummary, match MatchClause) bool {
	return matchClause(match, func(field string) any {
		return serviceAccountFieldValue(summary, field)
	})
}

func matchClause(match MatchClause, resolveField func(string) any) bool {
	return evaluateBooleanGroup(match.All, match.Any, match.Not, resolveField)
}

func evaluateBooleanGroup(all, any, not []Predicate, resolveField func(string) any) bool {
	for _, predicate := range all {
		if !evaluatePredicate(predicate, resolveField) {
			return false
		}
	}

	if len(any) > 0 {
		anyMatched := false
		for _, predicate := range any {
			if evaluatePredicate(predicate, resolveField) {
				anyMatched = true
				break
			}
		}
		if !anyMatched {
			return false
		}
	}

	for _, predicate := range not {
		if evaluatePredicate(predicate, resolveField) {
			return false
		}
	}

	return true
}

func evaluatePredicate(predicate Predicate, resolveField func(string) any) bool {
	if len(predicate.All) > 0 || len(predicate.Any) > 0 || len(predicate.Not) > 0 {
		return evaluateBooleanGroup(predicate.All, predicate.Any, predicate.Not, resolveField)
	}
	return matchPredicate(resolveField(predicate.Field), predicate)
}

func containerFieldValue(workload Workload, container Container, field string) any {
	switch field {
	case "name":
		return container.Name
	case "image":
		return container.Image
	case "privileged":
		return boolPointerValue(container.Privileged)
	case "runAsNonRoot":
		return boolPointerValue(container.RunAsNonRoot)
	case "runAsUser":
		return int64PointerValue(container.RunAsUser)
	case "readOnlyRootFilesystem":
		return boolPointerValue(container.ReadOnlyRootFilesystem)
	case "hasLivenessProbe":
		return container.HasLivenessProbe
	case "hasReadinessProbe":
		return container.HasReadinessProbe
	case "hasResourceRequests":
		return container.HasResourceRequests
	case "hasResourceLimits":
		return container.HasResourceLimits
	case "capabilitiesAdd":
		return container.CapabilitiesAdd
	case "workload.name":
		return workload.Resource.Name
	case "workload.namespace":
		return workload.Resource.Namespace
	case "workload.kind":
		return workload.Resource.Kind
	default:
		return nil
	}
}

func workloadFieldValue(workload Workload, field string) any {
	switch field {
	case "name":
		return workload.Resource.Name
	case "namespace":
		return workload.Resource.Namespace
	case "kind":
		return workload.Resource.Kind
	case "serviceAccountName":
		return workload.ServiceAccountName
	case "nodeName":
		return workload.NodeName
	case "automountServiceAccountToken":
		return boolPointerValue(workload.AutomountServiceAccountToken)
	case "hostNetwork":
		return workload.HostNetwork
	case "hostPID":
		return workload.HostPID
	case "hostIPC":
		return workload.HostIPC
	case "tolerationKeys":
		return tolerationKeys(workload.Tolerations)
	case "hasControlPlaneToleration":
		return hasControlPlaneToleration(workload.Tolerations)
	default:
		return nil
	}
}

func serviceFieldValue(service Service, field string) any {
	switch field {
	case "name":
		return service.Resource.Name
	case "namespace":
		return service.Resource.Namespace
	case "kind":
		return service.Resource.Kind
	case "type":
		return service.Type
	default:
		return nil
	}
}

func namespaceFieldValue(summary namespaceSummary, field string) any {
	switch field {
	case "name":
		return summary.Resource.Name
	case "kind":
		return summary.Resource.Kind
	case "workloadCount":
		return int64(summary.WorkloadCount)
	case "serviceCount":
		return int64(summary.ServiceCount)
	case "publicServiceCount":
		return int64(summary.PublicServiceCount)
	case "networkPolicyCount":
		return int64(summary.NetworkPolicyCount)
	case "ingressPolicyCount":
		return int64(summary.IngressPolicyCount)
	case "egressPolicyCount":
		return int64(summary.EgressPolicyCount)
	case "hasWorkloads":
		return summary.WorkloadCount > 0
	case "hasServices":
		return summary.ServiceCount > 0
	case "hasPublicService":
		return summary.PublicServiceCount > 0
	case "hasNetworkPolicy":
		return summary.NetworkPolicyCount > 0
	case "hasIngressPolicy":
		return summary.IngressPolicyCount > 0
	case "hasEgressPolicy":
		return summary.EgressPolicyCount > 0
	default:
		return nil
	}
}

func serviceAccountFieldValue(summary serviceAccountSummary, field string) any {
	switch field {
	case "name":
		return summary.Resource.Name
	case "namespace":
		return summary.Resource.Namespace
	case "kind":
		return summary.Resource.Kind
	case "workloadCount":
		return int64(summary.WorkloadCount)
	case "automountingWorkloadCount":
		return int64(summary.AutomountingWorkloadCount)
	case "bindingCount":
		return int64(summary.BindingCount)
	case "hasWorkloads":
		return summary.WorkloadCount > 0
	case "hasAutomountingWorkloads":
		return summary.AutomountingWorkloadCount > 0
	case "hasBindings":
		return summary.BindingCount > 0
	case "hasWildcardPermissions":
		return summary.HasWildcardPermissions
	case "hasSecretReadPermissions":
		return summary.HasSecretReadPermissions
	default:
		return nil
	}
}

func tolerationKeys(tolerations []Toleration) []string {
	keys := make([]string, 0, len(tolerations))
	for _, toleration := range tolerations {
		if toleration.Key != "" {
			keys = append(keys, toleration.Key)
		}
	}
	return keys
}

func matchPredicate(actual any, predicate Predicate) bool {
	switch predicate.Op {
	case "exists":
		return actual != nil && actual != ""
	case "equals":
		return compareScalar(actual, predicate.Value)
	case "not_equals":
		return !compareScalar(actual, predicate.Value)
	case "contains":
		return containsValue(actual, predicate.Value)
	case "not_contains":
		return !containsValue(actual, predicate.Value)
	case "one_of":
		return oneOf(actual, predicate.Value)
	case "greater_than":
		return compareNumeric(actual, predicate.Value, func(left, right int64) bool {
			return left > right
		})
	case "greater_or_equal":
		return compareNumeric(actual, predicate.Value, func(left, right int64) bool {
			return left >= right
		})
	case "less_than":
		return compareNumeric(actual, predicate.Value, func(left, right int64) bool {
			return left < right
		})
	case "less_or_equal":
		return compareNumeric(actual, predicate.Value, func(left, right int64) bool {
			return left <= right
		})
	default:
		return false
	}
}

func compareScalar(actual any, expected any) bool {
	switch typed := actual.(type) {
	case nil:
		return expected == nil
	case bool:
		value, ok := toBool(expected)
		return ok && typed == value
	case int64:
		value, ok := toInt64(expected)
		return ok && typed == value
	case string:
		return typed == fmt.Sprint(expected)
	default:
		return fmt.Sprint(actual) == fmt.Sprint(expected)
	}
}

func containsValue(actual any, expected any) bool {
	switch typed := actual.(type) {
	case string:
		return strings.Contains(typed, fmt.Sprint(expected))
	case []string:
		expectedText := fmt.Sprint(expected)
		for _, value := range typed {
			if value == expectedText {
				return true
			}
		}
	}
	return false
}

func oneOf(actual any, expected any) bool {
	values, ok := expected.([]any)
	if !ok {
		return false
	}
	for _, value := range values {
		if compareScalar(actual, value) || containsValue(actual, value) {
			return true
		}
	}
	return false
}

func compareNumeric(actual any, expected any, compare func(int64, int64) bool) bool {
	left, ok := toInt64(actual)
	if !ok {
		return false
	}
	right, ok := toInt64(expected)
	if !ok {
		return false
	}
	return compare(left, right)
}

func boolPointerValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func int64PointerValue(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func toBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(typed)
		return parsed, err == nil
	default:
		return false, false
	}
}

func toInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case float64:
		if typed != math.Trunc(typed) {
			return 0, false
		}
		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

type namespaceSummary struct {
	Resource           ResourceRef
	WorkloadCount      int
	ServiceCount       int
	PublicServiceCount int
	NetworkPolicyCount int
	IngressPolicyCount int
	EgressPolicyCount  int
}

func namespaceSummaries(inventory Inventory) []namespaceSummary {
	byNamespace := map[string]*namespaceSummary{}

	for _, workload := range inventory.Workloads {
		if workload.Resource.Namespace == "" {
			continue
		}
		summary := ensureNamespaceSummary(byNamespace, workload.Resource.Namespace)
		summary.WorkloadCount++
	}

	for _, service := range inventory.Services {
		if service.Resource.Namespace == "" {
			continue
		}
		summary := ensureNamespaceSummary(byNamespace, service.Resource.Namespace)
		summary.ServiceCount++
		if isPublicServiceType(service.Type) {
			summary.PublicServiceCount++
		}
	}

	for _, networkPolicy := range inventory.NetworkPolicies {
		if networkPolicy.Resource.Namespace == "" {
			continue
		}
		summary := ensureNamespaceSummary(byNamespace, networkPolicy.Resource.Namespace)
		summary.NetworkPolicyCount++
		if networkPolicy.HasIngress {
			summary.IngressPolicyCount++
		}
		if networkPolicy.HasEgress {
			summary.EgressPolicyCount++
		}
	}

	summaries := make([]namespaceSummary, 0, len(byNamespace))
	namespaces := make([]string, 0, len(byNamespace))
	for namespace := range byNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	for _, namespace := range namespaces {
		summaries = append(summaries, *byNamespace[namespace])
	}
	return summaries
}

func ensureNamespaceSummary(byNamespace map[string]*namespaceSummary, namespace string) *namespaceSummary {
	if summary, ok := byNamespace[namespace]; ok {
		return summary
	}

	summary := &namespaceSummary{
		Resource: ResourceRef{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       namespace,
		},
	}
	byNamespace[namespace] = summary
	return summary
}

func isPublicServiceType(serviceType string) bool {
	return serviceType == "LoadBalancer" || serviceType == "NodePort"
}

type serviceAccountSummary struct {
	Resource                  ResourceRef
	WorkloadCount             int
	AutomountingWorkloadCount int
	BindingCount              int
	HasWildcardPermissions    bool
	HasSecretReadPermissions  bool
}

func serviceAccountSummaries(inventory Inventory) []serviceAccountSummary {
	byServiceAccount := map[string]*serviceAccountSummary{}
	bindingsByServiceAccount := map[string]map[string]struct{}{}

	for _, workload := range inventory.Workloads {
		namespace := workload.Resource.Namespace
		if namespace == "" {
			continue
		}
		name := workload.ServiceAccountName
		if name == "" {
			name = "default"
		}
		summary := ensureServiceAccountSummary(byServiceAccount, namespace, name)
		summary.WorkloadCount++
		if workload.AutomountServiceAccountToken == nil || *workload.AutomountServiceAccountToken {
			summary.AutomountingWorkloadCount++
		}
	}

	for _, resolution := range wildcardBindingResolutions(inventory) {
		for _, subject := range resolution.Binding.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}
			namespace := effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace)
			if namespace == "" {
				continue
			}
			summary := ensureServiceAccountSummary(byServiceAccount, namespace, subject.Name)
			summary.HasWildcardPermissions = true
			recordServiceAccountBinding(bindingsByServiceAccount, namespace, subject.Name, resolution.Binding.Resource)
		}
	}

	for _, resolution := range roleBindingResolutions(inventory, roleHasSecretReadPermissions) {
		for _, subject := range resolution.Binding.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}
			namespace := effectiveSubjectNamespace(subject, resolution.Binding.Resource.Namespace)
			if namespace == "" {
				continue
			}
			summary := ensureServiceAccountSummary(byServiceAccount, namespace, subject.Name)
			summary.HasSecretReadPermissions = true
			recordServiceAccountBinding(bindingsByServiceAccount, namespace, subject.Name, resolution.Binding.Resource)
		}
	}

	for key, bindings := range bindingsByServiceAccount {
		if summary, ok := byServiceAccount[key]; ok {
			summary.BindingCount = len(bindings)
		}
	}

	keys := make([]string, 0, len(byServiceAccount))
	for key := range byServiceAccount {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	summaries := make([]serviceAccountSummary, 0, len(keys))
	for _, key := range keys {
		summaries = append(summaries, *byServiceAccount[key])
	}
	return summaries
}

func ensureServiceAccountSummary(byServiceAccount map[string]*serviceAccountSummary, namespace, name string) *serviceAccountSummary {
	key := namespace + "/" + name
	if summary, ok := byServiceAccount[key]; ok {
		return summary
	}
	summary := &serviceAccountSummary{
		Resource: ResourceRef{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
			Namespace:  namespace,
			Name:       name,
		},
	}
	byServiceAccount[key] = summary
	return summary
}

func recordServiceAccountBinding(bindingsByServiceAccount map[string]map[string]struct{}, namespace, name string, resource ResourceRef) {
	key := namespace + "/" + name
	if bindingsByServiceAccount[key] == nil {
		bindingsByServiceAccount[key] = map[string]struct{}{}
	}
	bindingsByServiceAccount[key][resource.Kind+"/"+resource.Namespace+"/"+resource.Name] = struct{}{}
}
