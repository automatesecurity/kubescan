package policy

import "strings"

type InventoryFilter struct {
	IncludeKinds      []string
	ExcludeKinds      []string
	IncludeNamespaces []string
	ExcludeNamespaces []string
}

func ApplyInventoryFilter(inventory Inventory, filter InventoryFilter) Inventory {
	includeKinds := normalizeSet(filter.IncludeKinds)
	excludeKinds := normalizeSet(filter.ExcludeKinds)
	includeNamespaces := normalizeSet(filter.IncludeNamespaces)
	excludeNamespaces := normalizeSet(filter.ExcludeNamespaces)

	filtered := Inventory{}
	for _, workload := range inventory.Workloads {
		if matchesResourceFilter(workload.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Workloads = append(filtered.Workloads, workload)
		}
	}
	for _, node := range inventory.Nodes {
		if matchesResourceFilter(node.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Nodes = append(filtered.Nodes, node)
		}
	}
	for _, service := range inventory.Services {
		if matchesResourceFilter(service.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Services = append(filtered.Services, service)
		}
	}
	for _, configMap := range inventory.ConfigMaps {
		if matchesResourceFilter(configMap.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.ConfigMaps = append(filtered.ConfigMaps, configMap)
		}
	}
	for _, role := range inventory.Roles {
		if matchesResourceFilter(role.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Roles = append(filtered.Roles, role)
		}
	}
	for _, binding := range inventory.Bindings {
		if matchesResourceFilter(binding.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Bindings = append(filtered.Bindings, binding)
		}
	}
	for _, networkPolicy := range inventory.NetworkPolicies {
		if matchesResourceFilter(networkPolicy.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.NetworkPolicies = append(filtered.NetworkPolicies, networkPolicy)
		}
	}
	for _, namespace := range inventory.Namespaces {
		if matchesResourceFilter(namespace.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Namespaces = append(filtered.Namespaces, namespace)
		}
	}
	for _, component := range inventory.Components {
		if matchesResourceFilter(component.Resource, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces) {
			filtered.Components = append(filtered.Components, component)
		}
	}
	return filtered
}

func matchesResourceFilter(resource ResourceRef, includeKinds, excludeKinds, includeNamespaces, excludeNamespaces map[string]struct{}) bool {
	kind := strings.ToLower(resource.Kind)
	if len(includeKinds) > 0 {
		if _, ok := includeKinds[kind]; !ok {
			return false
		}
	}
	if _, ok := excludeKinds[kind]; ok {
		return false
	}
	namespace := strings.ToLower(resource.Namespace)
	if kind == "namespace" && namespace == "" {
		namespace = strings.ToLower(resource.Name)
	}
	if namespace != "" {
		if len(includeNamespaces) > 0 {
			if _, ok := includeNamespaces[namespace]; !ok {
				return false
			}
		}
		if _, ok := excludeNamespaces[namespace]; ok {
			return false
		}
	}
	return true
}

func normalizeSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			normalized := strings.ToLower(strings.TrimSpace(part))
			if normalized == "" {
				continue
			}
			set[normalized] = struct{}{}
		}
	}
	return set
}
