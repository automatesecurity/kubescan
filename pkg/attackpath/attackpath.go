package attackpath

import (
	"fmt"
	"sort"
	"strings"

	"kubescan/pkg/policy"
)

const (
	internetNodeID     = "synthetic:internet"
	nodeCompromiseID   = "synthetic:node-compromise"
	secretAccessID     = "synthetic:secret-access"
	wildcardAccessID   = "synthetic:wildcard-rbac"
	clusterAdminID     = "synthetic:cluster-admin"
	controlPlaneNodeID = "synthetic:control-plane"
	relationRoutesTo   = "ROUTES_TO"
	relationUsesSA     = "USES_SERVICE_ACCOUNT"
	relationBoundTo    = "BOUND_TO_ROLE"
	relationCanReach   = "CAN_REACH"
	relationCanRead    = "CAN_READ"
	relationGrants     = "GRANTS"
	relationTargets    = "TARGETS"
	relationPrecond    = "HAS_PRECONDITIONS_FOR"
)

type Node struct {
	ID         string              `json:"id"`
	Kind       string              `json:"kind"`
	Label      string              `json:"label"`
	Resource   *policy.ResourceRef `json:"resource,omitempty"`
	Attributes map[string]any      `json:"attributes,omitempty"`
}

type Edge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Step struct {
	Label        string              `json:"label"`
	Relationship string              `json:"relationship,omitempty"`
	Resource     *policy.ResourceRef `json:"resource,omitempty"`
}

type Result struct {
	ID              string             `json:"id"`
	Title           string             `json:"title"`
	Severity        policy.Severity    `json:"severity"`
	Summary         string             `json:"summary"`
	Entry           policy.ResourceRef `json:"entry"`
	Target          string             `json:"target"`
	Path            string             `json:"path"`
	SupportingRules []string           `json:"supportingRules,omitempty"`
	Remediation     string             `json:"remediation"`
	Steps           []Step             `json:"steps"`
}

func BuildGraph(inventory policy.Inventory) Graph {
	builder := newGraphBuilder()
	builder.addSyntheticNode(internetNodeID, "Internet", "Internet")
	builder.addSyntheticNode(nodeCompromiseID, "Target", "Node compromise preconditions")
	builder.addSyntheticNode(secretAccessID, "Target", "Secret access")
	builder.addSyntheticNode(wildcardAccessID, "Target", "Wildcard RBAC")
	builder.addSyntheticNode(clusterAdminID, "Target", "Cluster-admin")
	builder.addSyntheticNode(controlPlaneNodeID, "Target", "Control-plane nodes")

	for _, workload := range inventory.Workloads {
		ref := workload.Resource
		builder.addResourceNode(ref, map[string]any{
			"labels": workload.Labels,
		})
		saRef := serviceAccountResource(workload.Resource.Namespace, effectiveServiceAccountName(workload))
		builder.addResourceNode(saRef, nil)
		builder.addEdge(resourceNodeID(ref), resourceNodeID(saRef), relationUsesSA)

		if hasNodeCompromisePreconditions(workload) {
			builder.addEdge(resourceNodeID(ref), nodeCompromiseID, relationPrecond)
		}
		if hasControlPlaneIndicators(workload) {
			builder.addEdge(resourceNodeID(ref), controlPlaneNodeID, relationTargets)
		}
	}

	for _, service := range inventory.Services {
		ref := service.Resource
		builder.addResourceNode(ref, map[string]any{
			"type":     service.Type,
			"selector": service.Selector,
		})
		if isPublicService(service) {
			builder.addEdge(internetNodeID, resourceNodeID(ref), relationCanReach)
		}
		for _, workload := range inventory.Workloads {
			if serviceSelectsWorkload(service, workload) {
				builder.addEdge(resourceNodeID(ref), resourceNodeID(workload.Resource), relationRoutesTo)
			}
		}
	}

	for _, role := range inventory.Roles {
		ref := role.Resource
		builder.addResourceNode(ref, nil)
		if roleHasWildcardPermissions(role) {
			builder.addEdge(resourceNodeID(ref), wildcardAccessID, relationGrants)
		}
		if roleHasSecretReadPermissions(role) {
			builder.addEdge(resourceNodeID(ref), secretAccessID, relationCanRead)
		}
		if isClusterAdminRole(role) {
			builder.addEdge(resourceNodeID(ref), clusterAdminID, relationGrants)
		}
	}

	roleByKey := map[string]policy.Role{}
	for _, role := range inventory.Roles {
		roleByKey[roleKey(role.Resource.Kind, role.Resource.Namespace, role.Resource.Name)] = role
	}
	for _, binding := range inventory.Bindings {
		role, ok := roleByKey[roleKey(binding.RoleRefKind, binding.Resource.Namespace, binding.RoleRefName)]
		if !ok {
			role, ok = roleByKey[roleKey(binding.RoleRefKind, "", binding.RoleRefName)]
		}
		if !ok {
			continue
		}
		for _, subject := range binding.Subjects {
			if !strings.EqualFold(subject.Kind, "ServiceAccount") {
				continue
			}
			saRef := serviceAccountResource(effectiveSubjectNamespace(subject, binding.Resource.Namespace), subject.Name)
			builder.addResourceNode(saRef, nil)
			builder.addEdge(resourceNodeID(saRef), resourceNodeID(role.Resource), relationBoundTo)
		}
	}

	return builder.graph()
}

func Analyze(inventory policy.Inventory, findings []policy.Finding) []Result {
	graph := BuildGraph(inventory)
	nodeByID := make(map[string]Node, len(graph.Nodes))
	outbound := map[string][]Edge{}
	for _, node := range graph.Nodes {
		nodeByID[node.ID] = node
	}
	for _, edge := range graph.Edges {
		outbound[edge.From] = append(outbound[edge.From], edge)
	}

	findingsByResource := groupFindingsByResource(findings)
	var results []Result
	results = append(results, publicToNodeCompromisePaths(nodeByID, outbound, findingsByResource)...)
	results = append(results, workloadToPrivilegePaths(nodeByID, outbound, findingsByResource, wildcardAccessID, "AP002", "Workload reaches wildcard RBAC", policy.SeverityCritical, "Workload can reach wildcard RBAC through its service account bindings.", "Reduce the bound role permissions or move the workload to a less privileged service account.")...)
	results = append(results, workloadToPrivilegePaths(nodeByID, outbound, findingsByResource, secretAccessID, "AP003", "Workload reaches secret-read RBAC", policy.SeverityHigh, "Workload can reach Secret read permissions through its service account bindings.", "Remove unnecessary Secret read permissions from the service account path.")...)
	results = append(results, publicToPrivilegePaths(nodeByID, outbound, findingsByResource, secretAccessID, "AP004", "Public entry reaches secret-read RBAC", policy.SeverityCritical, "An internet-exposed service routes to a workload whose service account can read Secrets.", "Reduce external exposure or remove Secret read permissions from the workload identity.")...)
	results = append(results, publicToPrivilegePaths(nodeByID, outbound, findingsByResource, clusterAdminID, "AP005", "Public entry reaches cluster-admin", policy.SeverityCritical, "An internet-exposed service routes to a workload whose service account can reach cluster-admin.", "Remove cluster-admin access from the workload identity and restrict external exposure.")...)
	results = append(results, controlPlaneCompromisePaths(nodeByID, outbound, findingsByResource)...)
	sort.Slice(results, func(i, j int) bool {
		left := severityWeight(results[i].Severity)
		right := severityWeight(results[j].Severity)
		if left != right {
			return left > right
		}
		if results[i].ID != results[j].ID {
			return results[i].ID < results[j].ID
		}
		return resourceString(results[i].Entry) < resourceString(results[j].Entry)
	})
	return dedupeResults(results)
}

func publicToNodeCompromisePaths(nodeByID map[string]Node, outbound map[string][]Edge, findingsByResource map[string][]string) []Result {
	var results []Result
	for _, serviceEdge := range outbound[internetNodeID] {
		if serviceEdge.Relationship != relationCanReach {
			continue
		}
		serviceNode := nodeByID[serviceEdge.To]
		for _, workloadEdge := range outbound[serviceNode.ID] {
			if workloadEdge.Relationship != relationRoutesTo {
				continue
			}
			workloadNode := nodeByID[workloadEdge.To]
			if !hasEdge(outbound, workloadNode.ID, nodeCompromiseID, relationPrecond) {
				continue
			}
			steps := buildSteps(nodeByID, []edgeStep{
				{From: internetNodeID, To: serviceNode.ID, Relationship: relationCanReach},
				{From: serviceNode.ID, To: workloadNode.ID, Relationship: relationRoutesTo},
				{From: workloadNode.ID, To: nodeCompromiseID, Relationship: relationPrecond},
			})
			results = append(results, Result{
				ID:              "AP001",
				Title:           "Public entry reaches node-compromise preconditions",
				Severity:        policy.SeverityCritical,
				Summary:         "An internet-exposed Service routes to a workload with node-compromise preconditions.",
				Entry:           derefResource(serviceNode.Resource),
				Target:          nodeByID[nodeCompromiseID].Label,
				Path:            stepPath(steps),
				SupportingRules: supportingRules(findingsByResource, serviceNode, workloadNode),
				Remediation:     "Restrict external exposure and remove privileged, host namespace, or sensitive hostPath preconditions from the workload.",
				Steps:           steps,
			})
		}
	}
	return results
}

func workloadToPrivilegePaths(nodeByID map[string]Node, outbound map[string][]Edge, findingsByResource map[string][]string, targetID, pathID, title string, severity policy.Severity, summary, remediation string) []Result {
	var results []Result
	for _, workloadNode := range nodeByID {
		if workloadNode.Kind != "Workload" {
			continue
		}
		for _, saEdge := range outbound[workloadNode.ID] {
			if saEdge.Relationship != relationUsesSA {
				continue
			}
			saNode := nodeByID[saEdge.To]
			for _, roleEdge := range outbound[saNode.ID] {
				if roleEdge.Relationship != relationBoundTo {
					continue
				}
				roleNode := nodeByID[roleEdge.To]
				if !hasEdge(outbound, roleNode.ID, targetID, targetRelationForTarget(targetID)) {
					continue
				}
				steps := buildSteps(nodeByID, []edgeStep{
					{From: workloadNode.ID, To: saNode.ID, Relationship: relationUsesSA},
					{From: saNode.ID, To: roleNode.ID, Relationship: relationBoundTo},
					{From: roleNode.ID, To: targetID, Relationship: targetRelationForTarget(targetID)},
				})
				results = append(results, Result{
					ID:              pathID,
					Title:           title,
					Severity:        severity,
					Summary:         summary,
					Entry:           derefResource(workloadNode.Resource),
					Target:          nodeByID[targetID].Label,
					Path:            stepPath(steps),
					SupportingRules: supportingRules(findingsByResource, workloadNode, saNode, roleNode),
					Remediation:     remediation,
					Steps:           steps,
				})
			}
		}
	}
	return results
}

func publicToPrivilegePaths(nodeByID map[string]Node, outbound map[string][]Edge, findingsByResource map[string][]string, targetID, pathID, title string, severity policy.Severity, summary, remediation string) []Result {
	var results []Result
	for _, serviceEdge := range outbound[internetNodeID] {
		if serviceEdge.Relationship != relationCanReach {
			continue
		}
		serviceNode := nodeByID[serviceEdge.To]
		for _, workloadEdge := range outbound[serviceNode.ID] {
			if workloadEdge.Relationship != relationRoutesTo {
				continue
			}
			workloadNode := nodeByID[workloadEdge.To]
			for _, saEdge := range outbound[workloadNode.ID] {
				if saEdge.Relationship != relationUsesSA {
					continue
				}
				saNode := nodeByID[saEdge.To]
				for _, roleEdge := range outbound[saNode.ID] {
					if roleEdge.Relationship != relationBoundTo {
						continue
					}
					roleNode := nodeByID[roleEdge.To]
					if !hasEdge(outbound, roleNode.ID, targetID, targetRelationForTarget(targetID)) {
						continue
					}
					steps := buildSteps(nodeByID, []edgeStep{
						{From: internetNodeID, To: serviceNode.ID, Relationship: relationCanReach},
						{From: serviceNode.ID, To: workloadNode.ID, Relationship: relationRoutesTo},
						{From: workloadNode.ID, To: saNode.ID, Relationship: relationUsesSA},
						{From: saNode.ID, To: roleNode.ID, Relationship: relationBoundTo},
						{From: roleNode.ID, To: targetID, Relationship: targetRelationForTarget(targetID)},
					})
					results = append(results, Result{
						ID:              pathID,
						Title:           title,
						Severity:        severity,
						Summary:         summary,
						Entry:           derefResource(serviceNode.Resource),
						Target:          nodeByID[targetID].Label,
						Path:            stepPath(steps),
						SupportingRules: supportingRules(findingsByResource, serviceNode, workloadNode, saNode, roleNode),
						Remediation:     remediation,
						Steps:           steps,
					})
				}
			}
		}
	}
	return results
}

func controlPlaneCompromisePaths(nodeByID map[string]Node, outbound map[string][]Edge, findingsByResource map[string][]string) []Result {
	var results []Result
	for _, workloadNode := range nodeByID {
		if workloadNode.Kind != "Workload" {
			continue
		}
		if !hasEdge(outbound, workloadNode.ID, controlPlaneNodeID, relationTargets) || !hasEdge(outbound, workloadNode.ID, nodeCompromiseID, relationPrecond) {
			continue
		}
		steps := buildSteps(nodeByID, []edgeStep{
			{From: workloadNode.ID, To: controlPlaneNodeID, Relationship: relationTargets},
			{From: workloadNode.ID, To: nodeCompromiseID, Relationship: relationPrecond},
		})
		results = append(results, Result{
			ID:              "AP006",
			Title:           "Control-plane targeted workload has node-compromise preconditions",
			Severity:        policy.SeverityCritical,
			Summary:         "A workload shows control-plane scheduling indicators and node-compromise preconditions.",
			Entry:           derefResource(workloadNode.Resource),
			Target:          nodeByID[controlPlaneNodeID].Label,
			Path:            stepPath(steps),
			SupportingRules: supportingRules(findingsByResource, workloadNode),
			Remediation:     "Remove control-plane targeting and strip privileged, host namespace, or sensitive hostPath access from the workload.",
			Steps:           steps,
		})
	}
	return results
}

type edgeStep struct {
	From         string
	To           string
	Relationship string
}

type graphBuilder struct {
	nodes map[string]Node
	edges map[string]Edge
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{
		nodes: map[string]Node{},
		edges: map[string]Edge{},
	}
}

func (b *graphBuilder) addSyntheticNode(id, kind, label string) {
	if _, ok := b.nodes[id]; ok {
		return
	}
	b.nodes[id] = Node{ID: id, Kind: kind, Label: label}
}

func (b *graphBuilder) addResourceNode(resource policy.ResourceRef, attributes map[string]any) {
	if resource.Kind == "" || resource.Name == "" {
		return
	}
	id := resourceNodeID(resource)
	if existing, ok := b.nodes[id]; ok {
		if len(existing.Attributes) == 0 && len(attributes) > 0 {
			existing.Attributes = attributes
			b.nodes[id] = existing
		}
		return
	}
	resourceCopy := resource
	b.nodes[id] = Node{
		ID:         id,
		Kind:       nodeKindForResource(resource.Kind),
		Label:      stepLabel(resource),
		Resource:   &resourceCopy,
		Attributes: attributes,
	}
}

func (b *graphBuilder) addEdge(from, to, relationship string) {
	if from == "" || to == "" || relationship == "" {
		return
	}
	key := from + "|" + relationship + "|" + to
	b.edges[key] = Edge{From: from, To: to, Relationship: relationship}
}

func (b *graphBuilder) graph() Graph {
	nodes := make([]Node, 0, len(b.nodes))
	for _, node := range b.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := make([]Edge, 0, len(b.edges))
	for _, edge := range b.edges {
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].Relationship != edges[j].Relationship {
			return edges[i].Relationship < edges[j].Relationship
		}
		return edges[i].To < edges[j].To
	})

	return Graph{Nodes: nodes, Edges: edges}
}

func serviceSelectsWorkload(service policy.Service, workload policy.Workload) bool {
	if len(service.Selector) == 0 || len(workload.Labels) == 0 {
		return false
	}
	if service.Resource.Namespace != workload.Resource.Namespace {
		return false
	}
	for key, value := range service.Selector {
		if workload.Labels[key] != value {
			return false
		}
	}
	return true
}

func isPublicService(service policy.Service) bool {
	return service.Type == "LoadBalancer" || service.Type == "NodePort"
}

func roleHasWildcardPermissions(role policy.Role) bool {
	for _, policyRule := range role.Rules {
		if containsWildcard(policyRule.Verbs) || containsWildcard(policyRule.Resources) || containsWildcard(policyRule.NonResourceURLs) {
			return true
		}
	}
	return false
}

func roleHasSecretReadPermissions(role policy.Role) bool {
	for _, policyRule := range role.Rules {
		if !matchesAny(policyRule.Resources, "secrets") {
			continue
		}
		if matchesAny(policyRule.Verbs, "*", "get", "list", "watch") {
			return true
		}
	}
	return false
}

func isClusterAdminRole(role policy.Role) bool {
	return role.Resource.Kind == "ClusterRole" && role.Resource.Name == "cluster-admin"
}

func hasNodeCompromisePreconditions(workload policy.Workload) bool {
	return hasPrivilegedHostPID(workload) || hasPrivilegedHostPath(workload) || hasSensitiveHostPath(workload)
}

func hasPrivilegedHostPID(workload policy.Workload) bool {
	if !workload.HostPID {
		return false
	}
	for _, container := range workload.Containers {
		if container.Privileged != nil && *container.Privileged {
			return true
		}
	}
	return false
}

func hasPrivilegedHostPath(workload policy.Workload) bool {
	if len(workload.HostPathVolumes) == 0 {
		return false
	}
	for _, container := range workload.Containers {
		if container.Privileged != nil && *container.Privileged {
			return true
		}
	}
	return false
}

func hasSensitiveHostPath(workload policy.Workload) bool {
	for _, volume := range workload.HostPathVolumes {
		if _, ok := classifySensitiveHostPath(volume.Path); ok {
			return true
		}
	}
	return false
}

func hasControlPlaneIndicators(workload policy.Workload) bool {
	nodeName := strings.ToLower(workload.NodeName)
	return strings.Contains(nodeName, "control-plane") || strings.Contains(nodeName, "master") || hasControlPlaneToleration(workload.Tolerations)
}

func resourceNodeID(resource policy.ResourceRef) string {
	if resource.Namespace != "" {
		return fmt.Sprintf("resource:%s:%s:%s", resource.Kind, resource.Namespace, resource.Name)
	}
	return fmt.Sprintf("resource:%s:%s", resource.Kind, resource.Name)
}

func serviceAccountResource(namespace, name string) policy.ResourceRef {
	return policy.ResourceRef{
		Kind:      "ServiceAccount",
		Namespace: namespace,
		Name:      name,
	}
}

func effectiveServiceAccountName(workload policy.Workload) string {
	if workload.ServiceAccountName == "" {
		return "default"
	}
	return workload.ServiceAccountName
}

func effectiveSubjectNamespace(subject policy.Subject, bindingNamespace string) string {
	if subject.Namespace != "" {
		return subject.Namespace
	}
	return bindingNamespace
}

func roleKey(kind, namespace, name string) string {
	if kind == "ClusterRole" {
		namespace = ""
	}
	return kind + "|" + namespace + "|" + name
}

func buildSteps(nodeByID map[string]Node, edges []edgeStep) []Step {
	if len(edges) == 0 {
		return nil
	}
	steps := []Step{nodeToStep(nodeByID[edges[0].From], "")}
	for _, edge := range edges {
		steps = append(steps, nodeToStep(nodeByID[edge.To], edge.Relationship))
	}
	return steps
}

func nodeToStep(node Node, relationship string) Step {
	return Step{
		Label:        node.Label,
		Relationship: relationship,
		Resource:     node.Resource,
	}
}

func stepPath(steps []Step) string {
	labels := make([]string, 0, len(steps))
	for _, step := range steps {
		labels = append(labels, step.Label)
	}
	return strings.Join(labels, " -> ")
}

func supportingRules(findingsByResource map[string][]string, nodes ...Node) []string {
	seen := map[string]struct{}{}
	var rules []string
	for _, node := range nodes {
		if node.Resource == nil {
			continue
		}
		for _, ruleID := range findingsByResource[resourceString(*node.Resource)] {
			if _, ok := seen[ruleID]; ok {
				continue
			}
			seen[ruleID] = struct{}{}
			rules = append(rules, ruleID)
		}
	}
	sort.Strings(rules)
	return rules
}

func groupFindingsByResource(findings []policy.Finding) map[string][]string {
	grouped := map[string][]string{}
	for _, finding := range findings {
		key := resourceString(finding.Resource)
		if key == "" {
			continue
		}
		grouped[key] = append(grouped[key], finding.RuleID)
	}
	for key := range grouped {
		grouped[key] = uniqueStrings(grouped[key])
	}
	return grouped
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	var last string
	for i, value := range values {
		if i == 0 || value != last {
			result = append(result, value)
			last = value
		}
	}
	return result
}

func resourceString(resource policy.ResourceRef) string {
	if resource.Kind == "" || resource.Name == "" {
		return ""
	}
	if resource.Namespace != "" {
		return resource.Namespace + "/" + resource.Kind + "/" + resource.Name
	}
	return resource.Kind + "/" + resource.Name
}

func stepLabel(resource policy.ResourceRef) string {
	if resource.Namespace != "" {
		return resource.Kind + "/" + resource.Namespace + "/" + resource.Name
	}
	return resource.Kind + "/" + resource.Name
}

func nodeKindForResource(kind string) string {
	switch kind {
	case "Service":
		return "Service"
	case "ServiceAccount":
		return "ServiceAccount"
	case "Role", "ClusterRole":
		return "Role"
	case "Namespace":
		return "Namespace"
	default:
		return "Workload"
	}
}

func hasEdge(outbound map[string][]Edge, from, to, relationship string) bool {
	for _, edge := range outbound[from] {
		if edge.To == to && edge.Relationship == relationship {
			return true
		}
	}
	return false
}

func targetRelationForTarget(targetID string) string {
	switch targetID {
	case secretAccessID:
		return relationCanRead
	default:
		return relationGrants
	}
}

func severityWeight(severity policy.Severity) int {
	switch severity {
	case policy.SeverityCritical:
		return 4
	case policy.SeverityHigh:
		return 3
	case policy.SeverityMedium:
		return 2
	default:
		return 1
	}
}

func dedupeResults(results []Result) []Result {
	seen := map[string]struct{}{}
	deduped := make([]Result, 0, len(results))
	for _, result := range results {
		key := result.ID + "|" + resourceString(result.Entry) + "|" + result.Path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, result)
	}
	return deduped
}

func derefResource(resource *policy.ResourceRef) policy.ResourceRef {
	if resource == nil {
		return policy.ResourceRef{}
	}
	return *resource
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func matchesAny(values []string, candidates ...string) bool {
	for _, value := range values {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func hasControlPlaneToleration(tolerations []policy.Toleration) bool {
	for _, toleration := range tolerations {
		switch toleration.Key {
		case "node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master":
			return true
		}
	}
	return false
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
