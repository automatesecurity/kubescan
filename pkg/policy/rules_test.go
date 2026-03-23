package policy

import "testing"

func TestEvaluateFindsExpectedIssues(t *testing.T) {
	trueValue := true
	falseValue := false
	root := int64(0)

	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource:    ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				NodeName:    "control-plane-1",
				HostNetwork: true,
				HostPID:     true,
				Tolerations: []Toleration{
					{Key: "node-role.kubernetes.io/control-plane", Operator: "Exists", Effect: "NoSchedule"},
				},
				HostPathVolumes: []HostPathVolume{
					{Name: "host-data", Path: "/var/lib/kubelet"},
				},
				Containers: []Container{
					{
						Name:                     "api",
						Image:                    "nginx:latest",
						Privileged:               &trueValue,
						RunAsNonRoot:             &falseValue,
						RunAsUser:                &root,
						ReadOnlyRootFilesystem:   &falseValue,
						CapabilitiesAdd:          []string{"SYS_ADMIN"},
						SecretEnvRefs:            []SecretRef{{Name: "db-creds", Key: "password"}},
						HostPorts:                []int32{8080},
						AllowPrivilegeEscalation: &trueValue,
					},
				},
				SecretVolumes: []string{"api-tls"},
			},
		},
		Services: []Service{
			{
				Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
				Type:     "LoadBalancer",
			},
		},
		Roles: []Role{
			{
				Resource: ResourceRef{Kind: "Role", Namespace: "payments", Name: "wildcard"},
				Rules: []PolicyRule{
					{Verbs: []string{"*"}, Resources: []string{"pods"}},
				},
			},
		},
		Bindings: []Binding{
			{
				Resource:    ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "api-admin"},
				RoleRefKind: "Role",
				RoleRefName: "wildcard",
				Subjects: []Subject{
					{Kind: "ServiceAccount", Namespace: "payments", Name: "default"},
					{Kind: "User", Name: "alice@example.com"},
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)
	if len(findings) < 24 {
		t.Fatalf("expected at least 24 findings, got %d", len(findings))
	}
	assertRulePresent(t, findings, "KS001")
	assertRulePresent(t, findings, "KS033")
	assertRulePresent(t, findings, "KS034")
	assertRulePresent(t, findings, "KS035")
	assertRulePresent(t, findings, "KS002")
	assertRulePresent(t, findings, "KS022")
	assertRulePresent(t, findings, "KS023")
	assertRulePresent(t, findings, "KS003")
	assertRulePresent(t, findings, "KS004")
	assertRulePresent(t, findings, "KS005")
	assertRulePresent(t, findings, "KS024")
	assertRulePresent(t, findings, "KS025")
	assertRulePresent(t, findings, "KS006")
	assertRulePresent(t, findings, "KS007")
	assertRulePresent(t, findings, "KS008")
	assertRulePresent(t, findings, "KS009")
	assertRulePresent(t, findings, "KS010")
	assertRulePresent(t, findings, "KS011")
	assertRulePresent(t, findings, "KS012")
	assertRulePresent(t, findings, "KS013")
	assertRulePresent(t, findings, "KS016")
	assertRulePresent(t, findings, "KS017")
	assertRulePresent(t, findings, "KS027")
	assertRulePresent(t, findings, "KS018")
	assertRulePresent(t, findings, "KS019")
	assertRulePresent(t, findings, "KS020")
	assertRulePresent(t, findings, "KS021")
	assertRulePresent(t, findings, "KS015")
	assertRulePresent(t, findings, "KS030")
	assertRulePresent(t, findings, "KS031")
	assertRulePresent(t, findings, "KS032")
	assertRulePresent(t, findings, "KS036")
	assertRuleMissing(t, findings, "KS014")
}

func TestUsesMutableTag(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{image: "nginx", want: true},
		{image: "nginx:latest", want: true},
		{image: "nginx:1.27.1", want: false},
		{image: "ghcr.io/org/app@sha256:abc", want: false},
	}

	for _, tc := range cases {
		if got := usesMutableTag(tc.image); got != tc.want {
			t.Fatalf("usesMutableTag(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

func TestEvaluateDefaultProfileExcludesProfileOnlyRules(t *testing.T) {
	trueValue := true
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource:                     ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				ServiceAccountName:           "default",
				AutomountServiceAccountToken: &trueValue,
				SecretVolumes:                []string{"api-tls"},
				Containers: []Container{
					{
						Name:                "api",
						Image:               "nginx:latest",
						SecretEnvRefs:       []SecretRef{{Name: "db-creds", Key: "password"}},
						HasLivenessProbe:    false,
						HasReadinessProbe:   false,
						HasResourceLimits:   false,
						HasResourceRequests: false,
					},
				},
			},
		},
		Namespaces: []Namespace{
			{
				Resource: ResourceRef{Kind: "Namespace", Name: "payments"},
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "baseline",
				},
			},
		},
		ConfigMaps: []ConfigMap{
			{
				Resource: ResourceRef{Kind: "ConfigMap", Namespace: "payments", Name: "app-config"},
				Data: map[string]string{
					"api_token": "super-secret",
				},
			},
		},
	}

	findings := Evaluate(inventory)

	assertRulePresent(t, findings, "KS010")
	assertRuleMissing(t, findings, "KS006")
	assertRuleMissing(t, findings, "KS007")
	assertRuleMissing(t, findings, "KS008")
	assertRuleMissing(t, findings, "KS009")
	assertRuleMissing(t, findings, "KS012")
	assertRuleMissing(t, findings, "KS018")
	assertRuleMissing(t, findings, "KS019")
	assertRuleMissing(t, findings, "KS027")
	assertRuleMissing(t, findings, "KS028")
	assertRuleMissing(t, findings, "KS029")
	assertRuleMissing(t, findings, "KS032")
	assertRuleMissing(t, findings, "KS014")
}

func TestEvaluateWithBundleDisablesAndOverridesRules(t *testing.T) {
	trueValue := true

	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Containers: []Container{
					{
						Name:       "api",
						Image:      "nginx:latest",
						Privileged: &trueValue,
					},
				},
			},
		},
	}

	critical := SeverityCritical
	disabled := false
	findings := EvaluateWithBundle(inventory, RuleBundle{
		Rules: []RuleConfig{
			{ID: "KS003", Enabled: &disabled},
			{ID: "KS010", Severity: &critical},
		},
	})

	assertRuleMissing(t, findings, "KS003")
	assertRulePresent(t, findings, "KS010")
	for _, finding := range findings {
		if finding.RuleID == "KS010" {
			if finding.Severity != SeverityCritical {
				t.Fatalf("expected KS010 severity critical, got %s", finding.Severity)
			}
			if finding.OriginalSeverity != SeverityHigh {
				t.Fatalf("expected KS010 original severity high, got %s", finding.OriginalSeverity)
			}
		}
	}
}

func TestEvaluateWithBundleCustomRules(t *testing.T) {
	trueValue := true
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Containers: []Container{
					{
						Name:              "api",
						Image:             "ghcr.io/acme/api:1.0.0",
						Privileged:        &trueValue,
						HasLivenessProbe:  false,
						HasReadinessProbe: false,
					},
				},
				HostNetwork: true,
			},
		},
		Services: []Service{
			{
				Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "public"},
				Type:     "LoadBalancer",
			},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR001",
				Target:      "container",
				Category:    CategorySupplyChain,
				Title:       "Custom registry allowlist",
				Severity:    SeverityHigh,
				Message:     "Container image is from ghcr.io/acme.",
				Remediation: "Use the approved registry pattern.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "image", Op: "contains", Value: "ghcr.io/acme/"},
						{Field: "workload.namespace", Op: "equals", Value: "payments"},
					},
				},
			},
			{
				ID:          "CR002",
				Target:      "workload",
				Category:    CategoryExposure,
				Title:       "Custom host network check",
				Severity:    SeverityCritical,
				Message:     "Workload uses host networking.",
				Remediation: "Disable host networking.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "hostNetwork", Op: "equals", Value: true},
					},
				},
			},
			{
				ID:          "CR003",
				Target:      "service",
				Category:    CategoryExposure,
				Title:       "Custom public service check",
				Severity:    SeverityHigh,
				Message:     "Service is internet-facing.",
				Remediation: "Use ClusterIP for internal services.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "type", Op: "one_of", Value: []any{"LoadBalancer", "NodePort"}},
					},
				},
			},
		},
	})

	assertRulePresent(t, findings, "CR001")
	assertRulePresent(t, findings, "CR002")
	assertRulePresent(t, findings, "CR003")
}

func TestEvaluateWithBundleNamespaceCustomRules(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
			},
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "proxy"},
			},
		},
		Services: []Service{
			{
				Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"},
				Type:     "LoadBalancer",
			},
		},
		NetworkPolicies: []NetworkPolicy{
			{
				Resource: ResourceRef{Kind: "NetworkPolicy", Namespace: "platform", Name: "default-deny"},
			},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR004",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace lacks network policy coverage",
				Severity:    SeverityHigh,
				Message:     "Namespace has workloads but no network policies.",
				Remediation: "Add default-deny and allow-list network policies.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "hasWorkloads", Op: "equals", Value: true},
						{Field: "hasNetworkPolicy", Op: "equals", Value: false},
						{Field: "hasPublicService", Op: "equals", Value: true},
					},
				},
			},
		},
	})

	finding := findRule(t, findings, "CR004")
	if finding.Resource.Kind != "Namespace" {
		t.Fatalf("expected namespace resource kind, got %q", finding.Resource.Kind)
	}
	if finding.Resource.Name != "payments" {
		t.Fatalf("expected namespace resource name payments, got %q", finding.Resource.Name)
	}
	if got := finding.Evidence["networkPolicyCount"]; got != 0 {
		t.Fatalf("expected networkPolicyCount evidence 0, got %#v", got)
	}
	if got := finding.Evidence["publicServiceCount"]; got != 1 {
		t.Fatalf("expected publicServiceCount evidence 1, got %#v", got)
	}
}

func TestEvaluateWithBundleNumericComparisonRules(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "worker"}},
		},
		Services: []Service{
			{Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"}, Type: "LoadBalancer"},
			{Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "worker"}, Type: "NodePort"},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR005",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace has too many public services",
				Severity:    SeverityCritical,
				Message:     "Namespace exceeds the public service threshold.",
				Remediation: "Reduce internet-facing services or segment the namespace.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "publicServiceCount", Op: "greater_or_equal", Value: 2},
						{Field: "networkPolicyCount", Op: "less_than", Value: 1},
						{Field: "workloadCount", Op: "greater_than", Value: "1"},
					},
				},
			},
			{
				ID:          "CR006",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace is under threshold",
				Severity:    SeverityLow,
				Message:     "Namespace should not match this rule.",
				Remediation: "No-op.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "publicServiceCount", Op: "less_or_equal", Value: 1},
					},
				},
			},
		},
	})

	assertRulePresent(t, findings, "CR005")
	assertRuleMissing(t, findings, "CR006")
}

func TestEvaluateWithBundleBooleanCompositionRules(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "proxy"}},
		},
		Services: []Service{
			{Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"}, Type: "LoadBalancer"},
			{Resource: ResourceRef{Kind: "Service", Namespace: "platform", Name: "proxy"}, Type: "ClusterIP"},
		},
		NetworkPolicies: []NetworkPolicy{
			{Resource: ResourceRef{Kind: "NetworkPolicy", Namespace: "platform", Name: "default-deny"}},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR007",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace needs network isolation",
				Severity:    SeverityHigh,
				Message:     "Namespace is exposed without network isolation.",
				Remediation: "Add network policies or reduce exposure.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "hasWorkloads", Op: "equals", Value: true},
					},
					Any: []Predicate{
						{Field: "hasPublicService", Op: "equals", Value: true},
						{Field: "serviceCount", Op: "greater_than", Value: 1},
					},
					Not: []Predicate{
						{Field: "hasNetworkPolicy", Op: "equals", Value: true},
					},
				},
			},
		},
	})

	finding := findRule(t, findings, "CR007")
	if finding.Resource.Name != "payments" {
		t.Fatalf("expected payments namespace to match, got %q", finding.Resource.Name)
	}
}

func TestEvaluateWithBundleNestedBooleanRules(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "worker"}},
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "proxy"}},
		},
		Services: []Service{
			{Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "api"}, Type: "ClusterIP"},
			{Resource: ResourceRef{Kind: "Service", Namespace: "payments", Name: "worker"}, Type: "ClusterIP"},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR008",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Nested namespace rule",
				Severity:    SeverityHigh,
				Message:     "Namespace matches nested boolean logic.",
				Remediation: "Reduce service exposure or add network policy coverage.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "hasWorkloads", Op: "equals", Value: true},
						{
							Any: []Predicate{
								{Field: "hasPublicService", Op: "equals", Value: true},
								{
									All: []Predicate{
										{Field: "serviceCount", Op: "greater_than", Value: 1},
										{Field: "networkPolicyCount", Op: "less_than", Value: 1},
									},
								},
							},
						},
					},
					Not: []Predicate{
						{
							All: []Predicate{
								{Field: "name", Op: "equals", Value: "platform"},
							},
						},
					},
				},
			},
		},
	})

	finding := findRule(t, findings, "CR008")
	if finding.Resource.Name != "payments" {
		t.Fatalf("expected nested boolean rule to match payments namespace, got %q", finding.Resource.Name)
	}
}

func TestEvaluateWithBundleServiceAccountCustomRules(t *testing.T) {
	trueValue := true
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource:                     ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				ServiceAccountName:           "api",
				AutomountServiceAccountToken: &trueValue,
			},
			{
				Resource:           ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "worker"},
				ServiceAccountName: "api",
			},
			{
				Resource:           ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "proxy"},
				ServiceAccountName: "proxy",
			},
		},
		Roles: []Role{
			{
				Resource: ResourceRef{Kind: "Role", Namespace: "payments", Name: "wildcard"},
				Rules: []PolicyRule{
					{Verbs: []string{"*"}, Resources: []string{"pods"}},
				},
			},
			{
				Resource: ResourceRef{Kind: "Role", Namespace: "payments", Name: "secret-reader"},
				Rules: []PolicyRule{
					{Verbs: []string{"get"}, Resources: []string{"secrets"}},
				},
			},
		},
		Bindings: []Binding{
			{
				Resource:    ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "wildcard-binding"},
				RoleRefKind: "Role",
				RoleRefName: "wildcard",
				Subjects: []Subject{
					{Kind: "ServiceAccount", Name: "api"},
				},
			},
			{
				Resource:    ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "secret-binding"},
				RoleRefKind: "Role",
				RoleRefName: "secret-reader",
				Subjects: []Subject{
					{Kind: "ServiceAccount", Name: "api"},
				},
			},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR009",
				Target:      "serviceAccount",
				Category:    CategoryIdentity,
				Title:       "Service account is highly privileged",
				Severity:    SeverityCritical,
				Message:     "Service account has risky workload and RBAC reachability.",
				Remediation: "Reduce RBAC and token exposure.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "workloadCount", Op: "greater_or_equal", Value: 2},
						{Field: "hasWildcardPermissions", Op: "equals", Value: true},
						{Field: "hasSecretReadPermissions", Op: "equals", Value: true},
						{Field: "hasAutomountingWorkloads", Op: "equals", Value: true},
					},
				},
			},
		},
	})

	finding := findRule(t, findings, "CR009")
	if finding.Resource.Kind != "ServiceAccount" {
		t.Fatalf("expected service account resource kind, got %q", finding.Resource.Kind)
	}
	if finding.Resource.Namespace != "payments" || finding.Resource.Name != "api" {
		t.Fatalf("expected payments/api service account, got %s/%s", finding.Resource.Namespace, finding.Resource.Name)
	}
	if got := finding.Evidence["workloadCount"]; got != 2 {
		t.Fatalf("expected workloadCount evidence 2, got %#v", got)
	}
	if got := finding.Evidence["hasSecretReadPermissions"]; got != true {
		t.Fatalf("expected secret read evidence true, got %#v", got)
	}
}

func TestEvaluateWithBundleNamespaceIsolationCustomRules(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
		},
		NetworkPolicies: []NetworkPolicy{
			{
				Resource:   ResourceRef{Kind: "NetworkPolicy", Namespace: "payments", Name: "default-deny"},
				HasIngress: true,
			},
		},
	}

	findings := EvaluateWithBundle(inventory, RuleBundle{
		CustomRules: []CustomRuleSpec{
			{
				ID:          "CR010",
				Target:      "namespace",
				Category:    CategoryExposure,
				Title:       "Namespace lacks egress isolation",
				Severity:    SeverityHigh,
				Message:     "Namespace does not have an egress-isolating NetworkPolicy.",
				Remediation: "Add egress controls.",
				Match: MatchClause{
					All: []Predicate{
						{Field: "hasWorkloads", Op: "equals", Value: true},
						{Field: "hasIngressPolicy", Op: "equals", Value: true},
						{Field: "hasEgressPolicy", Op: "equals", Value: false},
					},
				},
			},
		},
	})

	finding := findRule(t, findings, "CR010")
	if got := finding.Evidence["ingressPolicyCount"]; got != 1 {
		t.Fatalf("expected ingressPolicyCount evidence 1, got %#v", got)
	}
	if got := finding.Evidence["egressPolicyCount"]; got != 0 {
		t.Fatalf("expected egressPolicyCount evidence 0, got %#v", got)
	}
}

func TestEvaluateFindsReachableWildcardRBACBindings(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource:           ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				ServiceAccountName: "api",
			},
		},
		Roles: []Role{
			{
				Resource: ResourceRef{Kind: "Role", Namespace: "payments", Name: "wildcard"},
				Rules: []PolicyRule{
					{Verbs: []string{"*"}, Resources: []string{"secrets"}},
				},
			},
		},
		Bindings: []Binding{
			{
				Resource:    ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "api-admin"},
				RoleRefKind: "Role",
				RoleRefName: "wildcard",
				Subjects: []Subject{
					{Kind: "ServiceAccount", Name: "api"},
					{Kind: "User", Name: "alice@example.com"},
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileHardening)

	subjectFindingCount := 0
	for _, finding := range findings {
		if finding.RuleID == "KS016" {
			subjectFindingCount++
		}
	}
	if subjectFindingCount != 2 {
		t.Fatalf("expected 2 subject findings for KS016, got %d", subjectFindingCount)
	}

	workloadFinding := findRule(t, findings, "KS017")
	if workloadFinding.Resource.Name != "api" {
		t.Fatalf("expected workload api to be flagged, got %q", workloadFinding.Resource.Name)
	}
	if got := workloadFinding.Evidence["serviceAccountName"]; got != "api" {
		t.Fatalf("expected serviceAccountName evidence api, got %#v", got)
	}
}

func TestEvaluateFindsSecretExposureAndReachability(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource:           ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				ServiceAccountName: "api",
				SecretVolumes:      []string{"api-tls"},
				Containers: []Container{
					{
						Name:              "api",
						Image:             "ghcr.io/acme/api:1.0.0",
						SecretEnvRefs:     []SecretRef{{Name: "db-creds", Key: "password"}},
						SecretEnvFromRefs: []string{"shared-config"},
					},
				},
			},
		},
		Roles: []Role{
			{
				Resource: ResourceRef{Kind: "Role", Namespace: "payments", Name: "secret-reader"},
				Rules: []PolicyRule{
					{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}},
				},
			},
		},
		Bindings: []Binding{
			{
				Resource:    ResourceRef{Kind: "RoleBinding", Namespace: "payments", Name: "read-secrets"},
				RoleRefKind: "Role",
				RoleRefName: "secret-reader",
				Subjects: []Subject{
					{Kind: "ServiceAccount", Name: "api"},
					{Kind: "User", Name: "alice@example.com"},
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileHardening)

	assertRulePresent(t, findings, "KS018")
	assertRulePresent(t, findings, "KS019")
	assertRulePresent(t, findings, "KS020")
	assertRulePresent(t, findings, "KS021")
}

func TestEvaluateFindsClusterAdminBindingReachability(t *testing.T) {
	inventory := Inventory{
		Bindings: []Binding{
			{
				Resource:    ResourceRef{Kind: "ClusterRoleBinding", Name: "platform-admins"},
				RoleRefKind: "ClusterRole",
				RoleRefName: "cluster-admin",
				Subjects: []Subject{
					{Kind: "User", Name: "alice@example.com"},
					{Kind: "ServiceAccount", Namespace: "payments", Name: "default"},
				},
			},
		},
		Workloads: []Workload{
			{
				Resource:           ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				ServiceAccountName: "default",
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileHardening)

	clusterAdminFindings := 0
	for _, finding := range findings {
		if finding.RuleID == "KS026" {
			clusterAdminFindings++
		}
	}
	if clusterAdminFindings != 2 {
		t.Fatalf("expected 2 cluster-admin subject findings, got %d", clusterAdminFindings)
	}

	finding := findRule(t, findings, "KS027")
	if got := finding.Evidence["hasClusterAdminBinding"]; got != true {
		t.Fatalf("expected default service account evidence to include cluster-admin binding, got %#v", got)
	}
}

func TestEvaluateFindsWeakPodSecurityLabels(t *testing.T) {
	inventory := Inventory{
		Namespaces: []Namespace{
			{
				Resource: ResourceRef{Kind: "Namespace", Name: "payments"},
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "baseline",
					"pod-security.kubernetes.io/audit":   "restricted",
				},
			},
			{
				Resource: ResourceRef{Kind: "Namespace", Name: "platform"},
				Labels: map[string]string{
					"pod-security.kubernetes.io/enforce": "restricted",
					"pod-security.kubernetes.io/audit":   "restricted",
					"pod-security.kubernetes.io/warn":    "restricted",
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	finding := findRule(t, findings, "KS028")
	if finding.Resource.Name != "payments" {
		t.Fatalf("expected payments namespace to be flagged, got %q", finding.Resource.Name)
	}
}

func TestEvaluateFindsPlaintextCredentialLikeValues(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Containers: []Container{
					{
						Name: "api",
						EnvVars: []EnvVar{
							{Name: "DB_PASSWORD", Value: "super-secret"},
							{Name: "TOKEN_FILE", ValueFrom: "configMapKeyRef"},
						},
					},
				},
			},
		},
		ConfigMaps: []ConfigMap{
			{
				Resource: ResourceRef{Kind: "ConfigMap", Namespace: "payments", Name: "app-config"},
				Data: map[string]string{
					"api_token": "super-secret",
					"endpoint":  "https://internal.example",
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	plaintextFindings := 0
	for _, finding := range findings {
		if finding.RuleID == "KS029" {
			plaintextFindings++
		}
	}
	if plaintextFindings != 2 {
		t.Fatalf("expected 2 plaintext credential findings, got %d", plaintextFindings)
	}
}

func TestEvaluateFindsKnownSecretPatterns(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Containers: []Container{
					{
						Name: "api",
						EnvVars: []EnvVar{
							{Name: "APP_CONFIG", Value: "ghp_0123456789abcdef0123456789abcdef0123"},
						},
					},
				},
			},
		},
		ConfigMaps: []ConfigMap{
			{
				Resource: ResourceRef{Kind: "ConfigMap", Namespace: "payments", Name: "ssh-material"},
				Data: map[string]string{
					"id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n",
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	matched := 0
	for _, finding := range findings {
		if finding.RuleID == "KS029" {
			matched++
		}
	}
	if matched != 2 {
		t.Fatalf("expected 2 secret-pattern findings, got %d", matched)
	}
}

func TestEvaluateFindsIngressAndEgressIsolationGaps(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}},
			{Resource: ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "proxy"}},
		},
		NetworkPolicies: []NetworkPolicy{
			{
				Resource:   ResourceRef{Kind: "NetworkPolicy", Namespace: "platform", Name: "default-deny"},
				HasIngress: true,
			},
			{
				Resource:  ResourceRef{Kind: "NetworkPolicy", Namespace: "payments", Name: "egress-only"},
				HasEgress: true,
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	ingressFinding := findRule(t, findings, "KS030")
	if ingressFinding.Resource.Name != "payments" {
		t.Fatalf("expected payments ingress coverage gap, got %q", ingressFinding.Resource.Name)
	}

	egressFinding := findRule(t, findings, "KS031")
	if egressFinding.Resource.Name != "platform" {
		t.Fatalf("expected platform egress coverage gap, got %q", egressFinding.Resource.Name)
	}
}

func TestEvaluateFindsPublicRegistryImages(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Containers: []Container{
					{Name: "api", Image: "nginx:1.27.1"},
					{Name: "internal", Image: "registry.internal.example/team/api:1.0.0"},
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	finding := findRule(t, findings, "KS032")
	if finding.Evidence["implicitRegistry"] != true {
		t.Fatalf("expected implicit docker.io registry evidence, got %#v", finding.Evidence["implicitRegistry"])
	}
}

func TestEvaluateFindsSensitiveHostPathAndCombinationRules(t *testing.T) {
	trueValue := true
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Pod", Namespace: "payments", Name: "debug"},
				HostPID:  true,
				HostPathVolumes: []HostPathVolume{
					{Name: "root", Path: "/"},
				},
				Containers: []Container{
					{
						Name:       "shell",
						Image:      "busybox:1.36",
						Privileged: &trueValue,
					},
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	assertRulePresent(t, findings, "KS033")
	assertRulePresent(t, findings, "KS034")
	finding := findRule(t, findings, "KS035")
	hostPaths, ok := finding.Evidence["hostPaths"].([]map[string]any)
	if !ok || len(hostPaths) != 1 {
		t.Fatalf("expected one sensitive hostPath evidence entry, got %#v", finding.Evidence["hostPaths"])
	}
	if hostPaths[0]["classification"] != "host-root" {
		t.Fatalf("expected host-root classification, got %#v", hostPaths[0]["classification"])
	}
}

func TestEvaluateFindsControlPlaneSchedulingIndicators(t *testing.T) {
	inventory := Inventory{
		Workloads: []Workload{
			{
				Resource: ResourceRef{Kind: "Deployment", Namespace: "platform", Name: "etcd-auditor"},
				NodeName: "master-0",
			},
			{
				Resource: ResourceRef{Kind: "DaemonSet", Namespace: "platform", Name: "agent"},
				Tolerations: []Toleration{
					{Key: "node-role.kubernetes.io/control-plane", Operator: "Exists", Effect: "NoSchedule"},
				},
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	controlPlaneFindings := 0
	for _, finding := range findings {
		if finding.RuleID == "KS036" {
			controlPlaneFindings++
		}
	}
	if controlPlaneFindings != 2 {
		t.Fatalf("expected 2 control-plane scheduling findings, got %d", controlPlaneFindings)
	}
}

func TestEvaluateFindsNodeInfrastructureIssues(t *testing.T) {
	inventory := Inventory{
		Nodes: []Node{
			{
				Resource:         ResourceRef{Kind: "Node", Name: "cp-1"},
				Labels:           map[string]string{"node-role.kubernetes.io/control-plane": ""},
				Unschedulable:    false,
				ContainerRuntime: "docker://24.0.7",
				ExternalIPs:      []string{"203.0.113.10"},
				Ready:            true,
			},
			{
				Resource:         ResourceRef{Kind: "Node", Name: "cp-2"},
				Labels:           map[string]string{"node-role.kubernetes.io/control-plane": ""},
				Unschedulable:    true,
				ContainerRuntime: "containerd://1.7.18",
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileEnterprise)

	assertRulePresent(t, findings, "KS037")
	assertRulePresent(t, findings, "KS038")
	assertRulePresent(t, findings, "KS039")

	schedFinding := findRule(t, findings, "KS037")
	if schedFinding.Resource.Name != "cp-1" {
		t.Fatalf("expected cp-1 schedulable control-plane finding, got %q", schedFinding.Resource.Name)
	}

	dockerFinding := findRule(t, findings, "KS038")
	if dockerFinding.Evidence["containerRuntime"] != "docker://24.0.7" {
		t.Fatalf("expected docker runtime evidence, got %#v", dockerFinding.Evidence["containerRuntime"])
	}

	externalFinding := findRule(t, findings, "KS039")
	externalIPs, ok := externalFinding.Evidence["externalIPs"].([]string)
	if !ok || len(externalIPs) != 1 || externalIPs[0] != "203.0.113.10" {
		t.Fatalf("expected external IP evidence, got %#v", externalFinding.Evidence["externalIPs"])
	}
}

func TestEvaluateFindsNodeReadinessAndVersionSkewIssues(t *testing.T) {
	inventory := Inventory{
		Nodes: []Node{
			{
				Resource:         ResourceRef{Kind: "Node", Name: "node-a"},
				Ready:            false,
				ContainerRuntime: "containerd://1.7.18",
				KubeletVersion:   "v1.31.2",
				KubeProxyVersion: "v1.31.2",
			},
			{
				Resource:         ResourceRef{Kind: "Node", Name: "node-b"},
				Ready:            true,
				ContainerRuntime: "containerd://1.7.18",
				KubeletVersion:   "v1.30.9",
				KubeProxyVersion: "v1.30.9",
			},
		},
		Components: []ClusterComponent{
			{
				Resource:  ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-a"},
				Name:      "kube-apiserver",
				Version:   "v1.31.2",
				Ecosystem: "kubernetes",
			},
			{
				Resource:  ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-b"},
				Name:      "kube-apiserver",
				Version:   "v1.30.9",
				Ecosystem: "kubernetes",
			},
			{
				Resource:  ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-scheduler-a"},
				Name:      "kube-scheduler",
				Version:   "v1.31.2",
				Ecosystem: "kubernetes",
			},
			{
				Resource:  ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-scheduler-b"},
				Name:      "kube-scheduler",
				Version:   "v1.31.2",
				Ecosystem: "kubernetes",
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileHardening)

	assertRulePresent(t, findings, "KS040")
	assertRulePresent(t, findings, "KS041")
	assertRulePresent(t, findings, "KS042")
	assertRulePresent(t, findings, "KS043")

	notReadyFinding := findRule(t, findings, "KS040")
	if notReadyFinding.Resource.Name != "node-a" {
		t.Fatalf("expected node-a NotReady finding, got %q", notReadyFinding.Resource.Name)
	}

	kubeletFinding := findRule(t, findings, "KS041")
	if kubeletFinding.Resource.Kind != "Cluster" {
		t.Fatalf("expected cluster-scoped kubelet skew finding, got %q", kubeletFinding.Resource.Kind)
	}
	if kubeletFinding.Evidence["component"] != "kubelet" {
		t.Fatalf("expected kubelet component evidence, got %#v", kubeletFinding.Evidence["component"])
	}
	if kubeletFinding.Evidence["versionCount"] != 2 {
		t.Fatalf("expected kubelet versionCount 2, got %#v", kubeletFinding.Evidence["versionCount"])
	}

	kubeProxyFinding := findRule(t, findings, "KS042")
	if kubeProxyFinding.Evidence["component"] != "kube-proxy" {
		t.Fatalf("expected kube-proxy component evidence, got %#v", kubeProxyFinding.Evidence["component"])
	}

	controlPlaneFinding := findRule(t, findings, "KS043")
	if controlPlaneFinding.Evidence["component"] != "kube-apiserver" {
		t.Fatalf("expected kube-apiserver control-plane skew evidence, got %#v", controlPlaneFinding.Evidence["component"])
	}
	if controlPlaneFinding.Evidence["versionCount"] != 2 {
		t.Fatalf("expected control-plane versionCount 2, got %#v", controlPlaneFinding.Evidence["versionCount"])
	}
}

func TestEvaluateFindsNodePressureAndNetworkIssues(t *testing.T) {
	inventory := Inventory{
		Nodes: []Node{
			{
				Resource:           ResourceRef{Kind: "Node", Name: "node-a"},
				Ready:              true,
				MemoryPressure:     true,
				NetworkUnavailable: true,
				KubeletVersion:     "v1.31.2",
				ContainerRuntime:   "containerd://1.7.18",
				ExternalIPs:        []string{"203.0.113.20"},
			},
			{
				Resource:         ResourceRef{Kind: "Node", Name: "node-b"},
				Ready:            true,
				DiskPressure:     false,
				PIDPressure:      false,
				KubeletVersion:   "v1.31.2",
				ContainerRuntime: "containerd://1.7.18",
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileHardening)

	assertRulePresent(t, findings, "KS044")
	assertRulePresent(t, findings, "KS045")

	pressureFinding := findRule(t, findings, "KS044")
	if pressureFinding.Resource.Name != "node-a" {
		t.Fatalf("expected node-a pressure finding, got %q", pressureFinding.Resource.Name)
	}
	pressures, ok := pressureFinding.Evidence["pressures"].([]string)
	if !ok || len(pressures) != 1 || pressures[0] != "MemoryPressure" {
		t.Fatalf("expected memory pressure evidence, got %#v", pressureFinding.Evidence["pressures"])
	}

	networkFinding := findRule(t, findings, "KS045")
	if networkFinding.Resource.Name != "node-a" {
		t.Fatalf("expected node-a network unavailable finding, got %q", networkFinding.Resource.Name)
	}
	if networkFinding.Evidence["networkUnavailable"] != true {
		t.Fatalf("expected networkUnavailable evidence true, got %#v", networkFinding.Evidence["networkUnavailable"])
	}
}

func TestEvaluateFindsKubeletConfigurationIssues(t *testing.T) {
	trueValue := true
	falseValue := false
	readOnlyPort := int32(10255)

	inventory := Inventory{
		Nodes: []Node{
			{
				Resource:                            ResourceRef{Kind: "Node", Name: "node-a"},
				KubeletConfigPath:                   "/var/lib/kubelet/config.yaml",
				KubeletAnonymousAuthEnabled:         &trueValue,
				KubeletWebhookAuthenticationEnabled: &falseValue,
				KubeletAuthorizationMode:            "AlwaysAllow",
				KubeletAuthenticationX509ClientCAFile: "",
				KubeletReadOnlyPort:                 &readOnlyPort,
				KubeletProtectKernelDefaults:        &falseValue,
				KubeletFailSwapOn:                   &falseValue,
				KubeletRotateCertificates:           &falseValue,
				KubeletServerTLSBootstrap:           &falseValue,
				KubeletSeccompDefault:               &falseValue,
			},
		},
	}

	findings := EvaluateWithProfile(inventory, RuleProfileHardening)

	assertRulePresent(t, findings, "KS046")
	assertRulePresent(t, findings, "KS047")
	assertRulePresent(t, findings, "KS048")
	assertRulePresent(t, findings, "KS049")
	assertRulePresent(t, findings, "KS050")
	assertRulePresent(t, findings, "KS051")
	assertRulePresent(t, findings, "KS052")
	assertRulePresent(t, findings, "KS053")
	assertRulePresent(t, findings, "KS054")
	assertRulePresent(t, findings, "KS055")

	anonFinding := findRule(t, findings, "KS046")
	if anonFinding.Evidence["anonymousAuthEnabled"] != true {
		t.Fatalf("expected anonymousAuthEnabled evidence true, got %#v", anonFinding.Evidence["anonymousAuthEnabled"])
	}

	authzFinding := findRule(t, findings, "KS048")
	if authzFinding.Evidence["authorizationMode"] != "AlwaysAllow" {
		t.Fatalf("expected authorization mode evidence, got %#v", authzFinding.Evidence["authorizationMode"])
	}

	roFinding := findRule(t, findings, "KS049")
	if roFinding.Evidence["readOnlyPort"] != int32(10255) {
		t.Fatalf("expected readOnlyPort evidence 10255, got %#v", roFinding.Evidence["readOnlyPort"])
	}
	seccompFinding := findRule(t, findings, "KS053")
	if seccompFinding.Evidence["seccompDefault"] != false {
		t.Fatalf("expected seccompDefault evidence false, got %#v", seccompFinding.Evidence["seccompDefault"])
	}
	failSwapFinding := findRule(t, findings, "KS055")
	if failSwapFinding.Evidence["failSwapOn"] != false {
		t.Fatalf("expected failSwapOn evidence false, got %#v", failSwapFinding.Evidence["failSwapOn"])
	}
}

func assertRulePresent(t *testing.T, findings []Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected finding for rule %s", ruleID)
}

func assertRuleMissing(t *testing.T, findings []Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			t.Fatalf("did not expect finding for rule %s", ruleID)
		}
	}
}

func findRule(t *testing.T, findings []Finding, ruleID string) Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return finding
		}
	}
	t.Fatalf("expected finding for rule %s", ruleID)
	return Finding{}
}
