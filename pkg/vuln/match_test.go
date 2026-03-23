package vuln

import (
	"testing"
	"time"

	"kubescan/pkg/policy"
)

func TestMatchInventory(t *testing.T) {
	inventory := policy.Inventory{
		Workloads: []policy.Workload{
			{
				Resource: policy.ResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"},
				Containers: []policy.Container{
					{Name: "api", Image: "ghcr.io/acme/api:1.0.0"},
					{Name: "worker", Image: "ghcr.io/acme/worker:2.0.0"},
				},
			},
		},
	}

	sboms := SBOMIndex{
		"ghcr.io/acme/api:1.0.0": {
			ImageRef: "ghcr.io/acme/api:1.0.0",
			Packages: []Package{
				{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
			},
		},
		"ghcr.io/acme/worker:2.0.0": {
			ImageRef: "ghcr.io/acme/worker:2.0.0",
			Packages: []Package{
				{Name: "busybox", Version: "1.36.0-r0", Ecosystem: "apk"},
			},
		},
	}

	advisories := AdvisoryBundle{
		Advisories: []Advisory{
			{
				ID:               "CVE-2026-0001",
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
				FixedVersion:     "1.1.1-r1",
				Severity:         policy.SeverityHigh,
				Summary:          "OpenSSL vulnerable package",
			},
			{
				ID:               "CVE-2026-0002",
				PackageName:      "busybox",
				Ecosystem:        "apk",
				AffectedVersions: []string{"<1.36.0-r2"},
				FixedVersion:     "1.36.0-r2",
				Severity:         policy.SeverityMedium,
				Summary:          "Busybox vulnerable package",
			},
		},
	}

	findings := MatchInventory(inventory, sboms, advisories, time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC))
	if got := len(findings); got != 2 {
		t.Fatalf("expected 2 findings, got %d", got)
	}
	for _, finding := range findings {
		if finding.Category != policy.CategoryVuln {
			t.Fatalf("expected vuln category, got %s", finding.Category)
		}
	}
	if findings[0].RuleID != "CVE-2026-0001" && findings[1].RuleID != "CVE-2026-0001" {
		t.Fatalf("expected CVE-2026-0001 finding")
	}
	if findings[0].RuleID != "CVE-2026-0002" && findings[1].RuleID != "CVE-2026-0002" {
		t.Fatalf("expected CVE-2026-0002 finding")
	}
}

func TestMatchClusterComponents(t *testing.T) {
	inventory := policy.Inventory{
		Components: []policy.ClusterComponent{
			{
				Resource:  policy.ResourceRef{Kind: "Node", Name: "worker-1"},
				Name:      "kubelet",
				Version:   "v1.31.1",
				Ecosystem: "kubernetes",
				Source:    "node.status.nodeInfo.kubeletVersion",
			},
			{
				Resource:  policy.ResourceRef{Kind: "Pod", Namespace: "kube-system", Name: "kube-apiserver-control-plane"},
				Name:      "kube-apiserver",
				Version:   "v1.31.1",
				Ecosystem: "kubernetes",
				Source:    "pod.spec.containers[].image",
			},
		},
	}

	advisories := AdvisoryBundle{
		Advisories: []Advisory{
			{
				ID:               "CVE-2026-2001",
				PackageName:      "kubelet",
				Ecosystem:        "kubernetes",
				AffectedVersions: []string{">=v1.31.0,<v1.31.3"},
				FixedVersion:     "v1.31.3",
				Severity:         policy.SeverityHigh,
				Summary:          "Kubelet vulnerability",
			},
			{
				ID:               "CVE-2026-2002",
				PackageName:      "kube-apiserver",
				Ecosystem:        "kubernetes",
				AffectedVersions: []string{"<=v1.31.1"},
				FixedVersion:     "v1.31.2",
				Severity:         policy.SeverityCritical,
				Summary:          "API server vulnerability",
			},
		},
	}

	findings := MatchClusterComponents(inventory, advisories, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if got := len(findings); got != 2 {
		t.Fatalf("expected 2 findings, got %d", got)
	}
	if findings[0].Category != policy.CategoryVuln || findings[1].Category != policy.CategoryVuln {
		t.Fatalf("expected vuln category findings, got %+v", findings)
	}
	if findings[0].RuleID != "CVE-2026-2001" && findings[1].RuleID != "CVE-2026-2001" {
		t.Fatalf("expected kubelet advisory finding, got %+v", findings)
	}
	if findings[0].RuleID != "CVE-2026-2002" && findings[1].RuleID != "CVE-2026-2002" {
		t.Fatalf("expected kube-apiserver advisory finding, got %+v", findings)
	}
}

func TestMatchImage(t *testing.T) {
	resource := policy.ResourceRef{Kind: "Image", Name: "ghcr.io/acme/api:1.0.0"}
	sbom := SBOM{
		ImageRef: "ghcr.io/acme/api:1.0.0",
		Packages: []Package{
			{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
		},
	}
	advisories := AdvisoryBundle{
		Advisories: []Advisory{
			{
				ID:               "CVE-2026-0001",
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{">=1.1.1-r0,<1.1.1-r2"},
				FixedVersion:     "1.1.1-r1",
				Severity:         policy.SeverityHigh,
				Summary:          "OpenSSL vulnerable package",
			},
		},
	}

	findings := MatchImage(resource, "ghcr.io/acme/api:1.0.0", sbom, advisories, time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC))
	if got := len(findings); got != 1 {
		t.Fatalf("expected 1 finding, got %d", got)
	}
	if findings[0].Resource.Kind != "Image" {
		t.Fatalf("expected image resource, got %+v", findings[0].Resource)
	}
	if findings[0].RuleID != "CVE-2026-0001" {
		t.Fatalf("expected CVE-2026-0001 finding, got %+v", findings[0])
	}
}

func TestMatchInventoryUsesDigestAwareCorrelation(t *testing.T) {
	inventory := policy.Inventory{
		Workloads: []policy.Workload{
			{
				Resource: policy.ResourceRef{Kind: "Pod", Namespace: "payments", Name: "api"},
				Containers: []policy.Container{
					{
						Name:        "api",
						Image:       "ghcr.io/acme/api:1.0.0",
						ImageDigest: "docker-pullable://ghcr.io/acme/api@sha256:deadbeef",
					},
				},
			},
		},
	}
	sboms := SBOMIndex{
		"ghcr.io/acme/api@sha256:deadbeef": {
			ImageRef: "ghcr.io/acme/api@sha256:deadbeef",
			Packages: []Package{
				{Name: "openssl", Version: "1.1.1-r0", Ecosystem: "apk"},
			},
		},
	}
	advisories := AdvisoryBundle{
		Advisories: []Advisory{
			{
				ID:               "CVE-2026-1111",
				PackageName:      "openssl",
				Ecosystem:        "apk",
				AffectedVersions: []string{"=1.1.1-r0"},
				Severity:         policy.SeverityHigh,
				Summary:          "Digest matched advisory",
			},
		},
	}

	findings := MatchInventory(inventory, sboms, advisories, time.Date(2026, 3, 21, 13, 0, 0, 0, time.UTC))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "CVE-2026-1111" {
		t.Fatalf("expected digest-matched advisory, got %+v", findings[0])
	}
}
