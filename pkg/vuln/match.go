package vuln

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"kubescan/pkg/policy"
)

func MatchInventory(inventory policy.Inventory, sboms SBOMIndex, advisories AdvisoryBundle, now time.Time) []policy.Finding {
	var findings []policy.Finding

	for _, workload := range inventory.Workloads {
		for _, container := range workload.Containers {
			sbom, ok := findSBOMForContainer(sboms, container)
			if !ok {
				continue
			}
			for _, pkg := range sbom.Packages {
				for _, advisory := range advisories.Advisories {
					if !advisoryMatchesPackage(advisory, pkg) {
						continue
					}
					findings = append(findings, makeFinding(workload.Resource, container.Name, container.Image, pkg, advisory, now))
				}
			}
		}
	}

	return findings
}

func MatchClusterComponents(inventory policy.Inventory, advisories AdvisoryBundle, now time.Time) []policy.Finding {
	var findings []policy.Finding

	for _, component := range inventory.Components {
		pkg := Package{
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: component.Ecosystem,
		}
		for _, advisory := range advisories.Advisories {
			if !advisoryMatchesPackage(advisory, pkg) {
				continue
			}
			findings = append(findings, makeComponentFinding(component, advisory, now))
		}
	}

	return findings
}

func MatchImage(resource policy.ResourceRef, imageRef string, sbom SBOM, advisories AdvisoryBundle, now time.Time) []policy.Finding {
	var findings []policy.Finding
	for _, pkg := range sbom.Packages {
		for _, advisory := range advisories.Advisories {
			if !advisoryMatchesPackage(advisory, pkg) {
				continue
			}
			findings = append(findings, makeImageFinding(resource, imageRef, pkg, advisory, now))
		}
	}
	return findings
}

func advisoryMatchesPackage(advisory Advisory, pkg Package) bool {
	if normalizePackageName(advisory.Ecosystem, advisory.PackageName) != normalizePackageName(pkg.Ecosystem, pkg.Name) {
		return false
	}
	if advisory.Ecosystem != pkg.Ecosystem {
		return false
	}
	match, err := matchesAffectedVersion(pkg.Ecosystem, pkg.Version, advisory.AffectedVersions)
	if err != nil {
		return false
	}
	return match
}

func normalizeImageRef(value string) string {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(trimmed, "docker-pullable://"):
		trimmed = strings.TrimPrefix(trimmed, "docker-pullable://")
	case strings.HasPrefix(trimmed, "docker://"):
		trimmed = strings.TrimPrefix(trimmed, "docker://")
	case strings.HasPrefix(trimmed, "containerd://"):
		trimmed = strings.TrimPrefix(trimmed, "containerd://")
	case strings.HasPrefix(trimmed, "cri-o://"):
		trimmed = strings.TrimPrefix(trimmed, "cri-o://")
	}
	return trimmed
}

func findSBOMForContainer(sboms SBOMIndex, container policy.Container) (SBOM, bool) {
	for _, key := range containerImageCandidates(container) {
		sbom, ok := sboms[key]
		if ok {
			return sbom, true
		}
	}
	return SBOM{}, false
}

func containerImageCandidates(container policy.Container) []string {
	seen := map[string]struct{}{}
	var candidates []string
	add := func(value string) {
		normalized := normalizeImageRef(value)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		candidates = append(candidates, normalized)
	}

	add(container.ImageDigest)
	if digest := digestOnly(container.ImageDigest); digest != "" {
		add(joinImageAndDigest(container.Image, digest))
	}
	if digest := digestOnly(container.Image); digest != "" {
		add(container.Image)
		add(joinImageAndDigest(container.Image, digest))
	}
	add(container.Image)
	return candidates
}

func digestOnly(value string) string {
	normalized := normalizeImageRef(value)
	if at := strings.Index(normalized, "@"); at >= 0 && at+1 < len(normalized) {
		return normalized[at+1:]
	}
	return ""
}

func joinImageAndDigest(imageRef, digest string) string {
	normalized := normalizeImageRef(imageRef)
	digest = strings.TrimSpace(digest)
	if normalized == "" || digest == "" {
		return ""
	}
	if strings.Contains(normalized, "@") {
		return normalized
	}
	repo := imageRepository(normalized)
	if repo == "" {
		return ""
	}
	return repo + "@" + digest
}

func imageRepository(imageRef string) string {
	normalized := normalizeImageRef(imageRef)
	if at := strings.Index(normalized, "@"); at >= 0 {
		return normalized[:at]
	}
	lastSlash := strings.LastIndex(normalized, "/")
	lastColon := strings.LastIndex(normalized, ":")
	if lastColon > lastSlash {
		return normalized[:lastColon]
	}
	return normalized
}

func makeFinding(resource policy.ResourceRef, containerName, image string, pkg Package, advisory Advisory, now time.Time) policy.Finding {
	message := fmt.Sprintf("%s/%s container %q image %q contains vulnerable package %s %s (%s)", resource.Kind, resource.Name, containerName, image, pkg.Name, pkg.Version, advisory.ID)
	sum := sha1.Sum([]byte(strings.Join([]string{
		string(policy.CategoryVuln),
		advisory.ID,
		resource.Kind,
		resource.Namespace,
		resource.Name,
		containerName,
		pkg.Name,
		pkg.Version,
	}, "|")))

	remediation := "Upgrade or replace the affected package."
	if advisory.FixedVersion != "" {
		remediation = "Upgrade " + pkg.Name + " to " + advisory.FixedVersion + " or later in the rebuilt image."
	}

	return policy.Finding{
		ID:          hex.EncodeToString(sum[:8]),
		Category:    policy.CategoryVuln,
		RuleID:      advisory.ID,
		Title:       advisory.Summary,
		Severity:    advisory.Severity,
		RuleVersion: "advisory/v1alpha1",
		Resource:    resource,
		Message:     message,
		Evidence: map[string]any{
			"container":      containerName,
			"image":          image,
			"packageName":    pkg.Name,
			"packageVersion": pkg.Version,
			"ecosystem":      pkg.Ecosystem,
			"aliases":        advisory.Aliases,
			"fixedVersion":   advisory.FixedVersion,
		},
		Remediation: remediation,
		Timestamp:   now.UTC(),
	}
}

func makeComponentFinding(component policy.ClusterComponent, advisory Advisory, now time.Time) policy.Finding {
	message := fmt.Sprintf("%s/%s cluster component %q version %q is affected by %s", component.Resource.Kind, component.Resource.Name, component.Name, component.Version, advisory.ID)
	sum := sha1.Sum([]byte(strings.Join([]string{
		string(policy.CategoryVuln),
		advisory.ID,
		component.Resource.Kind,
		component.Resource.Namespace,
		component.Resource.Name,
		component.Name,
		component.Version,
		component.Source,
	}, "|")))

	remediation := "Upgrade the affected Kubernetes component."
	if advisory.FixedVersion != "" {
		remediation = "Upgrade " + component.Name + " to " + advisory.FixedVersion + " or later."
	}

	return policy.Finding{
		ID:          hex.EncodeToString(sum[:8]),
		Category:    policy.CategoryVuln,
		RuleID:      advisory.ID,
		Title:       advisory.Summary,
		Severity:    advisory.Severity,
		RuleVersion: "advisory/v1alpha1",
		Resource:    component.Resource,
		Message:     message,
		Evidence: map[string]any{
			"componentName":    component.Name,
			"componentVersion": component.Version,
			"ecosystem":        component.Ecosystem,
			"aliases":          advisory.Aliases,
			"fixedVersion":     advisory.FixedVersion,
			"source":           component.Source,
		},
		Remediation: remediation,
		Timestamp:   now.UTC(),
	}
}

func makeImageFinding(resource policy.ResourceRef, imageRef string, pkg Package, advisory Advisory, now time.Time) policy.Finding {
	message := fmt.Sprintf("%s/%s image %q contains vulnerable package %s %s (%s)", resource.Kind, resource.Name, imageRef, pkg.Name, pkg.Version, advisory.ID)
	sum := sha1.Sum([]byte(strings.Join([]string{
		string(policy.CategoryVuln),
		advisory.ID,
		resource.Kind,
		resource.Namespace,
		resource.Name,
		imageRef,
		pkg.Name,
		pkg.Version,
	}, "|")))

	remediation := "Upgrade or replace the affected package."
	if advisory.FixedVersion != "" {
		remediation = "Upgrade " + pkg.Name + " to " + advisory.FixedVersion + " or later in the rebuilt image."
	}

	return policy.Finding{
		ID:          hex.EncodeToString(sum[:8]),
		Category:    policy.CategoryVuln,
		RuleID:      advisory.ID,
		Title:       advisory.Summary,
		Severity:    advisory.Severity,
		RuleVersion: "advisory/v1alpha1",
		Resource:    resource,
		Message:     message,
		Evidence: map[string]any{
			"image":          imageRef,
			"packageName":    pkg.Name,
			"packageVersion": pkg.Version,
			"ecosystem":      pkg.Ecosystem,
			"aliases":        advisory.Aliases,
			"fixedVersion":   advisory.FixedVersion,
		},
		Remediation: remediation,
		Timestamp:   now.UTC(),
	}
}
