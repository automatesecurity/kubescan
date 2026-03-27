package vulndb

import "testing"

func TestLoadKubernetesOfficialCVEFeedBytesParsesOSVAndText(t *testing.T) {
	content := []byte("{\n" +
		"  \"items\": [\n" +
		"    {\n" +
		"      \"id\": \"CVE-2026-1000\",\n" +
		"      \"summary\": \"Kubelet issue\",\n" +
		"      \"content_text\": \"### Affected Versions\\n- kubelet: <= v1.32.1\\n\\n### Fixed Versions\\n- kubelet: >= v1.32.2\\n\"\n" +
		"    },\n" +
		"    {\n" +
		"      \"id\": \"CVE-2026-1001\",\n" +
		"      \"summary\": \"apiserver issue\",\n" +
		"      \"content_text\": \"```json osv\\n{\\n  \\\"schema_version\\\":\\\"1.6.0\\\",\\n  \\\"id\\\":\\\"CVE-2026-1001\\\",\\n  \\\"summary\\\":\\\"apiserver issue\\\",\\n  \\\"affected\\\":[{\\\"package\\\":{\\\"ecosystem\\\":\\\"Kubernetes\\\",\\\"name\\\":\\\"kube-apiserver\\\"},\\\"ranges\\\":[{\\\"type\\\":\\\"SEMVER\\\",\\\"events\\\":[{\\\"introduced\\\":\\\"0\\\"},{\\\"fixed\\\":\\\"v1.33.4\\\"}]}]}]\\n}\\n```\"\n" +
		"    }\n" +
		"  ]\n" +
		"}")

	bundle, err := LoadKubernetesOfficialCVEFeedBytes(content)
	if err != nil {
		t.Fatalf("LoadKubernetesOfficialCVEFeedBytes returned error: %v", err)
	}
	if len(bundle.Advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(bundle.Advisories))
	}
	if bundle.Advisories[0].PackageName != "kubelet" || bundle.Advisories[0].AffectedVersions[0] != "<=1.32.1" || bundle.Advisories[0].FixedVersion != "1.32.2" {
		t.Fatalf("unexpected text advisory %+v", bundle.Advisories[0])
	}
	if bundle.Advisories[1].Ecosystem != "kubernetes" || bundle.Advisories[1].PackageName != "kube-apiserver" {
		t.Fatalf("unexpected osv advisory %+v", bundle.Advisories[1])
	}
}
