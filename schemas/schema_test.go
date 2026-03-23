package schemas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckedInSchemasHaveExpectedContractMarkers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path         string
		id           string
		title        string
		apiVersion   string
		kind         string
		apiVersionIn bool
	}{
		{
			path:         "report.automatesecurity.github.io_scan-result_v1.schema.json",
			id:           "https://automatesecurity.github.io/kubescan/schemas/report.automatesecurity.github.io/scan-result/v1",
			title:        "Kubescan Scan Result",
			apiVersion:   "report.automatesecurity.github.io/v1",
			kind:         "ScanResult",
			apiVersionIn: true,
		},
		{
			path:         "kubescan.automatesecurity.github.io_policy-controls_v1alpha1.schema.json",
			id:           "https://automatesecurity.github.io/kubescan/schemas/kubescan.automatesecurity.github.io/policy-controls/v1alpha1",
			title:        "Kubescan Policy Controls",
			apiVersion:   "kubescan.automatesecurity.github.io/v1alpha1",
			kind:         "PolicyControls",
			apiVersionIn: true,
		},
		{
			path:         "kubescan.automatesecurity.github.io_rule-bundle_v1alpha1.schema.json",
			id:           "https://automatesecurity.github.io/kubescan/schemas/kubescan.automatesecurity.github.io/rule-bundle/v1alpha1",
			title:        "Kubescan Rule Bundle",
			apiVersion:   "kubescan.automatesecurity.github.io/v1alpha1",
			kind:         "RuleBundle",
			apiVersionIn: true,
		},
		{
			path:         "kubescan.automatesecurity.github.io_advisory-bundle_v1alpha1.schema.json",
			id:           "https://automatesecurity.github.io/kubescan/schemas/kubescan.automatesecurity.github.io/advisory-bundle/v1alpha1",
			title:        "Kubescan Advisory Bundle",
			apiVersion:   "kubescan.automatesecurity.github.io/v1alpha1",
			kind:         "AdvisoryBundle",
			apiVersionIn: true,
		},
		{
			path:         "kubescan.automatesecurity.github.io_signed-bundle_v1alpha1.schema.json",
			id:           "https://automatesecurity.github.io/kubescan/schemas/kubescan.automatesecurity.github.io/signed-bundle/v1alpha1",
			title:        "Kubescan Signed Bundle Envelope",
			kind:         "SignedBundle",
			apiVersionIn: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			document := loadSchema(t, tc.path)
			if got := stringValue(document["$schema"]); got != "https://json-schema.org/draft/2020-12/schema" {
				t.Fatalf("unexpected $schema %q", got)
			}
			if got := stringValue(document["$id"]); got != tc.id {
				t.Fatalf("unexpected $id %q", got)
			}
			if got := stringValue(document["title"]); got != tc.title {
				t.Fatalf("unexpected title %q", got)
			}

			properties := nestedMap(t, document, "properties")
			if tc.apiVersionIn {
				apiVersion := nestedMap(t, properties, "apiVersion")
				if got := stringValue(apiVersion["const"]); got != tc.apiVersion {
					t.Fatalf("unexpected apiVersion const %q", got)
				}
			}
			kind := nestedMap(t, properties, "kind")
			if got := stringValue(kind["const"]); got != tc.kind {
				t.Fatalf("unexpected kind const %q", got)
			}
		})
	}
}

func loadSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	return document
}

func nestedMap(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	nested, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("expected nested object at %q", key)
	}
	return nested
}

func stringValue(value any) string {
	typed, _ := value.(string)
	return typed
}

