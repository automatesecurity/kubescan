package vuln

import "testing"

func TestNormalizePackageName(t *testing.T) {
	if got := normalizePackageName("pypi", "Jinja2_Legacy.Name"); got != "jinja2-legacy-name" {
		t.Fatalf("unexpected pypi normalization %q", got)
	}
	if got := normalizePackageName("npm", "@Scope/Package"); got != "@scope/package" {
		t.Fatalf("unexpected npm normalization %q", got)
	}
}
