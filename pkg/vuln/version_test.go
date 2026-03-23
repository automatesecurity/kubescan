package vuln

import "testing"

func TestComparePackageVersionsDebian(t *testing.T) {
	cases := []struct {
		left  string
		right string
		want  int
	}{
		{left: "1:1.0-1", right: "1.0-9", want: 1},
		{left: "1.0~beta1-1", right: "1.0-1", want: -1},
		{left: "1.0-2", right: "1.0-10", want: -1},
		{left: "2.0-1", right: "2.0-1", want: 0},
	}

	for _, tc := range cases {
		assertComparison(t, comparePackageVersions("deb", tc.left, tc.right), tc.want, tc.left, tc.right)
	}
}

func TestComparePackageVersionsRPMAndAPK(t *testing.T) {
	cases := []struct {
		ecosystem string
		left      string
		right     string
		want      int
	}{
		{ecosystem: "rpm", left: "1.1.1-2", right: "1.1.1-10", want: -1},
		{ecosystem: "rpm", left: "1.0~beta1", right: "1.0", want: -1},
		{ecosystem: "rpm", left: "1.0^git1", right: "1.0", want: 1},
		{ecosystem: "apk", left: "1.1.1-r0", right: "1.1.1-r1", want: -1},
		{ecosystem: "apk", left: "1.36.0-r10", right: "1.36.0-r2", want: 1},
	}

	for _, tc := range cases {
		assertComparison(t, comparePackageVersions(tc.ecosystem, tc.left, tc.right), tc.want, tc.left, tc.right)
	}
}

func TestMatchesAffectedVersion(t *testing.T) {
	cases := []struct {
		ecosystem   string
		version     string
		expressions []string
		want        bool
	}{
		{ecosystem: "apk", version: "1.1.1-r0", expressions: []string{"=1.1.1-r0"}, want: true},
		{ecosystem: "apk", version: "1.1.1-r0", expressions: []string{">=1.1.1-r0,<1.1.1-r2"}, want: true},
		{ecosystem: "apk", version: "1.1.1-r2", expressions: []string{">=1.1.1-r0,<1.1.1-r2"}, want: false},
		{ecosystem: "deb", version: "1.0~beta1-1", expressions: []string{"<1.0-1"}, want: true},
		{ecosystem: "rpm", version: "1.0^git1", expressions: []string{">1.0"}, want: true},
	}

	for _, tc := range cases {
		got, err := matchesAffectedVersion(tc.ecosystem, tc.version, tc.expressions)
		if err != nil {
			t.Fatalf("matchesAffectedVersion(%q, %q, %v) returned error: %v", tc.ecosystem, tc.version, tc.expressions, err)
		}
		if got != tc.want {
			t.Fatalf("matchesAffectedVersion(%q, %q, %v) = %v, want %v", tc.ecosystem, tc.version, tc.expressions, got, tc.want)
		}
	}
}

func assertComparison(t *testing.T, got, want int, left, right string) {
	t.Helper()
	switch {
	case want < 0 && got >= 0:
		t.Fatalf("comparison(%q, %q) = %d, want negative", left, right, got)
	case want > 0 && got <= 0:
		t.Fatalf("comparison(%q, %q) = %d, want positive", left, right, got)
	case want == 0 && got != 0:
		t.Fatalf("comparison(%q, %q) = %d, want 0", left, right, got)
	}
}
