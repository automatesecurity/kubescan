package buildinfo

import "testing"

func TestCurrentBuildInfoString(t *testing.T) {
	previousVersion := Version
	previousCommit := Commit
	previousDate := Date
	t.Cleanup(func() {
		Version = previousVersion
		Commit = previousCommit
		Date = previousDate
	})

	Version = "1.2.3"
	Commit = "abc123"
	Date = "2026-03-21T12:00:00Z"

	info := Current("kubescan")
	if got := info.String(); got != "kubescan version 1.2.3 (commit=abc123 date=2026-03-21T12:00:00Z)" {
		t.Fatalf("unexpected build info string %q", got)
	}
}
