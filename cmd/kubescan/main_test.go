package main

import (
	"bytes"
	"strings"
	"testing"

	"kubescan/internal/buildinfo"
)

func TestWriteVersion(t *testing.T) {
	previousVersion := buildinfo.Version
	previousCommit := buildinfo.Commit
	previousDate := buildinfo.Date
	t.Cleanup(func() {
		buildinfo.Version = previousVersion
		buildinfo.Commit = previousCommit
		buildinfo.Date = previousDate
	})

	buildinfo.Version = "1.2.3"
	buildinfo.Commit = "abc123"
	buildinfo.Date = "2026-03-21T12:00:00Z"

	var buffer bytes.Buffer
	exitCode := writeVersion(&buffer, "kubescan")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(buffer.String(), "kubescan version 1.2.3") {
		t.Fatalf("expected version output, got %q", buffer.String())
	}
}
