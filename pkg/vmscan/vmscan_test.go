package vmscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTargetFromRootFS(t *testing.T) {
	root := t.TempDir()
	target, err := ResolveTarget(root, "")
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	defer target.Cleanup()
	if target.RootFSPath != root {
		t.Fatalf("unexpected rootfs path %q", target.RootFSPath)
	}
}

func TestResolveTargetFromTarArchive(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "vm-rootfs.tar.gz")
	if err := writeTarGz(archivePath, map[string]string{
		"etc/os-release": "NAME=test\n",
		"var/lib/dpkg/status": "Package: libc6\nStatus: install ok installed\nVersion: 2.36-1\n\n",
	}); err != nil {
		t.Fatalf("writeTarGz returned error: %v", err)
	}

	target, err := ResolveTarget("", archivePath)
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	defer target.Cleanup()
	if _, err := os.Stat(filepath.Join(target.RootFSPath, "etc", "os-release")); err != nil {
		t.Fatalf("expected extracted rootfs file, got %v", err)
	}
}

func TestDetectDiskFormat(t *testing.T) {
	if got := detectDiskFormat("image.qcow2"); got != "disk" {
		t.Fatalf("expected qcow2 disk format, got %q", got)
	}
	if got := detectDiskFormat("image.ova"); got != "archive" {
		t.Fatalf("expected ova archive format, got %q", got)
	}
}

func writeTarGz(path string, files map[string]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gzw := gzip.NewWriter(file)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()
	for name, content := range files {
		data := []byte(content)
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := bytes.NewReader(data).WriteTo(tw); err != nil {
			return err
		}
	}
	return nil
}
