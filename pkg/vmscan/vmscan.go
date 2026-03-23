package vmscan

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"kubescan/pkg/filescan"
	"kubescan/pkg/imagescan"
	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"
)

var (
	lookPath = exec.LookPath
	runCmd   = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return nil
	}
)

type ResolvedTarget struct {
	RootFSPath string
	SourceRef  string
	Cleanup    func()
}

func ResolveTarget(rootfsPath string, diskPath string) (ResolvedTarget, error) {
	rootfs := strings.TrimSpace(rootfsPath)
	disk := strings.TrimSpace(diskPath)
	switch {
	case rootfs != "" && disk != "":
		return ResolvedTarget{}, fmt.Errorf("--rootfs and --disk cannot be used together")
	case rootfs != "":
		cleaned := filepath.Clean(rootfs)
		info, err := os.Stat(cleaned)
		if err != nil {
			return ResolvedTarget{}, fmt.Errorf("stat rootfs: %w", err)
		}
		if !info.IsDir() {
			return ResolvedTarget{}, fmt.Errorf("rootfs path must be a directory")
		}
		return ResolvedTarget{RootFSPath: cleaned, SourceRef: cleaned, Cleanup: func() {}}, nil
	case disk != "":
		return resolveDiskTarget(disk)
	default:
		return ResolvedTarget{}, fmt.Errorf("either --rootfs or --disk is required")
	}
}

func ScanResolvedRootFS(target ResolvedTarget, profile policy.RuleProfile, now time.Time, options filescan.Options) ([]policy.Finding, error) {
	result, err := filescan.ScanPathWithOptions(target.RootFSPath, profile, now, options)
	if err != nil {
		return nil, err
	}
	return result.Findings, nil
}

func ExtractSBOM(target ResolvedTarget) (vuln.SBOM, error) {
	cleaned := filepath.Clean(strings.TrimSpace(target.RootFSPath))
	if cleaned == "" {
		return vuln.SBOM{}, fmt.Errorf("rootfs path is required")
	}
	sourceRef := strings.TrimSpace(target.SourceRef)
	if sourceRef == "" {
		sourceRef = cleaned
	}
	return imagescan.ExtractRootFSSBOM(cleaned, sourceRef)
}

func resolveDiskTarget(diskPath string) (ResolvedTarget, error) {
	cleaned := filepath.Clean(strings.TrimSpace(diskPath))
	if cleaned == "" {
		return ResolvedTarget{}, fmt.Errorf("disk path is required")
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("stat disk: %w", err)
	}
	if info.IsDir() {
		return ResolvedTarget{RootFSPath: cleaned, SourceRef: cleaned, Cleanup: func() {}}, nil
	}

	switch detectDiskFormat(cleaned) {
	case "archive":
		rootfs, cleanup, err := extractArchiveTarget(cleaned)
		if err != nil {
			return ResolvedTarget{}, err
		}
		return ResolvedTarget{RootFSPath: rootfs, SourceRef: cleaned, Cleanup: cleanup}, nil
	case "disk":
		rootfs, cleanup, err := mountDiskImage(cleaned)
		if err != nil {
			return ResolvedTarget{}, err
		}
		return ResolvedTarget{RootFSPath: rootfs, SourceRef: cleaned, Cleanup: cleanup}, nil
	default:
		return ResolvedTarget{}, fmt.Errorf("unsupported VM input format for %s", cleaned)
	}
}

func detectDiskFormat(path string) string {
	lower := strings.ToLower(strings.TrimSpace(path))
	switch {
	case strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".ova"):
		return "archive"
	case strings.HasSuffix(lower, ".qcow2"), strings.HasSuffix(lower, ".vmdk"), strings.HasSuffix(lower, ".vhd"), strings.HasSuffix(lower, ".vhdx"), strings.HasSuffix(lower, ".raw"), strings.HasSuffix(lower, ".img"):
		return "disk"
	default:
		return ""
	}
}

func extractArchiveTarget(archivePath string) (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "kubescan-vm-archive-")
	if err != nil {
		return "", nil, fmt.Errorf("create archive temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }

	if err := untarFile(archivePath, tempDir); err != nil {
		cleanup()
		return "", nil, err
	}
	if strings.EqualFold(filepath.Ext(archivePath), ".ova") {
		if nested, ok := firstNestedDisk(tempDir); ok {
			rootfs, mountCleanup, err := mountDiskImage(nested)
			if err != nil {
				cleanup()
				return "", nil, err
			}
			return rootfs, func() {
				mountCleanup()
				cleanup()
			}, nil
		}
	}
	return tempDir, cleanup, nil
}

func untarFile(archivePath string, targetDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(strings.ToLower(archivePath), ".gz") || strings.HasSuffix(strings.ToLower(archivePath), ".tgz") {
		gzr, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip archive: %w", err)
		}
		defer gzr.Close()
		reader = gzr
	}

	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		targetPath := filepath.Join(targetDir, filepath.FromSlash(header.Name))
		cleaned := filepath.Clean(targetPath)
		if !strings.HasPrefix(cleaned, filepath.Clean(targetDir)+string(filepath.Separator)) && cleaned != filepath.Clean(targetDir) {
			return fmt.Errorf("archive entry escapes target dir: %s", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleaned, 0o755); err != nil {
				return fmt.Errorf("create archive directory %s: %w", header.Name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(cleaned), 0o755); err != nil {
				return fmt.Errorf("create archive parent %s: %w", header.Name, err)
			}
			out, err := os.OpenFile(cleaned, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("create archive file %s: %w", header.Name, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return fmt.Errorf("extract archive file %s: %w", header.Name, err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("close archive file %s: %w", header.Name, err)
			}
		}
	}
	return nil
}

func firstNestedDisk(root string) (string, bool) {
	var match string
	_ = filepath.WalkDir(root, func(current string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if detectDiskFormat(current) == "disk" {
			match = current
			return io.EOF
		}
		return nil
	})
	return match, match != ""
}

func mountDiskImage(diskPath string) (string, func(), error) {
	if _, err := lookPath("guestmount"); err != nil {
		return "", nil, fmt.Errorf("guestmount is required for VM disk image scanning (%w)", err)
	}
	if _, err := lookPath("guestunmount"); err != nil {
		return "", nil, fmt.Errorf("guestunmount is required for VM disk image scanning (%w)", err)
	}
	mountDir, err := os.MkdirTemp("", "kubescan-vm-mount-")
	if err != nil {
		return "", nil, fmt.Errorf("create mount dir: %w", err)
	}
	if err := runCmd("guestmount", "--ro", "-a", diskPath, "-i", mountDir); err != nil {
		_ = os.RemoveAll(mountDir)
		return "", nil, fmt.Errorf("mount VM disk image: %w", err)
	}
	cleanup := func() {
		_ = runCmd("guestunmount", mountDir)
		_ = os.RemoveAll(mountDir)
	}
	return mountDir, cleanup, nil
}
