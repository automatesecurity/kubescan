package nodecollector

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"kubescan/api/v1alpha1"
)

type KubeletObservations struct {
	NodeName                       string
	KubeletConfigPath              string
	AnonymousAuthEnabled           *bool
	WebhookAuthenticationEnabled   *bool
	AuthorizationMode              string
	AuthenticationX509ClientCAFile string
	ReadOnlyPort                   *int32
	ProtectKernelDefaults          *bool
	FailSwapOn                     *bool
	RotateCertificates             *bool
	ServerTLSBootstrap             *bool
	SeccompDefault                 *bool
}

type kubeletConfiguration struct {
	Authentication struct {
		Anonymous struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"anonymous"`
		Webhook struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"webhook"`
		X509 struct {
			ClientCAFile string `yaml:"clientCAFile"`
		} `yaml:"x509"`
	} `yaml:"authentication"`
	Authorization struct {
		Mode string `yaml:"mode"`
	} `yaml:"authorization"`
	ReadOnlyPort          *int32 `yaml:"readOnlyPort"`
	ProtectKernelDefaults *bool  `yaml:"protectKernelDefaults"`
	FailSwapOn            *bool  `yaml:"failSwapOn"`
	RotateCertificates    *bool  `yaml:"rotateCertificates"`
	ServerTLSBootstrap    *bool  `yaml:"serverTLSBootstrap"`
	SeccompDefault        *bool  `yaml:"seccompDefault"`
}

func LoadKubeletObservations(nodeName string, hostRoot string, kubeletConfigPath string) (KubeletObservations, error) {
	resolvedPath := resolveHostPath(hostRoot, kubeletConfigPath)
	content, err := os.ReadFile(resolvedPath)
	if err != nil {
		return KubeletObservations{}, fmt.Errorf("read kubelet config %s: %w", resolvedPath, err)
	}

	var config kubeletConfiguration
	if err := yaml.Unmarshal(content, &config); err != nil {
		return KubeletObservations{}, fmt.Errorf("parse kubelet config %s: %w", resolvedPath, err)
	}

	return KubeletObservations{
		NodeName:                       strings.TrimSpace(nodeName),
		KubeletConfigPath:              normalizeConfigPath(kubeletConfigPath),
		AnonymousAuthEnabled:           cloneBoolPointer(config.Authentication.Anonymous.Enabled),
		WebhookAuthenticationEnabled:   cloneBoolPointer(config.Authentication.Webhook.Enabled),
		AuthorizationMode:              strings.TrimSpace(config.Authorization.Mode),
		AuthenticationX509ClientCAFile: strings.TrimSpace(config.Authentication.X509.ClientCAFile),
		ReadOnlyPort:                   cloneInt32Pointer(config.ReadOnlyPort),
		ProtectKernelDefaults:          cloneBoolPointer(config.ProtectKernelDefaults),
		FailSwapOn:                     cloneBoolPointer(config.FailSwapOn),
		RotateCertificates:             cloneBoolPointer(config.RotateCertificates),
		ServerTLSBootstrap:             cloneBoolPointer(config.ServerTLSBootstrap),
		SeccompDefault:                 cloneBoolPointer(config.SeccompDefault),
	}, nil
}

func BuildNodeReport(observations KubeletObservations, now time.Time) v1alpha1.NodeReport {
	generatedAt := metav1.NewTime(now.UTC())
	return v1alpha1.NodeReport{
		APIVersion: v1alpha1.GroupName + "/" + v1alpha1.Version,
		Kind:       v1alpha1.NodeReportKind,
		Metadata: metav1.ObjectMeta{
			Name: observations.NodeName,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "kubescan-node-collector",
				"app.kubernetes.io/managed-by": "kubescan",
			},
		},
		Spec: v1alpha1.NodeReportSpec{
			NodeName:                       observations.NodeName,
			KubeletConfigPath:              observations.KubeletConfigPath,
			AnonymousAuthEnabled:           cloneBoolPointer(observations.AnonymousAuthEnabled),
			WebhookAuthenticationEnabled:   cloneBoolPointer(observations.WebhookAuthenticationEnabled),
			AuthorizationMode:              observations.AuthorizationMode,
			AuthenticationX509ClientCAFile: observations.AuthenticationX509ClientCAFile,
			ReadOnlyPort:                   cloneInt32Pointer(observations.ReadOnlyPort),
			ProtectKernelDefaults:          cloneBoolPointer(observations.ProtectKernelDefaults),
			FailSwapOn:                     cloneBoolPointer(observations.FailSwapOn),
			RotateCertificates:             cloneBoolPointer(observations.RotateCertificates),
			ServerTLSBootstrap:             cloneBoolPointer(observations.ServerTLSBootstrap),
			SeccompDefault:                 cloneBoolPointer(observations.SeccompDefault),
		},
		Status: v1alpha1.NodeReportStatus{
			Phase:       "Ready",
			GeneratedAt: &generatedAt,
		},
	}
}

func BuildNodeReportError(nodeName string, kubeletConfigPath string, now time.Time, err error) v1alpha1.NodeReport {
	generatedAt := metav1.NewTime(now.UTC())
	return v1alpha1.NodeReport{
		APIVersion: v1alpha1.GroupName + "/" + v1alpha1.Version,
		Kind:       v1alpha1.NodeReportKind,
		Metadata: metav1.ObjectMeta{
			Name: strings.TrimSpace(nodeName),
			Labels: map[string]string{
				"app.kubernetes.io/name":       "kubescan-node-collector",
				"app.kubernetes.io/managed-by": "kubescan",
			},
		},
		Spec: v1alpha1.NodeReportSpec{
			NodeName:          strings.TrimSpace(nodeName),
			KubeletConfigPath: normalizeConfigPath(kubeletConfigPath),
		},
		Status: v1alpha1.NodeReportStatus{
			Phase:       "Error",
			GeneratedAt: &generatedAt,
			LastError:   err.Error(),
		},
	}
}

func resolveHostPath(hostRoot string, kubeletConfigPath string) string {
	cleanRoot := filepath.Clean(strings.TrimSpace(hostRoot))
	if cleanRoot == "" || cleanRoot == "." {
		cleanRoot = string(filepath.Separator)
	}
	cleanConfig := normalizeConfigPath(kubeletConfigPath)
	if cleanRoot == string(filepath.Separator) {
		return filepath.Clean(cleanConfig)
	}
	return filepath.Join(cleanRoot, strings.TrimPrefix(cleanConfig, string(filepath.Separator)))
}

func normalizeConfigPath(configPath string) string {
	trimmed := strings.TrimSpace(configPath)
	if trimmed == "" {
		return "/var/lib/kubelet/config.yaml"
	}
	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	if strings.HasPrefix(normalized, "/") {
		return path.Clean(normalized)
	}
	return path.Clean("/" + normalized)
}

func cloneBoolPointer(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt32Pointer(value *int32) *int32 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
