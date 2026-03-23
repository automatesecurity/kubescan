package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"kubescan/api/v1alpha1"
	"kubescan/internal/buildinfo"
	"kubescan/pkg/k8s"
	"kubescan/pkg/nodecollector"
)

var nodeReportGVR = schema.GroupVersionResource{
	Group:    v1alpha1.GroupName,
	Version:  v1alpha1.Version,
	Resource: "nodereports",
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 1 {
		switch args[0] {
		case "version", "--version", "-v":
			return writeVersion(os.Stdout, "kubescan-node-collector")
		}
	}

	fs := flag.NewFlagSet("kubescan-node-collector", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	interval := fs.Duration("interval", 15*time.Minute, "collection interval")
	hostRoot := fs.String("host-root", "/host", "mounted host root used to resolve kubelet config files")
	kubeletConfigPath := fs.String("kubelet-config", "/var/lib/kubelet/config.yaml", "host kubelet config path to inspect")
	nodeName := fs.String("node-name", os.Getenv("NODE_NAME"), "node name for the generated NodeReport")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig file")
	contextName := fs.String("context", "", "kubeconfig context to use")
	once := fs.Bool("once", false, "run one collection cycle and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*nodeName) == "" {
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Fprintf(os.Stderr, "determine node name: %v\n", err)
			return 2
		}
		*nodeName = hostname
	}

	config, err := k8s.RESTConfigFromOptions(k8s.ClusterOptions{
		Kubeconfig: *kubeconfig,
		Context:    *contextName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "build kubernetes config: %v\n", err)
		return 1
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create dynamic client: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runOnce := func() error {
		report := collectNodeReport(strings.TrimSpace(*nodeName), *hostRoot, *kubeletConfigPath, time.Now().UTC())
		return upsertNodeReport(ctx, client, report)
	}

	if *once {
		if err := runOnce(); err != nil {
			fmt.Fprintf(os.Stderr, "collect node report: %v\n", err)
			return 1
		}
		return 0
	}

	if err := runOnce(); err != nil {
		fmt.Fprintf(os.Stderr, "collect node report: %v\n", err)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
			if err := runOnce(); err != nil {
				fmt.Fprintf(os.Stderr, "collect node report: %v\n", err)
			}
		}
	}
}

func collectNodeReport(nodeName string, hostRoot string, kubeletConfigPath string, now time.Time) v1alpha1.NodeReport {
	observations, err := nodecollector.LoadKubeletObservations(nodeName, hostRoot, kubeletConfigPath)
	if err != nil {
		return nodecollector.BuildNodeReportError(nodeName, kubeletConfigPath, now, err)
	}
	return nodecollector.BuildNodeReport(observations, now)
}

func upsertNodeReport(ctx context.Context, client dynamic.Interface, reportObject v1alpha1.NodeReport) error {
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&reportObject)
	if err != nil {
		return fmt.Errorf("encode node report: %w", err)
	}
	resource := client.Resource(nodeReportGVR)
	unstructuredObject := &unstructured.Unstructured{Object: object}

	existing, err := resource.Get(ctx, reportObject.Metadata.Name, metav1.GetOptions{})
	if err == nil {
		unstructuredObject.SetResourceVersion(existing.GetResourceVersion())
		if _, err := resource.Update(ctx, unstructuredObject, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update node report: %w", err)
		}
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get node report: %w", err)
	}
	if _, err := resource.Create(ctx, unstructuredObject, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create node report: %w", err)
	}
	return nil
}

func writeVersion(w io.Writer, name string) int {
	_, _ = fmt.Fprintln(w, buildinfo.Current(name).String())
	return 0
}
