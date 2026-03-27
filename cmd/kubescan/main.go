package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"kubescan/internal/buildinfo"
	"kubescan/pkg/cli"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: kubescan scan [--input <file> | --helm-chart <dir> [--helm-values <file> ...] [--helm-release <name>] [--helm-namespace <ns>] | --kustomize-dir <dir> | live-cluster flags] [--profile <name>] [--include-kind <kind> ...] [--exclude-kind <kind> ...] [--include-namespace <ns> ...] [--exclude-namespace <ns> ...] [--policy <file> | --policy-bundle <file> --bundle-key <file>] [--rules-bundle <file> --bundle-key <file>] [(--sbom <file> ... | --component-vulns) (--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>)] [--compliance <profile>] [--report all|summary] [--color auto|always|never] [--attack-paths] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stderr, "       live-cluster flags: [--kubeconfig <file>] [--context <name>] [--namespace <ns>]")
		fmt.Fprintln(os.Stderr, "       kubescan image --image <ref> [--registry-username <user> (--registry-password <pass> | --registry-password-stdin) | --registry-token <token>] [--scan-layers] [--secret-scan patterns|balanced|aggressive] [--license-allow <id> ...] [--license-deny <id> ...] [--sbom-out <file>] [--sbom-format cyclonedx|spdx] [(--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>) [--sbom <file>]] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stderr, "       kubescan fs --path <dir> [--profile <name>] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--secret-scan patterns|balanced|aggressive] [--report all|summary] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stderr, "       kubescan repo [--path <dir> | --url <git-url> [--ref <ref>] [--provider-native] [--sparse-path <pattern> ...] [--git-http-header <header> ...] [--git-ssh-command <command>]] [--profile <name>] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--secret-scan patterns|balanced|aggressive] [--report all|summary] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stderr, "       kubescan vm [--rootfs <dir> | --disk <path>] [--profile <name>] [--secret-scan patterns|balanced|aggressive] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--sbom-out <file>] [--sbom-format cyclonedx|spdx] [(--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>)] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stderr, "       kubescan verify bundle --bundle <file> --key <public-key>")
		fmt.Fprintln(os.Stderr, "       kubescan db build [--source-manifest <file> | --advisories <file> | --advisories-bundle <file> --bundle-key <file>] [--osv <file-or-url> ...] --out <file> [--metadata-out <file>] [--signature-out <file> --signing-key <file>]")
		fmt.Fprintln(os.Stderr, "       kubescan db info --db <file> [--format table|json]")
		fmt.Fprintln(os.Stderr, "       kubescan db verify --db <file> [--metadata <file>] [--signature <file> --key <public-key>]")
		fmt.Fprintln(os.Stderr, "       kubescan db update --url <url> --out <file> [--metadata-url <url>] [--signature-url <url> --key <public-key>]")
		return 2
	}

	switch args[0] {
	case "scan":
		return cli.RunScan(args[1:], os.Stdout, os.Stderr)
	case "image":
		return cli.RunImage(args[1:], os.Stdout, os.Stderr)
	case "fs":
		return cli.RunFS(args[1:], os.Stdout, os.Stderr)
	case "repo":
		return cli.RunRepo(args[1:], os.Stdout, os.Stderr)
	case "vm":
		return cli.RunVM(args[1:], os.Stdout, os.Stderr)
	case "verify":
		return cli.RunVerify(args[1:], os.Stdout, os.Stderr)
	case "db":
		return cli.RunDB(args[1:], os.Stdout, os.Stderr)
	case "version", "--version", "-v":
		return writeVersion(os.Stdout, "kubescan")
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, "usage: kubescan scan [--input <file> | --helm-chart <dir> [--helm-values <file> ...] [--helm-release <name>] [--helm-namespace <ns>] | --kustomize-dir <dir> | live-cluster flags] [--profile <name>] [--include-kind <kind> ...] [--exclude-kind <kind> ...] [--include-namespace <ns> ...] [--exclude-namespace <ns> ...] [--policy <file> | --policy-bundle <file> --bundle-key <file>] [--rules-bundle <file> --bundle-key <file>] [(--sbom <file> ... | --component-vulns) (--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>)] [--compliance <profile>] [--report all|summary] [--color auto|always|never] [--attack-paths] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stdout, "       live-cluster flags: [--kubeconfig <file>] [--context <name>] [--namespace <ns>]")
		fmt.Fprintln(os.Stdout, "       kubescan image --image <ref> [--registry-username <user> (--registry-password <pass> | --registry-password-stdin) | --registry-token <token>] [--scan-layers] [--secret-scan patterns|balanced|aggressive] [--license-allow <id> ...] [--license-deny <id> ...] [--sbom-out <file>] [--sbom-format cyclonedx|spdx] [(--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>) [--sbom <file>]] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stdout, "       kubescan fs --path <dir> [--profile <name>] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--secret-scan patterns|balanced|aggressive] [--report all|summary] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stdout, "       kubescan repo [--path <dir> | --url <git-url> [--ref <ref>] [--provider-native] [--sparse-path <pattern> ...] [--git-http-header <header> ...] [--git-ssh-command <command>]] [--profile <name>] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--secret-scan patterns|balanced|aggressive] [--report all|summary] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stdout, "       kubescan vm [--rootfs <dir> | --disk <path>] [--profile <name>] [--secret-scan patterns|balanced|aggressive] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--sbom-out <file>] [--sbom-format cyclonedx|spdx] [(--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>)] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]")
		fmt.Fprintln(os.Stdout, "       kubescan verify bundle --bundle <file> --key <public-key>")
		fmt.Fprintln(os.Stdout, "       kubescan db build [--source-manifest <file> | --advisories <file> | --advisories-bundle <file> --bundle-key <file>] [--osv <file-or-url> ...] --out <file> [--metadata-out <file>] [--signature-out <file> --signing-key <file>]")
		fmt.Fprintln(os.Stdout, "       kubescan db info --db <file> [--format table|json]")
		fmt.Fprintln(os.Stdout, "       kubescan db verify --db <file> [--metadata <file>] [--signature <file> --key <public-key>]")
		fmt.Fprintln(os.Stdout, "       kubescan db update --url <url> --out <file> [--metadata-url <url>] [--signature-url <url> --key <public-key>]")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		flag.Usage()
		return 2
	}
}

func writeVersion(w io.Writer, name string) int {
	_, _ = fmt.Fprintln(w, buildinfo.Current(name).String())
	return 0
}
