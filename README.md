# Kubescan

Kubescan is a Kubernetes-focused security analysis tool for deterministic posture, relationship, vulnerability, and attack-path scanning across live clusters, manifests, images, repositories, and filesystem inputs. It is designed to give operators and security teams a high-signal view of Kubernetes risk with versioned machine-readable output, signed policy inputs, and an architecture that works in both CLI and in-cluster operator mode.

Kubescan is not a general-purpose cloud security platform, runtime detection/response product, or exploit-prevention system. It does not try to replace admission control, node/runtime enforcement, or broad multi-cloud CSPM tooling. Its scope is to analyze and report Kubernetes-centric risk clearly and predictably, while leaving active prevention, runtime blocking, and non-Kubernetes platform enforcement to other systems.

The current implementation is an early foundation slice. It supports:
- Manifest-based scanning from YAML files
- Local filesystem and repository path scanning
- Broader secret scanning across local files, manifests, ConfigMaps, and image environment variables
- Declared project-license policy checks for local filesystem and repository scans
- Live cluster collection through `client-go`
- A built-in misconfiguration ruleset
- Initial vulnerability correlation from CycloneDX or SPDX SBOM input plus advisory bundles or local vulnerability databases
- Live control-plane and node vulnerability correlation from cluster component versions plus advisory bundles or local vulnerability databases
- Signed advisory bundle verification with Ed25519
- Signed policy bundle verification with Ed25519
- Signed rule bundle verification with Ed25519
- Declarative custom rules inside signed rule bundles
- Namespace-level relationship-aware custom rules through derived aggregate fields
- Numeric comparison operators for custom rules
- Boolean composition with `all`, `any`, and `not` in custom rules
- RBAC relationship analysis for subjects and service accounts reachable from wildcard bindings
- Secret exposure analysis for workload secret consumption and secret-read RBAC reachability
- Namespace Pod Security Admission posture and plaintext credential detection
- Built-in rule profiles for default, hardening, and enterprise scans
- Compliance profile evaluation with profile-oriented summaries
- Scan scoping controls and summary reporting
- Rendered Helm chart and Kustomize directory scan sources
- Policy-file based suppressions and severity overrides
- SARIF output
- HTML reporting
- File export with `--out`
- Threshold-based exit codes with `--fail-on`
- Human-readable table and HTML output
- JSON output for automation
- Graph-based attack path analysis with curated Kubernetes path detectors
- OCSF `1.8.0` JSON export for posture, vulnerability, and compliance results
- Stable versioned JSON scan output with explicit schema markers
- Local SQLite vulnerability database artifacts with metadata, detached signatures, reusable advisory caching, and initial OSV, Alpine SecDB, Debian Security Tracker, Ubuntu Security Notices, and Kubernetes official CVE-feed upstream-ingestion support

It does not yet implement arbitrary graph-style rule expressions or SBOM formats beyond CycloneDX JSON and SPDX JSON.

## Kubescan vs Trivy

The table below compares Kubescan's current shipped feature set with Trivy's documented capabilities as of March 21, 2026. It is intentionally Kubernetes-focused rather than a full product comparison, since Trivy also covers many non-Kubernetes targets that Kubescan does not.

| Capability | Kubescan | Trivy | Notes |
|---|---|---|---|
| Kubernetes manifest scanning | Yes | Yes | Kubescan scans manifests directly; Trivy documents Kubernetes resource and cluster scanning. |
| Live Kubernetes cluster scanning | Yes | Yes | Trivy `k8s` is documented as experimental. |
| Kubernetes misconfiguration scanning | Yes | Yes | Both support built-in posture checks. |
| Kubernetes vulnerability scanning | Yes | Yes | Kubescan correlates workload images with supplied SBOM/advisories and can match live control-plane/node component versions against advisories; Trivy scans images and Kubernetes components directly. |
| Kubernetes secret scanning | Partial | Yes | Kubescan covers Secret references and plaintext credential heuristics; Trivy documents exposed secret scanning. |
| RBAC relationship analysis | Yes | Partial | Kubescan has subject/service-account blast-radius findings; Trivy documents RBAC reporting in broader operator/reporting ecosystems, but not Kubescan-style relationship-aware attack-path reporting. |
| Attack-path analysis | Yes | No documented equivalent | Kubescan has in-memory Kubernetes attack-path analysis; no equivalent feature is documented in Trivy's current Kubernetes docs. |
| Signed policy/rule/advisory bundles | Yes | No documented equivalent | This is currently a Kubescan-specific trust/distribution model. |
| Compliance reporting | Yes | Yes | Both support compliance-oriented output. |
| SARIF for Kubernetes scan output | Yes | No documented support for `trivy k8s` | Trivy supports SARIF generally, but current Kubernetes docs list `table` and `json` for `trivy k8s`. |
| OCSF export | Yes | No documented equivalent | Kubescan exports OCSF `1.8.0` JSON for posture, vuln, and compliance results. |
| Include/exclude kinds and namespaces | Yes | Yes | Both document resource scoping controls. |
| Summary reporting for cluster-scale scans | Yes | Yes | Both support summary-style output. |
| Control-plane and node vulnerability scanning | Yes | Yes | Kubescan matches kubelet, kube-proxy, kube-apiserver, kube-controller-manager, kube-scheduler, and etcd versions against advisory bundles when visible from the cluster API. |
| Node configuration / infrastructure assessment | Partial | Yes | Kubescan now includes completed API-visible Phase 1A checks plus an optional Phase 1B node collector for kubelet config posture such as anonymous auth, webhook authn/authz, read-only port exposure, cert rotation, server TLS bootstrap, seccomp defaulting, and kernel-default protection; Trivy still documents broader infrastructure/CIS-style assessment depth. |
| Continuous in-cluster operator mode | Partial | Yes | Kubescan now includes a reporting-focused operator with periodic scans, watch-triggered debounced rescans, affected-scope policy reconciliation, signed bundle/SBOM sources, delta notifications, and bounded trend history; Trivy documents a broader mature operator ecosystem. |
| Multi-target breadth outside Kubernetes | Partial | Yes | Kubescan now supports direct image, filesystem, local/remote repository, VM rootfs scanning, and direct VM disk or appliance inputs, but still lacks Trivy's broader VM/image/provider depth. |

Primary Trivy sources for this comparison:
- [Trivy README](https://github.com/aquasecurity/trivy)
- [Trivy Kubernetes docs](https://trivy.dev/docs/latest/target/kubernetes/)
- [Trivy Reporting docs](https://trivy.dev/latest/docs/configuration/reporting/)
- [Trivy documentation overview](https://trivy.dev/latest/docs)

## Current Status

Kubescan is in active development.

Implemented today:
- Direct OCI container image scanning with `kubescan image`
- Unpacked OCI image-layer scanning for secrets and declared licenses
- Native Alpine, Debian, and RPM package inventory extraction from image layers
- Local filesystem scanning with `kubescan fs`
- Local repository scanning with `kubescan repo`
- Reusable secret detection for known token patterns, private keys, and high-signal plaintext secret assignments
- License allowlist and denylist policy checks for declared project licenses in common package manifests
- CLI entrypoint with `scan`
- CLI bundle verification with `verify bundle`
- Kubernetes inventory collection from manifests or kubeconfig
- Normalized internal inventory and finding models
- High-value workload, exposure, identity, and hygiene checks
- Initial image-to-SBOM-to-advisory vulnerability matching
- Live node and control-plane component vulnerability matching from node versions and `kube-system` pod images
- Signed advisory bundle verification during scans
- Signed policy bundle verification during scans
- Signed rule bundle verification during scans
- Declarative custom rule evaluation for container, workload, service, and namespace targets
- RBAC relationship findings for bound subjects and workloads using over-privileged service accounts
- Secret exposure findings for env-var injection, Secret volumes, and secret-read reachability
- Namespace Pod Security Admission label findings and plaintext credential-like values in env vars and ConfigMaps
- Static escalation-path checks aligned with Bishop Fox's Bad Pods research
- In-memory Kubernetes attack graph analysis with attack-path reporting
- Initial API-visible node configuration and infrastructure assessment for live cluster scans
- Completed Phase 1A API-visible node and control-plane posture checks for live cluster scans, including readiness, pressure, network availability, external exposure, scheduling posture, runtime posture, and version-skew assessment across kubelet, kube-proxy, and visible control-plane components
- Completed Phase 1B optional node-collector support with `NodeReport` ingestion and deeper kubelet configuration checks from host-mounted kubelet config files, including x509 client CA posture and swap-fail behavior
- Initial continuous in-cluster operator mode with periodic scans, watch-triggered debounced rescans, affected-scope policy reconciliation where possible, and CRD-backed report storage
- Completed Phase 2A reporting-focused in-cluster operator support with periodic scans and CRD-backed report storage
- Completed Phase 2B watch-triggered debounced rescans with namespace- and kind-aware policy routing inside affected scopes
- Per-reconcile `ScanReport.status.delta` summaries with added/removed/severity-changed findings, attack-path deltas, and per-resource change counts
- Delta-driven operator notifications through Kubernetes Events and optional webhook delivery from `ScanPolicy.spec.notification`
- Slack-compatible webhook notifications plus severity-gated operator delta delivery
- Bounded rolling trend/history summaries in `ScanReport.status.trend` for recent reconciliations, including recent highest severity, consecutive clean/error runs, and latest count deltas
- Operator-side refresh intervals and change tracking for remote `HTTP`, `OCIImage`, and provider-native `GitHubReleaseAsset` SBOM sources
- Operator report lifecycle controls including stale-report pruning, optional TTL cleanup, source-status reporting, and cached signed-bundle fallback with `bundleFailurePolicy: use-last-good`
- Remote operator workload SBOM resolution from `HTTP`, `OCIImage`, `SBOMReport`, `ConfigMap`, and `Secret` sources with secret-backed auth options
- Initial VM root filesystem scanning with `kubescan vm --rootfs`
- Direct VM disk, appliance, and archive resolution through `kubescan vm --disk`
- Native VM/rootfs SBOM extraction and advisory matching from mounted or extracted filesystems
- SPDX JSON SBOM export alongside CycloneDX for image and VM/rootfs inventory output
- Expanded native package inventory extraction for Go modules, Maven, Cargo, Composer, and NuGet lockfiles in image and VM/rootfs scans
- Provider-native GitHub repository retrieval plus sparse remote-repository checkout controls for large repo scans
- Built-in rule profile selection to keep default scans high-signal while preserving a broader enterprise catalog
- Compliance summaries for built-in profiles such as `k8s-cis`, `nsa`, and `pss-restricted`
- Resource kind and namespace scoping with summary-only reporting for larger scans
- Scoped suppressions and severity overrides from a YAML controls file
- SARIF reporting and file export
- Severity-threshold exit handling for CI
- Unit tests for parsing, collection, rules, CLI routing, and reporting
- Repeatable benchmark coverage for large-inventory rule evaluation, attack-path analysis, and JSON result serialization
- OCSF export for application security posture, vulnerability, and compliance findings
- Stable `report.automatesecurity.github.io/v1` scan-result JSON contract with explicit schema markers
- Versioned build metadata, multi-platform binary packaging, release workflows, and container build artifacts for `kubescan`, `kubescan-operator`, and `kubescan-node-collector`
- Sigstore-signed release checksums and container images plus published container provenance attestations


## Features

### Supported Targets

- OCI container image references via `kubescan image --image <ref>`
- Local filesystem paths via `kubescan fs --path <path>`
- Local repository paths via `kubescan repo --path <path>`
- Remote Git repositories via `kubescan repo --url <git-url>`
- Kubernetes manifests and rendered Kubernetes sources via `kubescan scan`
- Live Kubernetes clusters via `kubescan scan`
- In-cluster continuous reporting via `kubescan-operator`
- Mounted or extracted VM root filesystems via `kubescan vm --rootfs`
- Direct VM disk, appliance, and archive inputs via `kubescan vm --disk`

### Supported Input Modes

- Local filesystem paths via `kubescan fs --path`
- Local repository paths via `kubescan repo --path`
- Remote Git repository URLs via `kubescan repo --url`
- Kubernetes manifest files via `--input`
- Rendered Helm charts via `--helm-chart`
- Rendered Kustomize directories via `--kustomize-dir`
- Live cluster scanning via kubeconfig and current or selected context
- Built-in secret detection across local files, manifests, ConfigMaps, and image environment variables
- Optional policy controls via `--policy`
- Optional signed policy controls via `--policy-bundle` and `--bundle-key`
- Optional signed rule controls via `--rules-bundle` and `--bundle-key`
- Optional built-in rule profile selection via `--profile`
- Optional vulnerability inputs via repeated `--sbom` plus `--advisories`
- Optional signed advisory inputs via repeated `--sbom` plus `--advisories-bundle` and `--bundle-key`
- Optional live control-plane and node vulnerability matching via `--component-vulns` plus advisories
- Optional compliance summaries via `--compliance`
- Optional scoping via `--include-kind`, `--exclude-kind`, `--include-namespace`, and `--exclude-namespace`
- Optional summary-only reporting via `--report summary`
- Optional terminal color control via `--color auto|always|never`
- Optional attack path analysis via `--attack-paths`
- Optional file export via `--out`
- Optional OCSF export via `--format ocsf-json`
- Optional in-cluster report generation via `kubescan-operator` and `ScanPolicy` / `ScanReport` CRDs

### Stable Schemas

Kubescan now publishes explicit version markers for its primary machine-readable contracts:

The API and schema namespaces use GitHub-controlled identifiers such as `kubescan.automatesecurity.github.io`, `security.automatesecurity.github.io`, and `report.automatesecurity.github.io`. These are project-owned naming identifiers for versioned contracts, not a dependency on a separate hosted Kubescan service.

- CLI JSON scan output uses `apiVersion: report.automatesecurity.github.io/v1`
- CLI JSON scan output uses `kind: ScanResult`
- CLI JSON scan output uses `schema: kubescan-scan-result`
- CLI JSON scan output uses `schemaVersion: 1.0.0`
- Operator CRDs use `security.automatesecurity.github.io/v1alpha1`
- Signed policy, rule, and advisory bundles use `kubescan.automatesecurity.github.io/v1alpha1`

Checked-in formal schemas live in:

- `schemas/report.automatesecurity.github.io_scan-result_v1.schema.json`
- `schemas/kubescan.automatesecurity.github.io_policy-controls_v1alpha1.schema.json`
- `schemas/kubescan.automatesecurity.github.io_rule-bundle_v1alpha1.schema.json`
- `schemas/kubescan.automatesecurity.github.io_advisory-bundle_v1alpha1.schema.json`
- `schemas/kubescan.automatesecurity.github.io_signed-bundle_v1alpha1.schema.json`
- `deploy/crds/security.automatesecurity.github.io_scanpolicies.yaml`
- `deploy/crds/security.automatesecurity.github.io_scanreports.yaml`
- `deploy/crds/security.automatesecurity.github.io_sbomreports.yaml`
- `deploy/crds/security.automatesecurity.github.io_nodereports.yaml`

The `schemas/` files are JSON Schema documents that can validate either JSON or YAML instances of the bundle and policy payloads. The `deploy/crds/` files are the authoritative Kubernetes schemas for operator CRDs.

`ScanReport` now also includes a compact `status.delta` summary on updates. This records the prior report generation time, finding additions/removals, severity changes, attack-path additions/removals, and bounded per-resource change counts without storing a full report history.

Operator policies can also opt into delta-driven notifications through `ScanPolicy.spec.notification`. The current implementation supports Kubernetes Events, generic webhook delivery, Slack-compatible webhook delivery, and a history-oriented webhook sink with secret-backed auth headers, and persists best-effort delivery results in `ScanReport.status.notification`.

`ScanReport` also keeps a bounded rolling history in `status.trend`. This stores recent reconciliation points with total findings, attack paths, severity mix, phase, and cache usage, plus compact derived analytics such as the highest recent severity, consecutive clean/error runs, and the latest finding/attack-path count deltas.

Remote operator SBOM sources can now also use `ScanPolicy.spec.sbomRefreshInterval` to avoid refetching `HTTP`, `OCIImage`, and `GitHubReleaseAsset` sources on every reconciliation. When set, Kubescan reuses the last fetched remote SBOM until the interval expires, records the next scheduled refresh in `status.sourceStatuses[].nextRefreshAt`, and marks `status.sourceStatuses[].changed` when the refreshed remote SBOM digest differs from the previous successful fetch. The operator also runs an independent background refresh loop for those remote SBOM sources so changed external SBOM content can trigger a rescan even when no watched cluster object changes.

Compatibility policy for the stable CLI JSON result:

- `report.automatesecurity.github.io/v1` is the stable machine-readable scan-result contract
- additive fields may be added within `v1`
- existing fields will not be renamed or change meaning within `v1`
- breaking changes require a new `apiVersion`
- `schemaVersion` tracks the concrete documented result shape within the `v1` contract

Compatibility policy for bundle payloads and CRDs:

- signed bundle envelopes use `apiVersion: kubescan.automatesecurity.github.io/v1alpha1` and `kind: SignedBundle`
- policy controls use `apiVersion: kubescan.automatesecurity.github.io/v1alpha1` and `kind: PolicyControls`
- rule bundles use `apiVersion: kubescan.automatesecurity.github.io/v1alpha1` and `kind: RuleBundle`
- advisory bundles use `apiVersion: kubescan.automatesecurity.github.io/v1alpha1` and `kind: AdvisoryBundle`
- operator CRDs use `apiVersion: security.automatesecurity.github.io/v1alpha1`
- `v1alpha1` contracts are versioned and validated, but are still alpha and may change in a future non-backward-compatible release
- when `v1alpha1` contracts do change incompatibly, Kubescan will introduce a new `apiVersion` rather than silently reinterpreting an older one
- current loaders normalize missing `apiVersion` and `kind` markers for backward compatibility with older examples, but newly produced documents should always include them

Current example JSON header:

```json
{
  "apiVersion": "report.automatesecurity.github.io/v1",
  "kind": "ScanResult",
  "schema": "kubescan-scan-result",
  "schemaVersion": "1.0.0"
}
```

### Direct Image Scanning

The current `image` command supports:
- remote OCI image inspection from a registry reference
- image config analysis without requiring Kubernetes
- optional unpacked image-layer scanning for secrets and declared licenses
- native vulnerability matching from extracted Alpine, Debian, and RPM package inventories when advisories are supplied
- application dependency extraction from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `go.mod`, `pom.xml`, `Cargo.lock`, `composer.lock`, `packages.lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and `Gemfile.lock` found inside image layers
- CycloneDX or SPDX JSON SBOM export from the extracted image inventory through `--sbom-out`
- optional CycloneDX or SPDX SBOM correlation for a single image when `--sbom` and advisories are supplied

### Direct Filesystem and Repository Scanning

The current `fs` and `repo` commands support:
- high-signal secret detection in local text files, including token patterns, private keys, and plaintext credential-like assignments
- Kubernetes manifest discovery from local files and directories
- reuse of the existing Kubernetes rule engine against discovered manifests
- declared project-license policy checks for `package.json`, `Cargo.toml`, and `pyproject.toml`
- repeated path exclusions through `--exclude-path`
- configurable secret-scan sensitivity through `--secret-scan patterns|balanced|aggressive`
- summary or full reporting in the same formats as other commands

The current `repo` command can scan either a local repository path or a remote Git repository URL.
Generic plaintext secret assignment detection is intentionally limited to config-like files such as `.env`, YAML, JSON, TOML, INI, and properties-style files. Documentation, source files, and common lockfiles still get known-token and private-key detection, but not broad `key: value` secret heuristics.
For `fs` and `repo`, `--profile` only affects Kubernetes manifest findings discovered under the scanned path. File secret findings (`KF*`) and license findings (`KL*`) are evaluated independently of the Kubernetes rule profile.

### Supported Kubernetes Resources

The current collector/parser covers:
- `Pod`
- `Deployment`
- `StatefulSet`
- `DaemonSet`
- `Job`
- `CronJob`
- `Service`
- `ConfigMap`
- `Role`
- `ClusterRole`
- `RoleBinding`
- `ClusterRoleBinding`
- `NetworkPolicy`
- `Namespace`
- `Node` in live cluster mode

The live cluster collector also extracts versioned component inventory for:
- `kubelet`
- `kube-proxy`
- `kube-apiserver`
- `kube-controller-manager`
- `kube-scheduler`
- `etcd`

### Supported Compliance Profiles

- `k8s-cis`
- `nsa`
- `pss-restricted`

### Supported Rule Profiles

- `default`: high-signal hardening, exposure, and identity findings intended for routine scans
- `hardening`: `default` plus workload hygiene and namespace posture checks
- `enterprise`: `hardening` plus noisier policy-shaped detections such as plaintext credential heuristics and public-registry posture

Compliance evaluation always uses the enterprise built-in catalog so profile tuning does not reduce compliance coverage.

### Current Detection Coverage

Across the built-in profiles, Kubescan currently detects:
- Privileged containers
- Host network / PID / IPC usage
- Dangerous Linux capabilities
- Containers that allow privilege escalation
- Missing `runAsNonRoot`
- Containers explicitly running as UID `0`
- Writable root filesystems
- Missing or unconfined `seccompProfile`
- HostPath volume mounts
- Container `hostPort` bindings
- Missing CPU or memory requests
- Missing CPU or memory limits
- Missing liveness probes
- Missing readiness probes
- Mutable image tags such as `latest`
- Images pulled from implicit or public registries
- Public `LoadBalancer` and `NodePort` services
- Service account token auto-mounting risk
- Wildcard RBAC permissions
- Subjects that reach wildcard RBAC permissions through a binding
- Subjects that reach `cluster-admin` through a binding
- Workloads that use service accounts bound to wildcard RBAC permissions
- Workloads that use the namespace default service account
- Secret data referenced through environment variables
- Secret-backed workload volumes
- Sensitive values in environment variables or ConfigMaps, including known token patterns, private keys, and high-signal plaintext credential-like assignments
- Subjects that reach secret-read RBAC permissions through a binding
- Workloads that use service accounts with secret-read permissions
- Namespaces with workloads but no ingress-isolating `NetworkPolicy`
- Namespaces with workloads but no egress-isolating `NetworkPolicy`
- Namespaces missing restricted Pod Security Admission labels
- Privileged containers that also request `hostPID`
- Privileged workloads that also mount `hostPath`
- Sensitive `hostPath` mounts such as `/`, kubelet state, etcd data, Kubernetes config, and container runtime sockets
- Workloads with control-plane scheduling indicators such as control-plane tolerations or explicit control-plane node targeting
- Control-plane nodes that remain schedulable for general workloads
- Nodes that still report the legacy Docker runtime
- Nodes that advertise external IP addresses
- Nodes that are not reporting Ready
- Clusters with kubelet version skew across nodes
- Clusters with kube-proxy version skew across nodes
- Clusters with visible control-plane component version skew during upgrades
- Vulnerable OS packages present in supplied SBOM data when matching advisories exist
- Vulnerable control-plane and node components when matching live cluster advisories exist

The current direct image scanner also detects:
- Mutable image tags such as `latest`
- Images sourced from implicit or public registries
- Image configs that may run as root by default
- Sensitive environment variables baked into image config, including known token patterns and plaintext credential-like assignments
- Sensitive file content in unpacked image layers, including known token patterns, private keys, and high-signal plaintext credential-like assignments
- Disallowed declared licenses in unpacked image-layer files when a denylist is configured
- Declared licenses outside an allowlist in unpacked image-layer files when an allowlist is configured
- Vulnerable packages from native Alpine, Debian, and RPM package extraction when advisories are provided for the scanned image
- Vulnerable `golang`, `maven`, `cargo`, `composer`, `nuget`, `npm`, `pypi`, and `gem` packages extracted from common image-layer lock or manifest files when matching advisories are provided
- Vulnerable packages from a supplied SBOM when matching advisories are provided for the scanned image

The current local filesystem and repository scanner can also enforce:
- Disallowed declared project licenses from common package manifests
- Declared project licenses that fall outside a configured allowlist

### Current Attack Path Coverage

When `--attack-paths` is enabled, Kubescan currently emits curated attack paths for:
- Internet-exposed Services that route to workloads with node-compromise preconditions
- Workloads that reach wildcard RBAC through their service-account bindings
- Workloads that reach Secret-read RBAC through their service-account bindings
- Internet-exposed Services that route to workloads whose service accounts can read Secrets
- Internet-exposed Services that route to workloads whose service accounts can reach `cluster-admin`
- Workloads with control-plane scheduling indicators plus node-compromise preconditions

The implementation is inspired by Prowler's graph-based attack-path model as described in the [Prowler repository](https://github.com/prowler-cloud/prowler/tree/master) and its [attack paths tutorial](https://github.com/prowler-cloud/prowler/blob/master/docs/user-guide/tutorials/prowler-app-attack-paths.mdx), but Kubescan currently keeps the graph in-memory during a scan instead of persisting it in Neo4j.

### Research-Aligned Checks

Several of the built-in workload escalation checks are directly informed by Bishop Fox's [Bad Pods: Kubernetes Pod Privilege Escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) research and the accompanying [badPods repository](https://github.com/BishopFox/badPods).

Kubescan now statically flags these Bad Pods-style escalation preconditions:
- Privileged containers combined with `hostPID`
- Privileged workloads combined with `hostPath`
- Sensitive `hostPath` targets such as host root, kubelet, etcd, Kubernetes config, and runtime sockets
- Control-plane scheduling indicators that increase the chance of reaching high-value nodes

These checks are precondition-oriented. Kubescan identifies the risky pod configurations described in the research; it does not attempt runtime exploitation, traffic sniffing, metadata probing, or credential extraction from a live compromised pod.

## Installation

### Prerequisites

- Go `1.26+`
- Access to a Kubernetes cluster if you want to run live scans
- A valid kubeconfig for cluster mode
- A local `git` binary on `PATH` if you want to use `kubescan repo --url`
- A local `helm` binary on `PATH` if you want to use `--helm-chart`
- A local `kustomize` binary or `kubectl` on `PATH` if you want to use `--kustomize-dir`

### Build

From the repository root:

```bash
go build -o kubescan ./cmd/kubescan
go build -o kubescan-operator ./cmd/kubescan-operator
go build -o kubescan-node-collector ./cmd/kubescan-node-collector
```

Ensure `go` is on your `PATH` before building.

## Releases and Packaging

Kubescan now includes first-class packaging and release artifacts for the CLI, the reporting operator, and the optional node collector.

Published release/build assets in this repository:

- `./.goreleaser.yaml` for cross-platform binary archives and checksums
- `./.github/workflows/release.yaml` for tag-driven GitHub Releases and container publishing
- `./Dockerfile` for the `kubescan` CLI container image
- `./Dockerfile.operator` for the `kubescan-operator` container image
- `./Dockerfile.node-collector` for the `kubescan-node-collector` container image

Release hardening now includes:

- Sigstore keyless signing for published `checksums.txt`
- Sigstore keyless signing for published container images
- GitHub build provenance attestations for published container images
- embedded OCI image labels for version, revision, source, and build time
- weekly Dependabot updates for Go modules and GitHub Actions
- CI-time `go mod verify` and `govulncheck ./...` dependency verification

### Binary Version Output

All shipped binaries expose embedded build metadata:

```bash
go run ./cmd/kubescan version
go run ./cmd/kubescan-operator version
go run ./cmd/kubescan-node-collector version
```

Released binaries print the injected version, commit, and build date.

### Build Container Images Locally

Build the CLI image:

```bash
docker build -f ./Dockerfile -t kubescan:dev .
```

Build the operator image:

```bash
docker build -f ./Dockerfile.operator -t kubescan-operator:dev .
```

Build the node collector image:

```bash
docker build -f ./Dockerfile.node-collector -t kubescan-node-collector:dev .
```

### Release Workflow

Tagging a release like `v1.0.0` triggers the checked-in GitHub Actions release workflow, which:

- builds archive artifacts for `linux`, `darwin`, and `windows`
- emits a `checksums.txt` file
- signs `checksums.txt` with Sigstore keyless signing and uploads the signature and certificate
- publishes `ghcr.io/automatesecurity/kubescan:<tag>` and `:latest`
- publishes `ghcr.io/automatesecurity/kubescan-operator:<tag>` and `:latest`
- publishes `ghcr.io/automatesecurity/kubescan-node-collector:<tag>` and `:latest`
- signs all published container images with Sigstore keyless signing
- publishes GitHub build provenance attestations for all container images

### Verify Released Artifacts

Verify a released checksum manifest:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/.+/.+/.github/workflows/release.yaml@.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ./checksums.txt
```

Verify a released container image signature:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/.+/.+/.github/workflows/release.yaml@.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/automatesecurity/kubescan:latest
```

## Quick Start

### 1. Run the unit tests

```bash
go test ./...
```

### 2. Scan the included example manifest

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml
```

### 3. Scan a container image

```bash
go run ./cmd/kubescan image --image nginx:latest
```

To inspect unpacked layers for baked-in secrets and declared licenses:

```bash
go run ./cmd/kubescan image --image nginx:latest --scan-layers
```

To match image vulnerabilities directly from extracted packages:

```bash
go run ./cmd/kubescan image --image alpine:3.20 --advisories ./examples/advisories.yaml
```

To emit a CycloneDX JSON SBOM from the extracted inventory:

```bash
go run ./cmd/kubescan image --image registry.access.redhat.com/ubi9/ubi:latest --sbom-out ./ubi9.sbom.json
```

To scan a private registry image with explicit credentials:

```bash
printf '%s' "$REGISTRY_PASSWORD" | go run ./cmd/kubescan image --image registry.internal/acme/api:1.0.0 --registry-username "$REGISTRY_USERNAME" --registry-password-stdin
```

### 4. Scan the included filesystem demo

```bash
go run ./cmd/kubescan fs --path ./examples/fs-demo
```

### 5. Scan the current repository in summary mode

```bash
go run ./cmd/kubescan repo --path . --report summary
```

### 6. Scan a remote Git repository

```bash
go run ./cmd/kubescan repo --url https://github.com/owner/repo.git --report summary
```

To scan a private Git repository over HTTPS with an explicit auth header:

```bash
go run ./cmd/kubescan repo --url https://github.com/owner/private-repo.git --git-http-header "Authorization: Bearer $GITHUB_TOKEN" --report summary
```

To scan a private Git repository over SSH with an explicit SSH command:

```bash
go run ./cmd/kubescan repo --url git@github.com:owner/private-repo.git --git-ssh-command "ssh -i /path/to/id_ed25519 -o IdentitiesOnly=yes" --report summary
```

### 7. Scan the included secret demo

```bash
go run ./cmd/kubescan fs --path ./examples/secret-demo --format json
```

### 8. Scan the included license-policy demo

```bash
go run ./cmd/kubescan fs --path ./examples/license-demo --license-deny GPL-3.0-only --format json
```

### 9. Scan a live cluster

Use the default kubeconfig and current context:

```bash
go run ./cmd/kubescan scan
```

Scan a specific namespace:

```bash
go run ./cmd/kubescan scan --namespace payments
```

Use an explicit kubeconfig and context:

```bash
go run ./cmd/kubescan scan --kubeconfig /path/to/config --context prod-east --namespace payments
```

Apply the included policy controls file:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --policy ./examples/controls.yaml
```

Use a signed policy bundle instead of a plain policy file:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --policy-bundle ./examples/policy.bundle.yaml --bundle-key ./examples/bundle.pub.pem
```

Use a signed rule bundle to disable or re-severity built-in rules:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --rules-bundle ./examples/rules.bundle.yaml --bundle-key ./examples/bundle.pub.pem
```

Render and scan a Helm chart with a compliance profile:

```bash
go run ./cmd/kubescan scan --helm-chart ./examples/helm/api --helm-values ./examples/helm/api/values-prod.yaml --profile hardening
```

Render and scan a Kustomize overlay in summary mode:

```bash
go run ./cmd/kubescan scan --kustomize-dir ./examples/kustomize/overlays/prod --report summary
```

Scan with vulnerability correlation using the included SBOM and advisories:

```bash
go run ./cmd/kubescan scan --input ./examples/vuln-sample.yaml --sbom ./examples/vuln-sbom.json --advisories ./examples/advisories.yaml --policy ./examples/controls.yaml
```

Scan multiple images with multiple SBOMs in one run:

```bash
go run ./cmd/kubescan scan --input ./examples/vuln-multi.yaml --sbom ./examples/vuln-sbom.json --sbom ./examples/vuln-worker-sbom.json --advisories ./examples/advisories.yaml
```

Scan live cluster node and control-plane components against the included Kubernetes advisory example:

```bash
go run ./cmd/kubescan scan --component-vulns --advisories ./examples/k8s-components-advisories.yaml --namespace kube-system
```

Run the API-visible node posture, pressure, network-availability, and version-skew checks in a live cluster:

```bash
go run ./cmd/kubescan scan --profile hardening
```

### 10. Run the operator locally against the current cluster

Apply the CRDs first:

```bash
kubectl apply -f ./deploy/crds
```

Apply the example operator scan policy:

```bash
kubectl apply -f ./examples/operator-scanpolicy.yaml
```

To use signed policy, rule, and advisory bundles plus operator-managed workload SBOMs from in-cluster objects, load the checked-in examples into the cluster, label the SBOM source object, and apply the bundle-aware `ScanPolicy`:

```bash
kubectl create configmap kubescan-policy-bundle -n kubescan-system --from-file=policy.bundle.yaml=./examples/policy.bundle.yaml
kubectl create configmap kubescan-rules-bundle -n kubescan-system --from-file=rules.bundle.yaml=./examples/rules.bundle.yaml
kubectl create configmap kubescan-advisories-bundle -n kubescan-system --from-file=advisories.bundle.yaml=./examples/advisories.bundle.yaml
kubectl create secret generic kubescan-bundle-key -n kubescan-system --from-file=bundle.pub.pem=./examples/bundle.pub.pem
kubectl apply -f ./examples/operator-sbomreport.yaml
kubectl apply -f ./examples/operator-scanpolicy-bundles.yaml
```

To use remote HTTPS, OCI image, or provider-native GitHub release-asset SBOM sources in operator mode, create the auth secrets referenced by the example policies and then apply them:

```bash
kubectl create secret generic registry-creds -n payments --from-literal=creds.json='{"username":"robot","password":"change-me"}'
kubectl create secret generic sbom-http-auth -n payments --from-literal=token='Bearer change-me'
kubectl apply -f ./examples/operator-scanpolicy-remote-sboms.yaml
kubectl create secret generic github-api-auth -n payments --from-literal=token='Bearer ghp_example'
kubectl apply -f ./examples/operator-scanpolicy-github-sbom.yaml
```

The remote SBOM examples now show all supported external SBOM source types:

- `kind: HTTP` for HTTPS-fetched CycloneDX JSON or SPDX JSON SBOMs
- `kind: OCIImage` for deriving package inventory directly from a registry image reference
- `kind: GitHubReleaseAsset` for fetching a CycloneDX JSON or SPDX JSON SBOM from a tagged GitHub release asset
- `sbomRefreshInterval: 30m` to reuse the last fetched remote SBOM until the next refresh window
- `status.sourceStatuses[].changed` and `nextRefreshAt` to show refresh outcomes for remote SBOM sources

To enable Kubernetes Event, generic webhook, and Slack-compatible webhook notifications for changed reports, create the referenced auth secret and apply the notification policy:

```bash
kubectl create secret generic webhook-auth -n payments --from-literal=token="$KUBESCAN_WEBHOOK_TOKEN"
kubectl apply -f ./examples/operator-scanpolicy-slack.yaml
```

After the next changed reconciliation, inspect the report notification status and the emitted Event stream:

```bash
kubectl get scanreport cluster-notify -o yaml
kubectl get events --field-selector reason=ScanDeltaChanged
```

The same report now also carries a bounded rolling history under `status.trend`, including recent runs, highest recent severity, latest finding/attack-path deltas, and consecutive clean/error runs:

```bash
kubectl get scanreport cluster-notify -o yaml
```

To export the rolling report history and latest summary on every reconciliation, create the referenced auth secret and apply the history webhook policy:

```bash
kubectl create secret generic history-webhook-auth -n payments --from-literal=token="$KUBESCAN_HISTORY_TOKEN"
kubectl apply -f ./examples/operator-scanpolicy-history.yaml
```

The history webhook sink delivers even on initial report creation, so downstream systems can retain a longer-lived report timeline than the bounded `status.trend` window stored in the CRD.

Run one operator cycle locally:

```bash
go run ./cmd/kubescan-operator --once --cycle-timeout 5m --max-findings 250 --max-attack-paths 100
```

Cluster-wide and reduced-privilege in-cluster deployment manifests are included at [deploy/operator/operator.yaml](deploy/operator/operator.yaml) and [deploy/operator/operator-namespace.yaml](deploy/operator/operator-namespace.yaml). Update the image reference before applying them.

The optional Phase 1B node collector manifest is included at [deploy/node-collector/node-collector.yaml](deploy/node-collector/node-collector.yaml). It deploys one host-mounted collector pod per node and writes cluster-scoped `NodeReport` CRDs that live-cluster scans consume automatically when the CRD exists.

The namespace-scoped manifest uses `--namespace`, `--namespaced-only`, and `--default-only` together so the operator can run with narrower read permissions against one namespace while still writing cluster-scoped `ScanReport` CRDs. Both deployment examples enable `--watch=true` with a `--watch-debounce` window for event-driven rescans.

Both shipped operator deployment manifests now include baseline container hardening defaults:

- `runAsNonRoot: true`
- `seccompProfile: RuntimeDefault`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- dropped Linux capabilities
- default CPU and memory requests/limits

The shipped node collector manifest uses a narrower host-mounted model instead of full privileged mode:

- read-only `hostPath` access to `/var/lib/kubelet`
- `runAsUser: 0` for kubelet-config readability on the host mount
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- dropped Linux capabilities
- `RuntimeDefault` seccomp

### Node Collector

Phase 1B is now implemented through an optional `kubescan-node-collector` binary and a cluster-scoped `NodeReport` CRD. The collector reads kubelet configuration from the host and reports deeper node posture that is not visible through the Kubernetes API alone.

Current Phase 1B collector coverage includes:

- `authentication.anonymous.enabled`
- `authentication.webhook.enabled`
- `authorization.mode`
- `readOnlyPort`
- `rotateCertificates`
- `serverTLSBootstrap`
- `seccompDefault`
- `protectKernelDefaults`

Deploy the CRD and node collector:

```bash
kubectl apply -f ./deploy/crds/security.automatesecurity.github.io_nodereports.yaml
kubectl apply -f ./deploy/node-collector/node-collector.yaml
```

Run a live cluster scan after the collector reports in:

```bash
go run ./cmd/kubescan scan --profile hardening
```

If `NodeReport` objects are present, Kubescan automatically folds them into live-cluster node inventory and enables the deeper kubelet posture rules in the rule catalog below.

Inspect the stored reports:

```bash
kubectl get scanreports
kubectl get scanreport cluster-hardening -o yaml
```

Verify a signed advisory bundle:

```bash
go run ./cmd/kubescan verify bundle --bundle ./examples/advisories.bundle.yaml --key ./examples/bundle.pub.pem
```

Export SARIF to a file:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --format sarif --out ./findings.sarif
```

Export an interactive HTML report:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --format html --out ./findings.html
```

Filter to service resources in one namespace and print a summary only:

```bash
go run ./cmd/kubescan scan --input ./examples/scoping-sample.yaml --include-kind Service --include-namespace public --report summary
```

## CLI Usage

### Command

```text
kubescan scan [--input <file> | --helm-chart <dir> [--helm-values <file> ...] [--helm-release <name>] [--helm-namespace <ns>] | --kustomize-dir <dir> | live-cluster flags] [--profile default|hardening|enterprise] [--include-kind <kind> ...] [--exclude-kind <kind> ...] [--include-namespace <ns> ...] [--exclude-namespace <ns> ...] [--policy <file> | --policy-bundle <file> --bundle-key <file>] [--rules-bundle <file> --bundle-key <file>] [(--sbom <file> ... | --component-vulns) (--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>)] [--compliance <profile>] [--report all|summary] [--color auto|always|never] [--attack-paths] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]
live-cluster flags: [--kubeconfig <file>] [--context <name>] [--namespace <ns>]
kubescan image --image <ref> [--registry-username <user> (--registry-password <pass> | --registry-password-stdin) | --registry-token <token>] [--scan-layers] [--secret-scan patterns|balanced|aggressive] [--license-allow <id> ...] [--license-deny <id> ...] [--sbom-out <file>] [--sbom-format cyclonedx|spdx] [(--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>) [--sbom <file>]] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]
kubescan fs --path <path> [--profile default|hardening|enterprise] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--secret-scan patterns|balanced|aggressive] [--report all|summary] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]
kubescan repo [--path <path> | --url <git-url> [--ref <ref>] [--provider-native] [--sparse-path <pattern> ...] [--git-http-header <header> ...] [--git-ssh-command <command>]] [--profile default|hardening|enterprise] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--secret-scan patterns|balanced|aggressive] [--report all|summary] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]
kubescan vm [--rootfs <path> | --disk <path>] [--profile default|hardening|enterprise] [--secret-scan patterns|balanced|aggressive] [--license-allow <id> ...] [--license-deny <id> ...] [--exclude-path <pattern> ...] [--sbom-out <file>] [--sbom-format cyclonedx|spdx] [(--advisories <file> | --advisories-db <file> | --advisories-bundle <file> --bundle-key <file>)] [--color auto|always|never] [--format table|json|html|sarif|ocsf-json] [--out <file>] [--fail-on <severity>]
kubescan verify bundle --bundle <file> --key <public-key>
kubescan db build [--source-manifest <file> | --advisories <file> | --advisories-bundle <file> --bundle-key <file>] [--osv <file-or-url> ...] --out <file> [--metadata-out <file>]
kubescan db info --db <file> [--format table|json]
kubescan db verify --db <file> [--metadata <file>] [(--bundle <file> [sigstore flags]) | (--signature <file> --key <public-key>)]
kubescan db update --url <url> --out <file> [--metadata-url <url>] [--bundle-url <url> [sigstore flags]] [--signature-url <url> --key <public-key>]
kubescan-operator [--interval <duration>] [--watch=true|false] [--watch-debounce <duration>] [--cycle-timeout <duration>] [--prune-stale-reports] [--report-ttl <duration>] [--max-findings <count>] [--max-attack-paths <count>] [--kubeconfig <file>] [--context <name>] [--namespace <ns>] [--namespaced-only] [--default-only] [--profile default|hardening|enterprise] [--compliance <profile>] [--attack-paths] [--report-name <name>] [--once]
kubescan-node-collector [--interval <duration>] [--host-root <dir>] [--kubelet-config <path>] [--node-name <name>] [--kubeconfig <file>] [--context <name>] [--once]
```

### Flags

- `--input`: Path to a Kubernetes YAML manifest file
- `--path`: Path to a local filesystem or repository directory to scan with `fs` or `repo`
- `--url`: Remote Git repository URL to shallow-clone and scan with `repo`
- `--ref`: Branch, tag, or ref to fetch after cloning a remote repository with `repo`
- `--git-http-header`: Extra HTTP header for authenticated remote Git access; repeat for multiple values
- `--git-ssh-command`: Custom `GIT_SSH_COMMAND` for authenticated remote Git SSH access
- `--license-allow`: Approved SPDX license identifier for `fs` and `repo`; repeat for multiple values
- `--license-deny`: Disallowed SPDX license identifier for `fs` and `repo`; repeat for multiple values
- `--exclude-path`: Exclude a relative path or glob pattern from filesystem or repository scanning; repeat for multiple values
- `--secret-scan`: Secret scan sensitivity for `fs` and `repo`: `patterns`, `balanced`, or `aggressive`
- `--helm-chart`: Path to a Helm chart directory to render and scan
- `--helm-values`: Path to a Helm values file; repeat for multiple values files
- `--helm-release`: Release name used for Helm rendering; default is `kubescan`
- `--helm-namespace`: Namespace used for Helm rendering; default is `default`
- `--kustomize-dir`: Path to a Kustomize directory to render and scan
- `--kubeconfig`: Path to a kubeconfig file for live cluster scans
- `--context`: Kubeconfig context name to use
- `--namespace`: Namespace to scan for live cluster mode; defaults to all namespaces
- `--include-kind`: Only evaluate specific resource kinds
- `--exclude-kind`: Exclude specific resource kinds
- `--include-namespace`: Only evaluate specific namespaces
- `--exclude-namespace`: Exclude specific namespaces
- `--policy`: Path to a YAML controls file with suppressions and severity overrides
- `--policy-bundle`: Path to a signed policy controls bundle file
- `--rules-bundle`: Path to a signed rule bundle file
- `--profile`: Built-in rule profile to evaluate: `default`, `hardening`, or `enterprise`
- `--sbom`: Path to a CycloneDX JSON or SPDX JSON SBOM file; repeat for multiple images
- `--component-vulns`: Match live cluster control-plane and node components against advisories
- `--advisories`: Path to an advisory bundle file
- `--advisories-bundle`: Path to a signed advisory bundle file
- `--bundle-key`: Path to an Ed25519 public key for signed advisory bundle verification
- `--compliance`: Compliance profile to evaluate: `k8s-cis`, `nsa`, or `pss-restricted`
- `--report`: `all` or `summary`; `summary` is supported for table, JSON, and HTML output
- `--color`: `auto`, `always`, or `never`; applies to table and summary table output only
- `--attack-paths`: Analyze attack paths from the collected Kubernetes graph
- `--format`: `table`, `json`, `html`, `sarif`, or `ocsf-json`; default is `table`
- `--out`: Path to write scan output instead of stdout
- `--fail-on`: Severity threshold for failing a scan: `low`, `medium`, `high`, or `critical`
- `kubescan-operator --interval`: Periodic full-scan interval for operator mode
- `kubescan-operator --watch`: Enable or disable watch-triggered rescans in addition to periodic full scans
- `kubescan-operator --watch-debounce`: Debounce window applied to bursts of watch-triggered resource changes
- `kubescan-operator --cycle-timeout`: Maximum duration allowed for a single operator scan cycle
- `kubescan-operator --prune-stale-reports`: Delete stale managed `ScanReport` objects during full reconciliations
- `kubescan-operator --report-ttl`: Optional maximum age for managed `ScanReport` objects before age-based pruning
- `kubescan-operator --max-findings`: Maximum number of findings stored in a `ScanReport`
- `kubescan-operator --max-attack-paths`: Maximum number of attack paths stored in a `ScanReport`
- `kubescan-operator --namespace`: Default namespace scope for operator scans when no `ScanPolicy.spec.namespace` is set
- `kubescan-operator --namespaced-only`: Skip cluster-scoped inventory such as nodes, namespaces, `ClusterRole`, and `ClusterRoleBinding`
- `kubescan-operator --default-only`: Skip `ScanPolicy` discovery and always use the default operator flags
- `kubescan-operator --once`: Run one operator scan cycle and exit
- `kubescan-operator --report-name`: Default `ScanReport` name when no `ScanPolicy` objects exist
- `kubescan-node-collector --interval`: Periodic collection interval for `NodeReport` refresh
- `kubescan-node-collector --host-root`: Mounted host root used to resolve kubelet config files; defaults to `/host`
- `kubescan-node-collector --kubelet-config`: Host kubelet config path to inspect; defaults to `/var/lib/kubelet/config.yaml`
- `kubescan-node-collector --node-name`: Explicit node name for the generated `NodeReport`; defaults to `$NODE_NAME` or the local hostname
- `kubescan-node-collector --once`: Run one collection cycle and exit

Image command flags:
- `--image`: OCI image reference to inspect
- `--registry-username`: Registry username for authenticated direct image scanning
- `--registry-password`: Registry password for authenticated direct image scanning
- `--registry-password-stdin`: Read the registry password for authenticated direct image scanning from stdin
- `--registry-token`: Registry bearer token for authenticated direct image scanning
- `--scan-layers`: Inspect unpacked image layers for secret and license findings
- `--secret-scan`: Secret scan sensitivity for image layers: `patterns`, `balanced`, or `aggressive`
- `--license-allow`: Approved SPDX license identifier for image-layer license policy; repeat for multiple values
- `--license-deny`: Disallowed SPDX license identifier for image-layer license policy; repeat for multiple values
- `--sbom-out`: Write the extracted image inventory as a CycloneDX JSON or SPDX JSON SBOM file
- `--sbom-format`: Select `cyclonedx` or `spdx` for `--sbom-out`
- `--sbom`: Optional CycloneDX JSON or SPDX JSON SBOM for the image; if omitted, Kubescan extracts Alpine, Debian, RPM, Go, Maven, Cargo, Composer, NuGet, npm, PyPI, and gem packages directly from the image when advisories are supplied
- `--advisories`: Advisory bundle file used with native image package extraction or `--sbom`
- `--advisories-bundle`: Signed advisory bundle used with native image package extraction or `--sbom`
- `--bundle-key`: Ed25519 public key for `--advisories-bundle`
- `--color`: `auto`, `always`, or `never`
- `--format`: `table`, `json`, `html`, `sarif`, or `ocsf-json`
- `--out`: Path to write output instead of stdout
- `--fail-on`: Severity threshold for failing an image scan

### Input Rules

- `--input` uses manifest mode
- `--helm-chart` uses Helm-rendered manifest mode
- `--kustomize-dir` uses Kustomize-rendered manifest mode
- Omitting `--input`, `--helm-chart`, and `--kustomize-dir` uses live cluster mode
- Live cluster mode can use the current kubeconfig context with no flags, or an explicit `--kubeconfig` and/or `--context`
- `--input`, `--helm-chart`, and `--kustomize-dir` are mutually exclusive
- File, Helm, and Kustomize sources cannot be combined with live cluster flags such as `--kubeconfig`, `--context`, or `--namespace`
- `--policy` can be used with either manifest or cluster scans
- `--policy` and `--policy-bundle` are mutually exclusive
- `--rules-bundle` can be combined with either plain or signed policy controls
- `--sbom` may be repeated
- `--sbom` requires either `--advisories` or `--advisories-bundle`
- `--component-vulns` requires either `--advisories` or `--advisories-bundle`
- In `scan`, `--advisories` and `--advisories-bundle` require at least one `--sbom` or `--component-vulns`
- `--component-vulns` is supported only for live cluster scans
- `--advisories` and `--advisories-bundle` are mutually exclusive
- `--bundle-key` is required with `--policy-bundle`, `--rules-bundle`, and `--advisories-bundle`
- `--out` can be used with any supported output format
- `--fail-on` changes exit code behavior from "any findings" to "threshold met"
- `--report summary` is not supported with SARIF output
- `--report summary` is not supported with OCSF JSON output
- `--attack-paths` is supported with table, JSON, and HTML output
- `--attack-paths` is not supported with SARIF output
- `--attack-paths` is not supported with OCSF JSON output
- `--color auto` enables color only when writing table output directly to a terminal
- Compliance reports always evaluate against the enterprise built-in rule catalog, regardless of `--profile`
- `image` scans require `--image`
- `image` scans use the local container-registry keychain by default and also support explicit `--registry-username`/`--registry-password`, `--registry-password-stdin`, or `--registry-token` auth
- `image` advisory correlation uses `--sbom` when supplied, otherwise it attempts native Alpine, Debian, and RPM package extraction
- `image` `--sbom-out` writes a CycloneDX or SPDX JSON SBOM from the extracted inventory and cannot be combined with `--sbom`
- `image` `--secret-scan`, `--license-allow`, and `--license-deny` require `--scan-layers`
- `repo --url` requires a local `git` binary; Kubescan currently performs shallow clones through the local Git CLI
- `repo --url` currently accepts `https://`, `http://`, `ssh://`, and scp-style Git URLs only; local paths and `file://` URLs are rejected
- `repo --url` runs Git in non-interactive mode and disables local `file` and `ext` transport helpers during clone/fetch
- `repo --url` also supports explicit authenticated Git access through repeated `--git-http-header` values or `--git-ssh-command`
- `kubescan-operator` uses `ScanPolicy` and `ScanReport` CRDs and now supports both periodic scans and watch-triggered debounced rescans that rerun only the affected policy scopes when the changed resource maps cleanly to a namespace
- `kubescan-operator` enforces per-cycle timeouts, caps stored findings and attack paths, and can prune stale managed `ScanReport` objects by policy membership and optional TTL so report storage remains bounded
- `kubescan-operator --namespaced-only` is intended for reduced-privilege namespace-scoped deployments; it skips cluster-scoped inventory and works best with `--default-only`
- `ScanPolicy notification.emitEvents: true` emits Kubernetes Events when a `ScanReport` delta contains changes
- `ScanPolicy notification.webhookUrl` posts compact JSON delta notifications when a `ScanReport` delta contains changes
- `ScanPolicy notification.slackWebhookUrl` posts a compact Slack-compatible text summary when a `ScanReport` delta contains changes
- `ScanPolicy notification.historyWebhookUrl` posts a compact full-history summary payload on every reconciliation so external systems can persist longer-lived report history
- `ScanPolicy notification.minimumSeverity` gates notifications so unchanged low-severity reports do not emit sink traffic
- `ScanPolicy notification.authSecretRef` can provide a bearer token, a raw `Header: value`, or a JSON header map for webhook auth
- `ScanPolicy sbomRefreshInterval` controls how often remote `HTTP`, `OCIImage`, and `GitHubReleaseAsset` SBOM refs are refetched; the operator also checks those sources from an independent background refresh loop between normal reconciliations
- `ScanReport.status.trend` keeps a bounded rolling history of recent reconciliations with finding counts, attack-path counts, severity mix, phase, cache usage, highest recent severity, consecutive clean/error runs, and latest count deltas
- `ScanPolicy` supports `bundleKeyRef`, `policyBundleRef`, `rulesBundleRef`, and `advisoriesBundleRef` for signed bundle loading from `ConfigMap` or `Secret` objects
- `ScanPolicy bundleFailurePolicy: use-last-good` tells the operator to keep scanning from the last successfully verified signed bundle set when a later refresh fails; `ScanReport.status.usedCachedSources` and `status.sourceStatuses` show when that happens
- `ScanPolicy componentVulns: true` enables advisory matching for live cluster components when an `advisoriesBundleRef` is configured
- `ScanPolicy sbomRefs` loads CycloneDX JSON or SPDX JSON SBOMs from `ConfigMap`, `Secret`, `SBOMReport`, `HTTP`, `OCIImage`, or `GitHubReleaseAsset` sources for workload image vulnerability correlation when an `advisoriesBundleRef` is also configured
- `ScanPolicy sbomRefreshInterval` applies only to remote `HTTP`, `OCIImage`, and `GitHubReleaseAsset` SBOM refs; local `ConfigMap`, `Secret`, and `SBOMReport` sources are still read directly during each reconciliation
- `ScanPolicy sbomSelector` discovers CycloneDX JSON or SPDX JSON SBOM entries from labeled `SBOMReport`, `ConfigMap`, and `Secret` objects in the effective policy namespace; `ConfigMap` and `Secret` entries with `.json` keys are parsed as SBOMs
- `ScanReport.status.sourceStatuses[].changed` shows when a refreshed remote SBOM digest changed since the previous successful fetch
- `ScanReport.status.sourceStatuses[].nextRefreshAt` shows the next scheduled fetch time for a cached remote SBOM source
- `SBOMReport` is the preferred cluster-native carrier for operator-managed workload SBOM distribution; labeled `ConfigMap` and `Secret` discovery remains supported for backward compatibility
- `ScanPolicy.spec.*Ref.authSecretRef` can provide a secret-backed auth value for `HTTP` and `OCIImage` SBOM sources; HTTP refs use HTTPS only
- `HTTP` `authSecretRef` values may be a bearer token, a raw `Header: value` string, or JSON like `{"headers":{"Authorization":"Bearer ..."}}`
- `OCIImage` `authSecretRef` values may be a token string, `username:password`, or JSON like `{"username":"robot","password":"..."}`
- Filesystem and repository scans skip symlinked files and directories rather than following them outside the scan root

## Examples

### Example Catalog

The repository includes example fixtures for each major scan mode and rule family. The current test suite validates these examples directly; the Helm render example is also covered when a local `helm` binary is available.

- Direct image scans use external registry references rather than checked-in fixtures; the `image` command is covered by unit tests with a stubbed image inspector.
- `kubescan image --image registry.internal/acme/api:1.0.0 --registry-username ... --registry-password-stdin`: credentialed private-registry image example. This is command-only documentation rather than a checked-in fixture because credentials are environment-specific.
- `kubescan repo --url https://github.com/owner/private-repo.git --git-http-header "Authorization: Bearer ..."`: credentialed private Git HTTPS example. This is command-only documentation rather than a checked-in fixture because credentials are environment-specific.
- `kubescan repo --url https://github.com/owner/private-repo.git --provider-native --sparse-path cmd/kubescan --sparse-path README.md --git-http-header "Authorization: Bearer ..."`: provider-native GitHub archive retrieval plus sparse remote-scan example.
- `kubescan repo --url git@github.com:owner/private-repo.git --git-ssh-command "ssh -i ..."`: credentialed private Git SSH example. This is command-only documentation rather than a checked-in fixture because credentials are environment-specific.
- [examples/operator-scanpolicy.yaml](examples/operator-scanpolicy.yaml): operator-mode policy example for periodic and watch-triggered hardening, compliance, and attack-path reporting.
- [examples/operator-scanpolicy-bundles.yaml](examples/operator-scanpolicy-bundles.yaml): operator-mode policy example that loads signed policy, rule, and advisory bundles plus auto-discovered workload SBOMs through `sbomSelector`.
- [examples/operator-scanpolicy-notify.yaml](examples/operator-scanpolicy-notify.yaml): operator-mode policy example for Kubernetes Event and generic webhook delta notifications.
- [examples/operator-scanpolicy-slack.yaml](examples/operator-scanpolicy-slack.yaml): operator-mode policy example for Kubernetes Event, generic webhook, and Slack-compatible delta notifications with `minimumSeverity`.
- [examples/operator-scanpolicy-history.yaml](examples/operator-scanpolicy-history.yaml): operator-mode policy example for long-range history export through `notification.historyWebhookUrl`.
- [examples/operator-scanpolicy-github-sbom.yaml](examples/operator-scanpolicy-github-sbom.yaml): operator-mode policy example for provider-native `GitHubReleaseAsset` SBOM resolution and refresh.
- [examples/operator-sbomreport.yaml](examples/operator-sbomreport.yaml): cluster-native `SBOMReport` example for operator-managed workload SBOM correlation.
- [examples/operator-scanpolicy-remote-sboms.yaml](examples/operator-scanpolicy-remote-sboms.yaml): operator-mode policy example for remote `HTTP` and `OCIImage` SBOM sources with secret-backed auth and refresh intervals.
- [deploy/node-collector/node-collector.yaml](deploy/node-collector/node-collector.yaml): optional Phase 1B node-collector deployment for kubelet configuration posture.
- [deploy/operator/operator.yaml](deploy/operator/operator.yaml): cluster-wide operator deployment example with `ScanPolicy` discovery enabled.
- [deploy/operator/operator-namespace.yaml](deploy/operator/operator-namespace.yaml): reduced-privilege namespace-scoped operator deployment that uses `--namespace`, `--namespaced-only`, and `--default-only`.
- [examples/fs-demo/.env](examples/fs-demo/.env) + [examples/fs-demo/deployment.yaml](examples/fs-demo/deployment.yaml): combined filesystem and manifest discovery example. Key findings: `KF001` and `KS010`.
- [examples/secret-demo/app.env](examples/secret-demo/app.env) + [examples/secret-demo/id_rsa](examples/secret-demo/id_rsa): secret-scanning examples for token-pattern and private-key detection through `KF001`.
- [examples/license-demo/package.json](examples/license-demo/package.json): declared-license policy example for `KL001` and `KL002`, depending on allowlist and denylist settings.
- [examples/sample.yaml](examples/sample.yaml): default-profile manifest scan. Key built-in findings: `KS003`, `KS005`, `KS010`, `KS011`, `KS022`, `KS023`, `KS030`, `KS031`.
- [examples/hardening-sample.yaml](examples/hardening-sample.yaml): hardening-profile checks. Key findings: `KS006`, `KS007`, `KS008`, `KS009`, `KS012`, `KS018`, `KS019`, `KS027`, `KS028`, `KS030`, `KS031`.
- [examples/enterprise-sample.yaml](examples/enterprise-sample.yaml): enterprise-only policy-shaped checks. Key findings: `KS029` and `KS032`.
- [examples/rbac-sample.yaml](examples/rbac-sample.yaml): RBAC relationship and service-account blast-radius checks. Key findings: `KS013`, `KS016`, `KS017`, `KS020`, `KS021`, `KS026`.
- [examples/badpods-sample.yaml](examples/badpods-sample.yaml): Bishop Fox Bad Pods-inspired static escalation-path checks. Key findings: `KS001`, `KS002`, `KS024`, `KS033`, `KS034`, `KS035`, `KS036`.
- [examples/attackpaths-sample.yaml](examples/attackpaths-sample.yaml): graph-based attack-path analysis demo. Key attack paths: `AP001`, `AP002`, `AP003`, `AP004`, `AP005`, `AP006`.
- [examples/scoping-sample.yaml](examples/scoping-sample.yaml): scoping and summary reporting demo. With `--include-kind Service --include-namespace public --report summary`, the example reduces to a single `KS011` summary finding.
- [examples/kustomize/overlays/prod/kustomization.yaml](examples/kustomize/overlays/prod/kustomization.yaml): rendered Kustomize input. Key findings after rendering: `KS010` and `KS011`.
- [examples/helm/api/Chart.yaml](examples/helm/api/Chart.yaml): rendered Helm input. With [examples/helm/api/values.yaml](examples/helm/api/values.yaml), it demonstrates `KS010` and `KS011`; with [examples/helm/api/values-prod.yaml](examples/helm/api/values-prod.yaml), it demonstrates hardening-profile checks such as `KS006`, `KS007`, `KS008`, and `KS009`.
- [examples/vuln-sample.yaml](examples/vuln-sample.yaml) + [examples/vuln-sbom.json](examples/vuln-sbom.json) + [examples/advisories.yaml](examples/advisories.yaml): single-image vulnerability correlation. Key finding: `CVE-2026-0001`.
- [examples/vuln-multi.yaml](examples/vuln-multi.yaml) + [examples/vuln-sbom.json](examples/vuln-sbom.json) + [examples/vuln-worker-sbom.json](examples/vuln-worker-sbom.json) + [examples/advisories.yaml](examples/advisories.yaml): multi-image vulnerability correlation. Key findings: `CVE-2026-0001` and `CVE-2026-0002`.
- [examples/k8s-components-advisories.yaml](examples/k8s-components-advisories.yaml): example advisory bundle for live `--component-vulns` scans against `kubelet`, `kube-proxy`, and visible control-plane components.
- [examples/vm-demo/var/lib/dpkg/status](examples/vm-demo/var/lib/dpkg/status) + [examples/vm-demo/app/requirements.txt](examples/vm-demo/app/requirements.txt): mounted or extracted VM rootfs example for native package inventory, app dependency extraction, and advisory matching through `kubescan vm --rootfs`.
- [examples/controls.yaml](examples/controls.yaml): plain policy controls file. Applied to [examples/sample.yaml](examples/sample.yaml), it suppresses the other sample findings and upgrades `KS010` to `critical`.
- [examples/policy.bundle.yaml](examples/policy.bundle.yaml) + [examples/bundle.pub.pem](examples/bundle.pub.pem): signed policy bundle example for the same control behavior as [examples/controls.yaml](examples/controls.yaml).
- [examples/rules.bundle.yaml](examples/rules.bundle.yaml) + [examples/bundle.pub.pem](examples/bundle.pub.pem): signed rule bundle example. It disables `KS003`, upgrades `KS010` to `critical`, and adds custom rule `CR001`.
- [examples/advisories.bundle.yaml](examples/advisories.bundle.yaml) + [examples/bundle.pub.pem](examples/bundle.pub.pem): signed advisory bundle example for the vulnerability-correlation fixtures.

### Manifest Scan

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml
```

Expected output:

```text
 _  ___   _ ____  _____ ____   ____    _    _   _
| |/ / | | | __ )| ____/ ___| / ___|  / \  | \ | |
| ' /| | | |  _ \|  _| \___ \| |     / _ \ |  \| |
| . \| |_| | |_) | |___ ___) | |___ / ___ \| |\  |
|_|\_\\___/|____/|_____|____/ \____/_/   \_\_| \_|
Kubescan (c) 2026 Daniel Wood https://www.github.com/automatesecurity/kubescan

Kubescan Scan Report

OVERVIEW   VALUE
generated  2026-03-20T18:00:00Z
findings   8
severity mix  crit:0 high:5 med:3 low:0
critical   0
high       5
medium     3
low        0

Top Rules
RULE   COUNT
KS003  1
KS022  1
KS023  1
KS005  1
KS010  1

Findings
payments/Deployment/api
SEV   CATEGORY      RULE   MESSAGE
HIGH  misconfig     KS003  Deployment/api container "api" does not enforce runAsNonRoot
HIGH  misconfig     KS022  Deployment/api container "api" allows privilege escalation
HIGH  misconfig     KS023  Deployment/api container "api" does not enforce a restricted seccomp profile
HIGH  supply-chain  KS010  Deployment/api container "api" uses a mutable image tag
MED   misconfig     KS005  Deployment/api container "api" uses a writable root filesystem
...

payments/Service/api
SEV   CATEGORY  RULE   MESSAGE
HIGH  exposure  KS011  Service/api is publicly exposed through LoadBalancer
```

### Direct Image Scan

```bash
go run ./cmd/kubescan image --image nginx:latest
```

Expected finding types from the initial image-scanning slice:
- `KI001`: mutable image tag
- `KI002`: public or implicit registry
- `KI003`: image may run as root
- `KI004`: plaintext credential-like image environment variable

To include unpacked layer scanning:

```bash
go run ./cmd/kubescan image --image nginx:latest --scan-layers --secret-scan balanced
```

Additional layer-scan finding types:
- `KI005`: sensitive file content detected in an unpacked image layer
- `KI006`: disallowed declared license detected in an unpacked image layer
- `KI007`: declared license outside the allowlist detected in an unpacked image layer

Current image-layer scan behavior:
- layer scanning is opt-in through `--scan-layers`
- secrets reuse the same `patterns|balanced|aggressive` modes used by filesystem and repository scans
- generic plaintext assignment heuristics stay restricted to config-like files in `balanced` mode to reduce noise
- license checks evaluate declared licenses in files such as `package.json`, `Cargo.toml`, and `pyproject.toml` found inside layers

Current native image vulnerability behavior:
- `kubescan image --advisories ...` can extract package inventories directly from Alpine, Debian, RPM, Go module, Maven, Cargo, Composer, NuGet, npm, PyPI, and gem sources in image layers without `--sbom`
- the same extraction pass also reads `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `go.mod`, `pom.xml`, `Cargo.lock`, `composer.lock`, `packages.lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and `Gemfile.lock` from image layers to surface `golang`, `maven`, `cargo`, `composer`, `nuget`, `npm`, `pypi`, and `gem` packages
- extracted package inventories are matched through the same advisory engine used by supplied CycloneDX or SPDX SBOMs
- if `--sbom` is provided, Kubescan uses the supplied SBOM instead of native package extraction
- `--sbom-out` emits the extracted inventory as either a CycloneDX `1.6` JSON or SPDX `2.3` JSON document

The direct image scanner currently inspects registry-backed image config, unpacked text files from image layers, native Alpine, Debian, and RPM package databases, and selected application dependency files from image layers. It does not yet resolve full dependency graphs, parse every language lockfile format, or support every RPM database format.

### Filesystem and Repository Scanning

Scan the included local filesystem demo:

```bash
go run ./cmd/kubescan fs --path ./examples/fs-demo
```

Scan the current repository in summary mode:

```bash
go run ./cmd/kubescan repo --path . --report summary
```

Scan a remote repository in summary mode:

```bash
go run ./cmd/kubescan repo --url https://github.com/owner/repo.git --report summary
```

Scan a remote repository with tighter noise control:

```bash
go run ./cmd/kubescan repo --url https://github.com/owner/repo.git --exclude-path docs/** --exclude-path .plans/** --secret-scan patterns --report summary
```

JSON output for automation:

```bash
go run ./cmd/kubescan fs --path ./examples/fs-demo --format json
```

Expected behavior:
- local text files are inspected for plaintext credential-like assignments
- YAML manifests discovered under the scanned path are parsed as Kubernetes resources and evaluated with the selected built-in profile
- `repo --url` performs a shallow clone to a temp directory and scans that checkout with the same pipeline
- `--ref` can be used with `--url` to fetch and check out a specific branch, tag, or ref after clone
- `--exclude-path` removes matching relative paths or subtrees before secret, license, and manifest evaluation
- `--secret-scan patterns` limits repo/file secret scanning to known token formats and private keys
- `--secret-scan balanced` is the default and adds generic assignment heuristics only for config-like files
- `--secret-scan aggressive` enables generic assignment heuristics across all scanned text files except skipped lockfiles

Included example coverage:
- [examples/fs-demo/.env](examples/fs-demo/.env) triggers `KF001`
- [examples/fs-demo/deployment.yaml](examples/fs-demo/deployment.yaml) triggers `KS010`
- [examples/secret-demo/app.env](examples/secret-demo/app.env) triggers `KF001` through known token-pattern detection
- [examples/secret-demo/id_rsa](examples/secret-demo/id_rsa) triggers `KF001` through private-key detection
- [examples/license-demo/package.json](examples/license-demo/package.json) triggers `KL001` when scanned with `--license-deny GPL-3.0-only`

### License Policy for Filesystem and Repository Scans

Disallow a declared project license:

```bash
go run ./cmd/kubescan fs --path ./examples/license-demo --license-deny GPL-3.0-only --format json
```

Require an allowlist:

```bash
go run ./cmd/kubescan repo --path . --license-allow MIT --license-allow Apache-2.0 --report summary
```

Current behavior:
- license policy currently evaluates declared project licenses in `package.json`, `Cargo.toml`, and `pyproject.toml`
- SPDX-like identifiers are matched token-by-token from the declared license expression
- `--license-deny` emits `KL001` when any declared identifier is denied
- `--license-allow` emits `KL002` when any declared identifier falls outside the configured allowlist

### VM Root Filesystem Scanning

Scan the included extracted rootfs demo:

```bash
go run ./cmd/kubescan vm --rootfs ./examples/vm-demo
```

Scan a VM disk or appliance directly:

```bash
go run ./cmd/kubescan vm --disk ./images/server.qcow2
```

Match vulnerabilities from native rootfs package extraction:

```bash
go run ./cmd/kubescan vm --rootfs ./examples/vm-demo --advisories ./examples/advisories.yaml --format json
```

Emit a CycloneDX or SPDX SBOM from the mounted or extracted rootfs:

```bash
go run ./cmd/kubescan vm --rootfs ./examples/vm-demo --sbom-out ./vm-demo.sbom.json
```

Current behavior:
- `kubescan vm --rootfs` scans mounted or extracted root filesystems directly
- `kubescan vm --disk` supports `.qcow2`, `.vmdk`, `.vhd`, `.vhdx`, `.raw`, `.img`, `.ova`, `.tar`, `.tar.gz`, and `.tgz`
- `.ova` inputs are unpacked first and then scanned through the first supported nested disk image when present
- direct disk-image scanning currently requires local `guestmount` and `guestunmount` from libguestfs for `.qcow2`, `.vmdk`, `.vhd`, `.vhdx`, `.raw`, and `.img`
- secret, license, and manifest scanning reuse the filesystem/repository scan engine
- native SBOM extraction reuses the image package parsers for Alpine, Debian, RPM, Go, Maven, Cargo, Composer, NuGet, `npm`, `pypi`, and `gem` dependency files found under the rootfs
- advisory matching reuses the same vulnerability engine used by direct image and Kubernetes SBOM correlation

### HTML Output

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --format html --out ./findings.html
```

The HTML report is a single self-contained file with:

- overview cards for finding, attack-path, and compliance totals
- summary breakdowns by rule, namespace, category, and attack-path ID
- grouped findings with remediation and expandable evidence
- attack-path cards with step lists and supporting rules
- an embedded raw JSON section for offline review and future integrations
- client-side filtering for findings and attack paths by search text and severity

### JSON Output

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --format json
```

Example shape:

```json
{
  "generatedAt": "2026-03-20T18:00:00Z",
  "summary": {
    "totalBySeverity": {
      "high": 5,
      "medium": 3
    },
    "totalFindings": 8,
    "attackPaths": {
      "totalBySeverity": {
        "critical": 1
      },
      "totalPaths": 1
    }
  },
  "attackPaths": [
    {
      "id": "AP001",
      "title": "Public entry reaches node-compromise preconditions",
      "severity": "critical",
      "target": "Node compromise preconditions"
    }
  ],
  "findings": [
    {
      "id": "abc123",
      "category": "misconfig",
      "ruleId": "KS003",
      "title": "Missing runAsNonRoot",
      "severity": "high",
      "ruleVersion": "v0",
      "resource": {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "namespace": "payments",
        "name": "api"
      },
      "message": "Deployment/api container \"api\" does not enforce runAsNonRoot",
      "evidence": {
        "container": "api"
      },
      "remediation": "Set securityContext.runAsNonRoot=true on each container or at the pod security context level.",
      "timestamp": "2026-03-20T18:00:00Z"
    }
  ]
}
```

### OCSF Output

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --compliance k8s-cis --format ocsf-json
```

Kubescan currently exports OCSF `1.8.0` JSON events for:
- `Application Security Posture Finding` for `KS*` posture, exposure, identity, and supply-chain findings
- `Vulnerability Finding` for SBOM/advisory matches such as `CVE-*`
- `Compliance Finding` for built-in compliance control results when `--compliance` is enabled

Example shape:

```json
[
  {
    "class_uid": 7,
    "class_name": "Application Security Posture Finding",
    "category_uid": 2,
    "category_name": "Findings",
    "type_uid": 701,
    "severity_id": 4,
    "metadata": {
      "version": "1.8.0",
      "product": {
        "name": "kubescan"
      }
    },
    "finding_info": {
      "uid": "finding-1",
      "title": "Mutable image tag"
    }
  }
]
```

Current OCSF mapping notes:
- The exporter targets the stable OCSF `1.8.0` schema version
- Attack paths are not exported yet
- The current output is JSON array form, not NDJSON
- Compliance export includes both passing and failing controls when `--compliance` is requested

### SARIF Output

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --format sarif --out ./findings.sarif
```

The generated file is valid SARIF `2.1.0` and includes:
- Rule metadata for each reported Kubescan rule
- Result severity mapped to SARIF levels
- Resource locations encoded as `k8s://<namespace>/<kind>/<name>`
- Remediation text in the SARIF rule help content

Example shape:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "kubescan",
          "version": "dev",
          "rules": [
            {
              "id": "KS010",
              "name": "Mutable image tag",
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "KS010",
          "level": "error",
          "message": {
            "text": "Deployment/api container \"api\" uses a mutable image tag"
          }
        }
      ]
    }
  ]
}
```

### OCSF Class Mapping

Kubescan currently maps to these OCSF classes:
- `Application Security Posture Finding (class_uid 7)` for built-in posture findings such as `KS001`, `KS010`, `KS021`, and similar non-vulnerability findings
- `Vulnerability Finding (class_uid 2)` for advisory/SBOM matches
- `Compliance Finding (class_uid 3)` for compliance control results

The current implementation targets OCSF `1.8.0` and is based on the official schema in the [ocsf-schema repository](https://github.com/ocsf/ocsf-schema) and the class definitions for [Application Security Posture Finding](https://schema.ocsf.io/1.8.0/classes/application_security_posture_finding), [Vulnerability Finding](https://schema.ocsf.io/1.8.0/classes/vulnerability_finding), and [Compliance Finding](https://schema.ocsf.io/1.8.0/classes/compliance_finding).

### Cluster Scan

```bash
go run ./cmd/kubescan scan --namespace payments --format table
```

This uses your current kubeconfig context unless `--kubeconfig` or `--context` is supplied.

### Profile-Specific Examples

Hardening profile example:

```bash
go run ./cmd/kubescan scan --input ./examples/hardening-sample.yaml --profile hardening
```

This demonstrates operational and namespace-posture checks such as missing probes/resources, service-account token auto-mounting, Secret usage, default service account use, and weak Pod Security Admission labels.

Enterprise profile example:

```bash
go run ./cmd/kubescan scan --input ./examples/enterprise-sample.yaml --profile enterprise
```

This demonstrates enterprise-only checks such as plaintext credential-like values in manifests or ConfigMaps and public or implicit registry sourcing.

### RBAC Relationship Analysis

```bash
go run ./cmd/kubescan scan --input ./examples/rbac-sample.yaml
```

This demonstrates wildcard RBAC, secret-read reachability, cluster-admin reachability, and over-privileged workload service accounts.

### Bishop Fox Bad Pods-Inspired Checks

```bash
go run ./cmd/kubescan scan --input ./examples/badpods-sample.yaml --profile hardening
```

This example is aligned with Bishop Fox's [Bad Pods: Kubernetes Pod Privilege Escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) research and the accompanying [badPods repository](https://github.com/BishopFox/badPods). It demonstrates static precondition detection for privileged plus `hostPID`, privileged plus `hostPath`, sensitive `hostPath` mounts, and control-plane scheduling indicators.

### Attack Path Analysis

```bash
go run ./cmd/kubescan scan --input ./examples/attackpaths-sample.yaml --attack-paths --format json
```

This example demonstrates the in-memory attack graph and emits:
- `AP001`: internet-exposed Service to node-compromise preconditions
- `AP002`: workload to wildcard RBAC
- `AP003`: workload to Secret-read RBAC
- `AP004`: internet-exposed Service to Secret-read RBAC
- `AP005`: internet-exposed Service to `cluster-admin`
- `AP006`: control-plane targeted workload with node-compromise preconditions

Human-readable table and HTML output are also supported:

```bash
go run ./cmd/kubescan scan --input ./examples/attackpaths-sample.yaml --attack-paths
```

The attack-path output is intentionally curated and deterministic: Kubescan builds an in-memory Kubernetes graph for the current scan, links existing findings back to graph resources as supporting evidence, and emits predefined path patterns rather than arbitrary user-defined graph queries.

### Scoped Summary Reporting

```bash
go run ./cmd/kubescan scan --input ./examples/scoping-sample.yaml --include-kind Service --include-namespace public --report summary --format json
```

The scoped summary reduces the example to a single public-service finding summary for `public/Service/web`.

### Kustomize Input

```bash
go run ./cmd/kubescan scan --kustomize-dir ./examples/kustomize/overlays/prod
```

This renders the included Kustomize overlay and scans the resulting manifest set. In the checked-in example, the rendered workload and service demonstrate `KS010` and `KS011`.

### Helm Input

```bash
go run ./cmd/kubescan scan --helm-chart ./examples/helm/api --helm-values ./examples/helm/api/values.yaml
```

This renders the included Helm chart and scans the resulting manifest set. With `values.yaml`, the example demonstrates `KS010` and `KS011`. With `values-prod.yaml`, it demonstrates hardening-profile checks such as missing resource settings and probes.

### Vulnerability Correlation

```bash
go run ./cmd/kubescan scan --input ./examples/vuln-sample.yaml --sbom ./examples/vuln-sbom.json --advisories ./examples/advisories.yaml --policy ./examples/controls.yaml
```

Observed output:

```text
SEVERITY  RULE           RESOURCE                 MESSAGE
high      CVE-2026-0001  payments/Deployment/api  Deployment/api container "api" image "ghcr.io/acme/api:1.0.0" contains vulnerable package openssl 1.1.1-r0 (CVE-2026-0001)
```

This uses:
- [examples/vuln-sample.yaml](examples/vuln-sample.yaml)
- [examples/vuln-sbom.json](examples/vuln-sbom.json)
- [examples/advisories.yaml](examples/advisories.yaml)

Current vulnerability matching behavior:
- Matches workload images to supplied CycloneDX JSON or SPDX JSON SBOMs by exact image reference
- Extracts OS packages from `apk`, `deb`, and `rpm` package URLs
- Matches advisories by exact `packageName`, `ecosystem`, and version constraint evaluation
- Emits findings as category `vuln`

### Multi-SBOM Correlation

```bash
go run ./cmd/kubescan scan --input ./examples/vuln-multi.yaml --sbom ./examples/vuln-sbom.json --sbom ./examples/vuln-worker-sbom.json --advisories ./examples/advisories.yaml
```

Observed vulnerability findings in that run:

```text
high      CVE-2026-0001  payments/Deployment/multi  Deployment/multi container "api" image "ghcr.io/acme/api:1.0.0" contains vulnerable package openssl 1.1.1-r0 (CVE-2026-0001)
medium    CVE-2026-0002  payments/Deployment/multi  Deployment/multi container "worker" image "ghcr.io/acme/worker:2.0.0" contains vulnerable package busybox 1.36.0-r0 (CVE-2026-0002)
```

Multi-SBOM behavior:
- You can repeat `--sbom` to supply one SBOM per image
- Kubescan indexes SBOMs by image reference
- Only containers with a matching SBOM are eligible for vulnerability findings
- A single scan can therefore correlate multiple deployed images in one run

Supported advisory constraint syntax:
- Exact version: `1.1.1-r0`
- Equality: `=1.1.1-r0` or `==1.1.1-r0`
- Greater/less than: `>1.1.1-r0`, `>=1.1.1-r0`, `<1.1.1-r2`, `<=1.1.1-r2`
- Ranges with AND semantics inside one entry: `>=1.1.1-r0, <1.1.1-r2`
- Multiple `affectedVersions` entries are treated as OR conditions

Current version ordering behavior by ecosystem:
- `deb`: Debian-style epoch, upstream version, revision, and `~` pre-release ordering
- `rpm`: segmented RPM-style ordering with numeric vs alphanumeric comparison plus `~` and `^`
- `apk`: segmented package ordering appropriate for Alpine-style versions such as `1.1.1-r0`

### Control-Plane and Node Vulnerability Scanning

```bash
go run ./cmd/kubescan scan --component-vulns --advisories ./examples/k8s-components-advisories.yaml --namespace kube-system
```

Expected finding shape:

```text
SEVERITY  RULE           RESOURCE               MESSAGE
high      CVE-2026-2001  Node/worker-1          Node/worker-1 cluster component "kubelet" version "v1.31.1" is affected by CVE-2026-2001
critical  CVE-2026-2002  kube-system/Pod/...    Pod/... cluster component "kube-apiserver" version "v1.31.1" is affected by CVE-2026-2002
```

Current live component matching behavior:
- `--component-vulns` uses the existing advisory bundle format with ecosystem `kubernetes`
- Node findings come from `node.status.nodeInfo.kubeletVersion` and `node.status.nodeInfo.kubeProxyVersion`
- Control-plane findings come from visible `kube-system` pod images for `kube-apiserver`, `kube-controller-manager`, `kube-scheduler`, and `etcd`
- Version constraints reuse the same advisory matcher used for image-package vulnerability correlation
- The included [examples/k8s-components-advisories.yaml](examples/k8s-components-advisories.yaml) file is a live-scan demo input, not a synthetic manifest fixture

Current limitations:
- This mode is live-cluster only; it does not run from `--input`, `--helm-chart`, or `--kustomize-dir`
- Managed control planes may hide some components from the Kubernetes API, in which case Kubescan can still report node components but may not see apiserver/controller-manager/scheduler/etcd versions
- Namespace scoping affects pod-derived control-plane visibility; node components remain cluster-scoped
- Advisory matching currently depends on version visibility, not package-manager or OS distribution metadata

### Policy Controls

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --policy ./examples/controls.yaml
```

Expected output:

```text
Kubescan Scan Report

OVERVIEW   VALUE
generated  2026-03-20T18:00:00Z
findings   1
severity mix  crit:1 high:0 med:0 low:0
critical   1
high       0
medium     0
low        0

Findings
payments/Deployment/api
SEV   CATEGORY      RULE   MESSAGE
CRIT  supply-chain  KS010  Deployment/api container "api" uses a mutable image tag
```

The included controls file suppresses the other default-profile sample findings and upgrades `KS010` from `high` to `critical`.

### Signed Policy Bundles

Kubescan can verify signed policy-control bundles before applying them in a scan.

Verification command:

```bash
go run ./cmd/kubescan verify bundle --bundle ./examples/policy.bundle.yaml --key ./examples/bundle.pub.pem
```

Signed-scan example:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --policy-bundle ./examples/policy.bundle.yaml --bundle-key ./examples/bundle.pub.pem
```

Current signed policy bundle format:

```yaml
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: SignedBundle
metadata:
  type: policy-controls
  algorithm: ed25519
payload: |-
  apiVersion: kubescan.automatesecurity.github.io/v1alpha1
  kind: PolicyControls
  suppressions:
    - ruleId: KS012
      namespace: payments
      kind: Deployment
      name: api
      expiresOn: 2026-12-31
  severityOverrides:
    - ruleId: KS010
      namespace: payments
      kind: Deployment
      name: api
      severity: critical
signature: BASE64_ED25519_SIGNATURE
```

Signed policy bundle behavior:
- The signature is verified over the exact embedded `payload` bytes
- The current implementation supports bundle type `policy-controls`
- The current implementation supports algorithm `ed25519`
- Plain `--policy` files still work; signed bundles are an additional trusted path

### Signed Rule Bundles

Kubescan can verify signed rule bundles before applying them to the built-in ruleset.

Signed-scan example:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --rules-bundle ./examples/rules.bundle.yaml --bundle-key ./examples/bundle.pub.pem
```

Current signed rule bundle format:

```yaml
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: SignedBundle
metadata:
  type: rules
  algorithm: ed25519
payload: |-
  apiVersion: kubescan.automatesecurity.github.io/v1alpha1
  kind: RuleBundle
  rules:
    - id: KS003
      enabled: false
    - id: KS010
      severity: critical
signature: BASE64_ED25519_SIGNATURE
```

Signed rule bundle behavior:
- The signature is verified over the exact embedded `payload` bytes
- The current implementation supports bundle type `rules`
- The current implementation supports algorithm `ed25519`
- The current implementation can configure the built-in ruleset and evaluate declarative custom rules
- Built-in rule controls today are per-rule enable/disable and severity override
- Custom rules currently support `container`, `workload`, `service`, `namespace`, and `serviceAccount` targets
- Custom rules currently support `equals`, `not_equals`, `contains`, `not_contains`, `exists`, `one_of`, `greater_than`, `greater_or_equal`, `less_than`, and `less_or_equal`
- Custom rules support boolean composition with `all`, `any`, and `not` match clauses, including nested boolean groups
- Namespace custom rules can use derived aggregate fields including `workloadCount`, `serviceCount`, `publicServiceCount`, `networkPolicyCount`, `ingressPolicyCount`, `egressPolicyCount`, `hasWorkloads`, `hasServices`, `hasPublicService`, `hasNetworkPolicy`, `hasIngressPolicy`, and `hasEgressPolicy`
- Service account custom rules can use derived relationship fields including `workloadCount`, `automountingWorkloadCount`, `bindingCount`, `hasWorkloads`, `hasAutomountingWorkloads`, `hasBindings`, `hasWildcardPermissions`, and `hasSecretReadPermissions`

Example signed rule bundle payload:

```yaml
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: RuleBundle
rules:
  - id: KS003
    enabled: false
  - id: KS010
    severity: critical
customRules:
  - id: CR001
    target: container
    category: supply-chain
    title: Custom registry allowlist
    severity: high
    message: Container image is from ghcr.io/acme.
    remediation: Use the approved registry pattern.
    match:
      all:
        - field: image
          op: contains
          value: ghcr.io/acme/
        - field: workload.namespace
          op: equals
          value: payments
  - id: CR002
    target: namespace
    category: exposure
    title: Namespace lacks network policy coverage
    severity: high
    message: Namespace has workloads but no network policies.
    remediation: Add default-deny and allow-list network policies.
    match:
      all:
        - field: workloadCount
          op: greater_than
          value: 0
      any:
        - all:
            - field: publicServiceCount
              op: greater_or_equal
              value: 1
            - field: serviceCount
              op: greater_than
              value: 0
        - field: hasPublicService
          op: equals
          value: true
      not:
        - field: hasNetworkPolicy
          op: equals
          value: true
```

`all` predicates must all match. If `any` is present, at least one of its predicates must match. If any `not` predicate matches, the rule does not fire. Entries inside those lists can be either leaf predicates or nested `all` / `any` / `not` groups.

### Policy File Format

Kubescan currently supports a YAML controls file with:
- `suppressions`
- `severityOverrides`

Each suppression supports:
- `ruleId`
- `namespace`
- `kind`
- `name`
- `expiresOn`
- `reason`
- `id`

Each severity override supports:
- `ruleId`
- `namespace`
- `kind`
- `name`
- `severity`

Example:

```yaml
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: PolicyControls
suppressions:
  - id: suppress-token-automount
    ruleId: KS012
    namespace: payments
    kind: Deployment
    name: api
    expiresOn: 2026-12-31
    reason: The workload still requires Kubernetes API access.
severityOverrides:
  - ruleId: KS010
    namespace: payments
    kind: Deployment
    name: api
    severity: critical
```

Behavior:
- Suppressions match on `ruleId` and any provided resource scope fields
- Expired suppressions are ignored
- `expiresOn` accepts `YYYY-MM-DD` or RFC3339
- Severity overrides apply to matching findings before reporting
- If a severity override changes a finding, JSON output includes `originalSeverity`

### Threshold-Based Exit Control

Use `--fail-on` to gate CI on a severity threshold instead of failing on any finding.

Example:

```bash
go run ./cmd/kubescan scan --input ./examples/sample.yaml --policy ./examples/controls.yaml --fail-on critical
```

Observed output:

```text
Kubescan Scan Report

OVERVIEW   VALUE
generated  2026-03-20T18:00:00Z
findings   1
severity mix  crit:1 high:0 med:0 low:0
critical   1
high       0
medium     0
low        0

Findings
payments/Deployment/api
SEV   CATEGORY      RULE   MESSAGE
CRIT  supply-chain  KS010  Deployment/api container "api" uses a mutable image tag
```

This command exits with code `4` because the remaining finding is `critical`.

### Advisory Bundle Format

Kubescan currently accepts a YAML advisory bundle.

Example:

```yaml
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: AdvisoryBundle
advisories:
  - id: CVE-2026-0001
    aliases:
      - GHSA-demo-0001
    packageName: openssl
    ecosystem: apk
    affectedVersions:
      - ">=1.1.1-r0, <1.1.1-r2"
    fixedVersion: 1.1.1-r1
    severity: high
    summary: OpenSSL package vulnerability in the base image
```

Current advisory behavior:
- `affectedVersions` accepts exact versions and comparator expressions
- Clauses separated by commas are combined with AND semantics
- Multiple entries in `affectedVersions` are combined with OR semantics
- Matching now uses ecosystem-specific comparison logic for `deb`, `rpm`, and `apk`

### Signed Advisory Bundles

Kubescan can verify signed advisory bundles before using them in a scan.

Verification command:

```bash
go run ./cmd/kubescan verify bundle --bundle ./examples/advisories.bundle.yaml --key ./examples/bundle.pub.pem
```

Signed-scan example:

```bash
go run ./cmd/kubescan scan --input ./examples/vuln-sample.yaml --sbom ./examples/vuln-sbom.json --advisories-bundle ./examples/advisories.bundle.yaml --bundle-key ./examples/bundle.pub.pem
```

Local vulnerability database example:

```bash
go run ./cmd/kubescan db build --source-manifest ./examples/vulndb-sources.yaml --out ./advisories.db --metadata-out ./advisories.db.metadata.json
go run ./cmd/kubescan db info --db ./advisories.db
go run ./cmd/kubescan scan --input ./examples/vuln-sample.yaml --sbom ./examples/vuln-sbom.json --advisories-db ./advisories.db
```

Signed and verifiable database artifact example:

```bash
go run ./cmd/kubescan db build --advisories ./examples/advisories.yaml --out ./advisories.db --metadata-out ./advisories.db.metadata.json
cosign sign-blob --yes --new-bundle-format --bundle ./advisories.db.sigstore.json ./advisories.db
go run ./cmd/kubescan db verify --db ./advisories.db --metadata ./advisories.db.metadata.json --bundle ./advisories.db.sigstore.json
go run ./cmd/kubescan db update --url https://example.com/kubescan/advisories.db --metadata-url https://example.com/kubescan/advisories.db.metadata.json --bundle-url https://example.com/kubescan/advisories.db.sigstore.json --out ./cache/advisories.db
```

The current vulnerability database flow is still early, but it now has a manifest-driven upstream-ingestion slice. It can compile existing advisory bundles plus OSV JSON, Alpine SecDB, Debian Security Tracker, Ubuntu Security Notices, and Kubernetes official CVE-feed sources from local files or remote URLs into a reusable SQLite artifact, apply deterministic source-priority rules while merging overlapping advisories, emit metadata for distribution, verify Sigstore-signed database bundles locally, download them from a remote URL with optional verification, and point `scan`, `image`, or `vm` at the cached database with `--advisories-db`, while keeping the existing plain advisory file and signed advisory bundle paths unchanged. Legacy detached Ed25519 database signatures are still accepted for compatibility, but Sigstore bundles are now the canonical database-artifact trust path.

The checked-in source manifest example is [examples/vulndb-sources.yaml](./examples/vulndb-sources.yaml). It demonstrates the current source kinds and priority model:

- `AdvisoryBundle` for curated Kubescan-native advisory bundles
- `SignedAdvisoryBundle` for signed curated advisory bundles
- `AlpineSecDB` for official Alpine SecDB JSON from local files or remote URLs
- `DebianSecurityTracker` for the official Debian tracker JSON with a required `release` selector such as `bookworm`
- `UbuntuSecurityNotices` for Canonical Ubuntu security notices, either as a single OSV JSON file or a notices archive, with a required `release` selector such as `24.04`
- `KubernetesOfficialCVEFeed` for the official Kubernetes CVE JSON feed
- `OSV` for OSV JSON from local files or remote URLs
- `GitHubReleaseAsset` for release-published OSV JSON, Alpine SecDB JSON, or advisory bundle artifacts

The current feed-native sources are OSV JSON, Alpine SecDB JSON, Debian Security Tracker JSON, Ubuntu Security Notices, and the Kubernetes official CVE feed. Kubescan normalizes supported OSV ecosystems into its current advisory model for `apk`, `deb`, `golang`, `maven`, `npm`, `cargo`, `composer`, `nuget`, `pypi`, `gem`, and `kubernetes` package matching. Alpine SecDB is normalized into `apk` advisories by package name and fixed version. Debian tracker sources are release-scoped and currently normalize package advisories for a selected Debian release such as `bookworm`. Ubuntu notices are also release-scoped and normalize official Ubuntu OSV notices into `deb` advisories, including binary package fan-out when the notice includes binary metadata. The Kubernetes feed parser can consume embedded OSV blocks when present and falls back to the feed's textual affected-version sections for component advisories such as `kubelet`, `kube-apiserver`, and `kube-controller-manager`.

The checked-in feed examples are:

- [examples/osv-sample.json](./examples/osv-sample.json)
- [examples/alpine-secdb-sample.json](./examples/alpine-secdb-sample.json)
- [examples/debian-tracker-sample.json](./examples/debian-tracker-sample.json)
- [examples/ubuntu-osv-sample.json](./examples/ubuntu-osv-sample.json)
- [examples/kubernetes-cve-feed-sample.json](./examples/kubernetes-cve-feed-sample.json)

When two sources describe the same package advisory and share an overlapping ID or alias set, Kubescan keeps the higher-priority source record. Vendor-style distro feeds such as Debian Security Tracker and Ubuntu Security Notices outrank Alpine SecDB and OSV by default; Alpine SecDB outranks OSV by default unless you override priorities explicitly.

For automated publishing, the repo now includes a scheduled workflow at [.github/workflows/vulndb.yaml](./.github/workflows/vulndb.yaml). By default it runs daily at `06:00 UTC`, builds from the checked-in [examples/vulndb-sources-public.yaml](./examples/vulndb-sources-public.yaml), signs the database with Sigstore keyless signing through GitHub Actions OIDC, uploads the DB artifacts as workflow artifacts, and also publishes them to the `vulndb-latest` GitHub release. The default public manifest currently uses live Alpine SecDB, Debian Security Tracker for `bookworm`, and the official Kubernetes CVE feed. Ubuntu support is implemented in the builder and demonstrated in the checked-in local manifest, but because it is archive-based and heavier than the other feeds it is not enabled in the default scheduled public manifest yet. The same workflow also supports manual `workflow_dispatch` runs with overridable `manifest_path` and `release_tag` inputs, so you can test a one-off source manifest or publish a pinned DB snapshot without changing the daily schedule.

By default, `kubescan db verify` and `kubescan db update` expect the official Kubescan database bundle to be signed by the repository workflow identity matching `https://github.com/automatesecurity/kubescan/.github/workflows/vulndb.yaml@...` with the GitHub Actions OIDC issuer `https://token.actions.githubusercontent.com`. You can override that trust policy for custom or mirrored database publishers with `--certificate-identity`, `--certificate-identity-regexp`, `--certificate-oidc-issuer`, `--certificate-oidc-issuer-regexp`, `--trusted-root`, `--tuf-cache`, and `--tuf-mirror`.

Once that workflow is publishing assets, a client-side update can point directly at the release-hosted files:

```bash
go run ./cmd/kubescan db update \
  --url https://github.com/automatesecurity/kubescan/releases/download/vulndb-latest/kubescan-vulndb.sqlite \
  --metadata-url https://github.com/automatesecurity/kubescan/releases/download/vulndb-latest/kubescan-vulndb.sqlite.metadata.json \
  --bundle-url https://github.com/automatesecurity/kubescan/releases/download/vulndb-latest/kubescan-vulndb.sqlite.sigstore.json \
  --out ./cache/advisories.db
```

Current signed bundle format:

```yaml
apiVersion: kubescan.automatesecurity.github.io/v1alpha1
kind: SignedBundle
metadata:
  type: advisories
  algorithm: ed25519
payload: |-
  apiVersion: kubescan.automatesecurity.github.io/v1alpha1
  kind: AdvisoryBundle
  advisories:
    - id: CVE-2026-0001
      packageName: openssl
      ecosystem: apk
      affectedVersions:
        - ">=1.1.1-r0, <1.1.1-r2"
      fixedVersion: 1.1.1-r1
      severity: high
      summary: OpenSSL package vulnerability in the base image
signature: BASE64_ED25519_SIGNATURE
```

Signed bundle behavior:
- The signature is verified over the exact embedded `payload` bytes
- The current implementation supports bundle type `advisories`
- The current implementation supports algorithm `ed25519`
- Plain `--advisories` files still work; signed bundles are an additional trusted path

The same `verify bundle` command also verifies signed policy and rule bundles.

## Exit Codes

Kubescan currently uses:
- `0`: Scan completed and no findings were produced
- `1`: Runtime or I/O error
- `2`: Invalid CLI usage
- `3`: Scan completed and findings were produced
- `4`: `--fail-on` threshold was met or exceeded

Default behavior:
- Without `--fail-on`, any findings return `3`
- With `--fail-on`, findings below the threshold return `0`
- With `--fail-on`, any finding at or above the threshold returns `4`

## Rule Catalog

Built-in misconfiguration rules:

Built-in profile behavior:
- `default` enables the high-signal subset used when `--profile` is omitted
- `hardening` adds operational and namespace-posture checks such as probes, resources, and Pod Security Admission labels
- `enterprise` adds the full built-in catalog except the older roll-up-only `KS014`
- `KS014` is retained as a bundle-addressable roll-up rule and is not enabled by the built-in profiles

| Rule ID | Title | Severity |
|---|---|---|
| `KS001` | Privileged container | `critical` |
| `KS002` | Host namespace access | `high` |
| `KS003` | Missing runAsNonRoot | `high` |
| `KS004` | Container runs as root | `high` |
| `KS005` | Writable root filesystem | `medium` |
| `KS006` | Missing resource requests | `medium` |
| `KS007` | Missing resource limits | `medium` |
| `KS008` | Missing liveness probe | `medium` |
| `KS009` | Missing readiness probe | `medium` |
| `KS010` | Mutable image tag | `high` |
| `KS011` | Public service exposure | `high` |
| `KS012` | Service account token auto-mounting | `medium` |
| `KS013` | Wildcard RBAC permissions | `critical` |
| `KS014` | Missing namespace network policy | `medium` |
| `KS015` | Dangerous Linux capabilities | `high` |
| `KS016` | Subject reaches wildcard RBAC permissions | `critical` |
| `KS017` | Workload uses an over-privileged service account | `critical` |
| `KS018` | Secret exposed through environment variables | `high` |
| `KS019` | Secret mounted into workload | `medium` |
| `KS020` | Subject reaches secret-read RBAC permissions | `high` |
| `KS021` | Workload uses a service account with secret-read permissions | `high` |
| `KS022` | Privilege escalation allowed | `high` |
| `KS023` | Missing or unconfined seccomp profile | `high` |
| `KS024` | HostPath volume mounted | `high` |
| `KS025` | Host port exposure | `medium` |
| `KS026` | Subject reaches cluster-admin | `critical` |
| `KS027` | Workload uses the default service account | `medium` |
| `KS028` | Missing or weak Pod Security Admission labels | `medium` |
| `KS029` | Sensitive value detected in manifest data | `high` |
| `KS030` | Missing namespace ingress isolation | `medium` |
| `KS031` | Missing namespace egress isolation | `medium` |
| `KS032` | Image sourced from a public or implicit registry | `medium` |
| `KS033` | Privileged container with hostPID access | `critical` |
| `KS034` | Privileged workload with hostPath access | `critical` |
| `KS035` | Sensitive hostPath mount | `critical` |
| `KS036` | Control-plane scheduling indicator | `high` |
| `KS037` | Control-plane node is schedulable | `high` |
| `KS038` | Node uses legacy Docker runtime | `medium` |
| `KS039` | Node advertises an external IP | `medium` |
| `KS040` | Node is not Ready | `high` |
| `KS041` | Kubelet version skew detected | `medium` |
| `KS042` | kube-proxy version skew detected | `medium` |
| `KS043` | Visible control-plane component version skew detected | `high` |
| `KS044` | Node reports resource pressure | `high` |
| `KS045` | Node network is unavailable | `high` |
| `KS046` | Kubelet anonymous authentication enabled | `critical` |
| `KS047` | Kubelet webhook authentication disabled | `high` |
| `KS048` | Kubelet authorization mode is not webhook | `high` |
| `KS049` | Kubelet read-only port enabled | `high` |
| `KS050` | Kubelet protectKernelDefaults disabled | `medium` |

Vulnerability findings use the advisory ID as `ruleId`, for example `CVE-2026-0001`.

Built-in direct image rules:

| Rule ID | Title | Severity |
|---|---|---|
| `KI001` | Mutable image tag | `high` |
| `KI002` | Image sourced from a public or implicit registry | `medium` |
| `KI003` | Image may run as root | `high` |
| `KI004` | Image config contains sensitive environment variable | `high` |
| `KI005` | Image layer contains sensitive file content | `high` |
| `KI006` | Image layer declares a disallowed license | `high` |
| `KI007` | Image layer declares a license outside the allowlist | `medium` |

Filesystem and repository rules:

| Rule ID | Title | Severity |
|---|---|---|
| `KF001` | Sensitive value detected in file | `high` |
| `KL001` | Disallowed license detected | `high` |
| `KL002` | License not in allowlist | `medium` |

## Development

### Run Tests

```bash
go test ./...
```

The checked-in GitHub Actions workflow at `./.github/workflows/ci.yaml` enforces:

- `gofmt` cleanliness across all Go source files
- `go test ./...`
- repository drift tests that fail if README references, checked-in schemas, or CRD documentation fall out of sync

### Performance Validation

Kubescan now includes checked-in benchmark coverage for larger synthetic inventories in `./internal/perf/benchmark_test.go`.

Run the benchmark suite with:

```bash
go test -run '^$' -bench . ./internal/perf -benchmem
```

The current benchmark coverage focuses on:

- enterprise-profile rule evaluation across a large synthetic inventory
- attack-path analysis over the same large inventory
- JSON serialization of a large `report.automatesecurity.github.io/v1` scan result
- workload vulnerability matching across a large synthetic SBOM/advisory set
- filesystem and repository-style scanning across a large synthetic file tree

Current local baseline on this repository as of March 21, 2026:

- large enterprise inventory rule evaluation: about `6.7ms/op`
- large inventory attack-path analysis: about `5.6ms/op`
- large JSON result serialization: about `33.0ms/op`
- large workload SBOM/advisory correlation: about `1.2ms/op`
- large filesystem tree scan: about `1.84s/op`

### Format Code

```bash
gofmt -w ./cmd/kubescan/main.go ./pkg/cli/*.go ./pkg/imagescan/*.go ./pkg/k8s/*.go ./pkg/policy/*.go ./pkg/report/*.go ./pkg/vuln/*.go
```

### Repository Layout

```text
cmd/kubescan/         CLI entrypoint
cmd/kubescan-node-collector/ Optional Phase 1B node collector binary
pkg/cli/              CLI flow and source selection
pkg/filescan/         Local filesystem and repository path scanning
pkg/imagescan/        Direct OCI image inspection and image-specific findings
pkg/k8s/              Manifest parsing and live cluster collection
pkg/licensescan/      Declared project-license detection and local path license policy
pkg/nodecollector/    Host kubelet-config parsing and NodeReport generation
pkg/policy/           Internal models, built-in rules, and policy controls
pkg/reposcan/         Remote Git clone support for repository scanning
pkg/secretscan/       Reusable secret detection for local files, manifests, and image config
pkg/vuln/             SBOM loading, advisory loading, and vulnerability matching
internal/buildinfo/   Embedded version, commit, and build-date metadata
internal/perf/        Benchmark coverage for large synthetic inventories and report serialization
Dockerfile            Container build for the kubescan CLI
Dockerfile.operator   Container build for the kubescan operator
Dockerfile.node-collector Container build for the kubescan node collector
.goreleaser.yaml      Cross-platform binary packaging and checksums
Dockerfile            Container build for the kubescan CLI with OCI metadata labels
Dockerfile.operator   Container build for the kubescan operator with OCI metadata labels
pkg/report/           Table, JSON, HTML, and SARIF reporting
examples/             Sample manifests, policy controls, signed bundles, rendered-input fixtures, SBOMs, and advisories
schemas/              Checked-in JSON Schema documents for stable scan output and versioned bundle payloads
deploy/node-collector/ Optional node collector deployment manifests
SECURITY.md           Trust model, threat model, and operational security guidance
.github/workflows/    GitHub Actions CI and release workflows
```

## Security Notes

Kubescan now includes a dedicated security and trust model document at `./SECURITY.md`.

- Kubescan reads Kubernetes API objects, manifest contents, image metadata, and local text files under explicitly scanned paths
- It does not read raw Kubernetes Secret data
- It does not need outbound internet access to execute manifest, filesystem, repository, or live cluster scans
- Direct image scanning requires registry access for the referenced image
- Helm and Kustomize source modes execute local `helm`, `kustomize`, or `kubectl kustomize` binaries to render manifests before scanning

The scanner still does not read Secret values. Helm/Kustomize execution and local path scanning should be treated as part of the local trust boundary.

See `./SECURITY.md` for:

- explicit trust boundaries
- signed bundle trust assumptions
- operator security boundaries
- current out-of-scope threats
- operational deployment recommendations

The shipped operator deployment manifests also include baseline runtime hardening with non-root execution, `RuntimeDefault` seccomp, dropped capabilities, read-only root filesystems, and default CPU/memory requests and limits.

## Known Limitations

- No admission-controller or runtime integrations
- Node configuration and infrastructure assessment now includes API-visible Phase 1A plus kubelet-config-focused Phase 1B, but it still does not perform broader host telemetry collection, file-integrity monitoring, runtime process inspection, or full CIS-style node hardening validation
- Secret scanning currently focuses on high-signal token patterns, private keys, and plaintext assignments; it does not yet add entropy-only generic blob detection outside named assignments or support inline suppressions
- Generic secret-assignment heuristics are intentionally restricted to config-like files to reduce false positives in docs, source files, and lockfiles
- Path exclusions currently apply to filesystem and repository scans only; scan-time excludes do not yet integrate with manifest-only, image, or live-cluster modes
- License policy currently evaluates declared project licenses only; it does not yet resolve dependency license trees or classify licenses from unpacked artifacts and image layers
- Remote repository scanning currently relies on the local Git CLI by default, with optional GitHub-native archive retrieval, sparse checkout controls, and explicit HTTPS-header or SSH-command auth support; it does not yet support broader SCM-provider APIs or richer SCM-native metadata
- Vulnerability matching currently supports CycloneDX JSON and SPDX JSON SBOM inputs
- Native image package extraction currently supports Alpine and Debian package databases plus RPM `Packages`, `Packages.db`, and `rpmdb.sqlite` backends; legacy RPM layouts outside those formats are not implemented yet
- Native application dependency extraction from image layers currently supports `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `go.mod`, `pom.xml`, `Cargo.lock`, `composer.lock`, `packages.lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and `Gemfile.lock`; other ecosystem-specific lockfiles are not implemented yet
- Image layer scanning currently inspects unpacked text files and package databases only; it does not yet analyze compiled artifacts inside layers
- Vulnerability matching does not yet implement every edge case from native distro package managers
- Vulnerability matching currently accepts CycloneDX JSON and SPDX JSON SBOM inputs, but still requires exact image reference alignment between workloads and SBOM metadata when no live digest is available
- Direct image scanning supports the local container-registry keychain plus explicit username/password or bearer-token auth, but it does not yet support alternative registry helper configuration beyond the local `go-containerregistry`/CLI environment
- Public-registry detection is heuristic and does not yet support an organization-specific allowlist or image-signature verification policy
- The Bishop Fox-aligned Bad Pods coverage is currently static precondition analysis only; Kubescan does not attempt runtime metadata probing, localhost service reachability tests, kubelet anonymous-auth checks, or exploit validation
- Bundle verification currently supports advisory, policy-control, and rule bundles only
- Bundle verification currently supports Ed25519 only
- Signed bundle verification now authenticates the full signed bundle envelope metadata and payload together; previously generated example bundles were rotated to the fixed format
- Declarative custom rules currently support simple predicate matching over container, workload, service, and namespace aggregate fields
- Relationship-aware custom rules currently support namespace and service-account derived aggregates rather than arbitrary joins or graph expressions
- Helm rendering requires a local `helm` binary
- Kustomize rendering requires either a local `kustomize` binary or `kubectl`
- The current operator mode performs periodic scans, watch-triggered debounced rescans with namespace- and kind-aware policy routing, independent background refresh for remote SBOM sources, compact per-reconcile delta summaries, Kubernetes Event notifications, generic webhook and Slack-compatible delta delivery, history-webhook export, and bounded rolling trend/history summaries, but it does not yet provide admission enforcement
- Operator reports are stored as cluster-scoped `ScanReport` CRDs with bounded finding and attack-path lists plus optional stale-report pruning and TTL-based cleanup; large clusters may still require tighter caps or namespace-scoped policies
- Operator remote SBOM fetching currently supports HTTPS URLs, OCI image references, and provider-native GitHub release assets with interval-based caching plus independent background refresh; broader provider coverage is not implemented yet

## Contributing

At this stage, contributions should preserve these constraints:
- Keep scanning deterministic
- Prefer explicit internal models over scattered ad hoc parsing
- Add unit tests for every new rule and collector behavior
- Keep the CI workflow green locally with `gofmt` and `go test ./...` before changing contracts or docs
- Do not claim support in docs before the code path exists
- Keep README and CLI help aligned with actual behavior

## License

Apache 2.0. See [LICENSE](./LICENSE).
