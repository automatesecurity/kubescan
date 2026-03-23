# Security Model

This document describes Kubescan's current trust model, threat model, and major security boundaries.

## Trust Model

Kubescan currently operates with these trust assumptions:

- The local machine or CI runner executing Kubescan is trusted.
- The operator deployment namespace and its service account are trusted within the permissions granted to them.
- Signed policy, rule, and advisory bundles are trusted only after successful Ed25519 signature verification against a trusted public key.
- Unsigned inputs such as local files, remote repositories, SBOMs, manifests, Helm charts, Kustomize trees, and image references are treated as untrusted scan inputs.
- Kubernetes API data is trusted only as inventory input, not as proof that a resource is safe.
- Optional `NodeReport` CRDs produced by the node collector are trusted only as inventory input from a host-mounted collector running with the RBAC and host access you grant it.

## Threat Model

Kubescan is designed to help identify:

- Kubernetes misconfiguration and posture issues
- RBAC privilege escalation paths and blast radius
- Secret exposure patterns and high-signal plaintext credential material
- Vulnerability exposure from supplied or discovered package inventories
- Relationship-aware attack paths across Kubernetes resources

Kubescan is not currently designed to:

- prevent exploitation at runtime
- contain malicious code execution inside scanned workloads
- replace admission control or workload isolation
- validate exploitability of a detected vulnerability or attack path
- guarantee full host or control-plane hardening coverage

Admission-time or runtime prevention may be explored in the future as a separate product direction, but it is not part of Kubescan's current roadmap or security guarantees.

## Trusted and Untrusted Inputs

### Signed Bundles

Signed policy, rule, and advisory bundles are verified as signed envelopes. Kubescan authenticates the signed metadata and payload together before accepting them.

### Released Binaries and Container Images

Published release checksums and published container images are intended to be verified through Sigstore keyless signing and GitHub-issued provenance. Release consumers should verify signatures and provenance rather than trusting artifact names or tags alone.

### Local Filesystem and Repository Inputs

Filesystem and repository scans treat scanned content as untrusted. Kubescan skips symlink traversal to avoid escaping the intended scan root, but the local filesystem and the Git binary remain part of the local trust boundary.

### Remote Git Repositories

Remote Git scans clone untrusted repositories into a temporary directory. Kubescan restricts supported URL schemes, disables unsafe Git protocol helpers, and supports explicit authenticated access through repeated HTTP headers or a custom `GIT_SSH_COMMAND`, but the host running `git` remains trusted and Git itself is part of the execution boundary.

### Image Scanning

Direct image scans treat registry content and image metadata as untrusted. Kubescan reads image manifests, config, and optionally unpacked layer contents for analysis. It supports the local container-registry keychain plus explicit username/password or bearer-token auth for private registries, but registry trust policy remains outside Kubescan's enforcement scope.

### Kubernetes Cluster and Operator Inputs

Live-cluster scans and operator mode treat Kubernetes API resources as scan inventory. Kubescan does not assume those resources are trustworthy simply because they are present in the cluster. Operator-managed bundle, SBOM, `ConfigMap`, `Secret`, `SBOMReport`, and `NodeReport` inputs should be protected with normal cluster RBAC and namespace controls. Remote operator SBOM sources currently support HTTPS URLs and OCI image references only; external SBOM endpoints should be treated as untrusted until validated by your own transport, auth, and provenance controls.

## Secret Handling

Kubescan is designed to avoid echoing raw secret material in findings. It reports:

- resource and file context
- rule and message metadata
- redacted evidence descriptions

It does not read raw Kubernetes Secret data values from the API as part of posture scanning.

## Operator Security Boundaries

The reporting operator is intended to be read-only with respect to scanned resources and write-only for its own reporting CRDs.

Current operator hardening includes:

- bounded stored findings and attack paths per `ScanReport`
- per-cycle scan timeouts
- optional namespace-scoped reduced-privilege mode
- watch debouncing to reduce event storms
- signed bundle verification before use
- hardened shipped deployment manifests with non-root execution, dropped capabilities, read-only root filesystems, and default resource limits

The optional node collector is a separate trust boundary:

- it mounts host kubelet state read-only
- it runs as UID `0` for host file readability
- it does not require full Linux capabilities or `privileged: true` in the shipped manifest
- it writes only `NodeReport` CRDs

## Out of Scope

The following are currently outside Kubescan's security guarantees:

- runtime exploit prevention
- sandboxing of local rendering tools such as `helm`, `kustomize`, or `kubectl kustomize`
- sandboxing of the local `git` client
- full control-plane and node host inspection without an additional collector
- broad host telemetry beyond the shipped kubelet-config-focused node collector
- automatic trust establishment for third-party advisories, registries, or SBOM sources
- a built-in continuously updated vulnerability database

## Operational Recommendations

For safer production use:

- run Kubescan in dedicated CI or scanning environments
- restrict operator RBAC to the smallest feasible scope
- prefer signed bundles over unsigned policy inputs
- protect bundle keys, operator namespaces, and SBOM carrier objects with RBAC
- verify released checksums and published container image signatures before promotion into trusted environments
- pin and review the local `helm`, `kustomize`, `kubectl`, and `git` binaries used by your environment
- use private registry auth, repo auth, and network controls appropriate for your environment
- monitor dependency updates through the shipped Dependabot configuration and keep CI-time `govulncheck` results clean

## Reporting Security Issues

If you discover a security issue in Kubescan itself, report it privately to the maintainer rather than opening a public exploit issue first.
