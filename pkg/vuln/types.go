package vuln

import "kubescan/pkg/policy"

type SBOM struct {
	ImageRef string
	Packages []Package
}

type SBOMIndex map[string]SBOM

type Package struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
}

type AdvisoryBundle struct {
	APIVersion string     `json:"apiVersion,omitempty" yaml:"apiVersion"`
	Kind       string     `json:"kind,omitempty" yaml:"kind"`
	Advisories []Advisory `json:"advisories" yaml:"advisories"`
}

const (
	AdvisoryBundleAPIVersion = "kubescan.automatesecurity.github.io/v1alpha1"
	AdvisoryBundleKind       = "AdvisoryBundle"
)

type Advisory struct {
	ID               string          `json:"id" yaml:"id"`
	Aliases          []string        `json:"aliases,omitempty" yaml:"aliases"`
	PackageName      string          `json:"packageName" yaml:"packageName"`
	Ecosystem        string          `json:"ecosystem" yaml:"ecosystem"`
	AffectedVersions []string        `json:"affectedVersions" yaml:"affectedVersions"`
	FixedVersion     string          `json:"fixedVersion,omitempty" yaml:"fixedVersion"`
	Severity         policy.Severity `json:"severity" yaml:"severity"`
	Summary          string          `json:"summary" yaml:"summary"`
}
