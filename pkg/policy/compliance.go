package policy

import (
	"fmt"
	"strings"
)

type ComplianceProfile struct {
	Name     string
	Title    string
	Controls []ComplianceControl
}

type ComplianceControl struct {
	ID      string
	Title   string
	RuleIDs []string
}

type ComplianceStatus string

const (
	ComplianceStatusPass ComplianceStatus = "pass"
	ComplianceStatusFail ComplianceStatus = "fail"
)

type ComplianceControlResult struct {
	ID              string           `json:"id"`
	Title           string           `json:"title"`
	Status          ComplianceStatus `json:"status"`
	RuleIDs         []string         `json:"ruleIds"`
	FailingFindings int              `json:"failingFindings"`
}

type ComplianceReport struct {
	Profile        string                    `json:"profile"`
	Title          string                    `json:"title"`
	PassedControls int                       `json:"passedControls"`
	FailedControls int                       `json:"failedControls"`
	Controls       []ComplianceControlResult `json:"controls"`
}

var complianceProfiles = map[string]ComplianceProfile{
	"k8s-cis": {
		Name:  "k8s-cis",
		Title: "Kubernetes CIS Aligned Checks",
		Controls: []ComplianceControl{
			{ID: "CIS-5.2.1", Title: "Minimize privileged containers", RuleIDs: []string{"KS001", "KS033", "KS034"}},
			{ID: "CIS-5.2.2", Title: "Minimize host namespace sharing", RuleIDs: []string{"KS002"}},
			{ID: "CIS-5.2.3", Title: "Require non-root execution", RuleIDs: []string{"KS003", "KS004"}},
			{ID: "CIS-5.2.4", Title: "Minimize hostPort use", RuleIDs: []string{"KS025"}},
			{ID: "CIS-5.2.5", Title: "Use read-only root filesystems", RuleIDs: []string{"KS005"}},
			{ID: "CIS-5.2.6", Title: "Disallow privilege escalation", RuleIDs: []string{"KS022"}},
			{ID: "CIS-5.2.8", Title: "Limit secret exposure", RuleIDs: []string{"KS018", "KS019", "KS029"}},
			{ID: "CIS-5.2.9", Title: "Use seccomp profiles", RuleIDs: []string{"KS023"}},
			{ID: "CIS-5.2.12", Title: "Avoid hostPath volumes", RuleIDs: []string{"KS024", "KS035"}},
			{ID: "CIS-5.7.3", Title: "Apply namespace network policy", RuleIDs: []string{"KS014", "KS030", "KS031"}},
		},
	},
	"nsa": {
		Name:  "nsa",
		Title: "NSA Kubernetes Hardening Aligned Checks",
		Controls: []ComplianceControl{
			{ID: "NSA-01", Title: "Avoid privileged containers and host namespaces", RuleIDs: []string{"KS001", "KS002", "KS033", "KS034"}},
			{ID: "NSA-02", Title: "Run as non-root with read-only filesystems", RuleIDs: []string{"KS003", "KS004", "KS005"}},
			{ID: "NSA-02B", Title: "Disallow privilege escalation and require seccomp", RuleIDs: []string{"KS022", "KS023"}},
			{ID: "NSA-03", Title: "Restrict service account and RBAC reachability", RuleIDs: []string{"KS012", "KS013", "KS016", "KS017", "KS020", "KS021", "KS026", "KS027"}},
			{ID: "NSA-04", Title: "Constrain network exposure", RuleIDs: []string{"KS011", "KS014", "KS024", "KS025", "KS030", "KS031", "KS035"}},
			{ID: "NSA-05", Title: "Keep credential material out of plain text", RuleIDs: []string{"KS018", "KS019", "KS029"}},
			{ID: "NSA-06", Title: "Use approved image registries", RuleIDs: []string{"KS032"}},
			{ID: "NSA-07", Title: "Avoid control-plane targeting from workloads", RuleIDs: []string{"KS036"}},
		},
	},
	"pss-restricted": {
		Name:  "pss-restricted",
		Title: "Pod Security Standards Restricted Aligned Checks",
		Controls: []ComplianceControl{
			{ID: "PSS-01", Title: "No privileged containers or dangerous capabilities", RuleIDs: []string{"KS001", "KS015", "KS033", "KS034"}},
			{ID: "PSS-02", Title: "No host namespace sharing", RuleIDs: []string{"KS002"}},
			{ID: "PSS-03", Title: "Run as non-root", RuleIDs: []string{"KS003", "KS004"}},
			{ID: "PSS-04", Title: "Disallow privilege escalation and require seccomp", RuleIDs: []string{"KS022", "KS023"}},
			{ID: "PSS-05", Title: "Avoid hostPath and hostPort exposure", RuleIDs: []string{"KS024", "KS025", "KS035"}},
		},
	},
}

func ParseComplianceProfile(name string) (ComplianceProfile, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	profile, ok := complianceProfiles[key]
	if !ok {
		return ComplianceProfile{}, fmt.Errorf("unsupported compliance profile %q", name)
	}
	return profile, nil
}

func EvaluateCompliance(profile ComplianceProfile, findings []Finding) ComplianceReport {
	findingsByRule := map[string]int{}
	for _, finding := range findings {
		findingsByRule[finding.RuleID]++
	}

	report := ComplianceReport{
		Profile: profile.Name,
		Title:   profile.Title,
	}
	for _, control := range profile.Controls {
		result := ComplianceControlResult{
			ID:      control.ID,
			Title:   control.Title,
			RuleIDs: append([]string(nil), control.RuleIDs...),
			Status:  ComplianceStatusPass,
		}
		for _, ruleID := range control.RuleIDs {
			result.FailingFindings += findingsByRule[ruleID]
		}
		if result.FailingFindings > 0 {
			result.Status = ComplianceStatusFail
			report.FailedControls++
		} else {
			report.PassedControls++
		}
		report.Controls = append(report.Controls, result)
	}

	return report
}
