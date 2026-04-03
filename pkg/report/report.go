package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"kubescan/pkg/attackpath"
	"kubescan/pkg/policy"
)

type TableOptions struct {
	Color bool
}

const (
	ScanResultAPIVersion = "report.automatesecurity.github.io/v1"
	ScanResultKind       = "ScanResult"
	ScanResultSchema     = "kubescan-scan-result"
	ScanResultVersion    = "1.0.0"
)

type Summary struct {
	TotalBySeverity map[policy.Severity]int `json:"totalBySeverity"`
	TotalFindings   int                     `json:"totalFindings"`
	ByRule          []SummaryEntry          `json:"byRule"`
	ByNamespace     []SummaryEntry          `json:"byNamespace"`
	ByCategory      []SummaryEntry          `json:"byCategory"`
	AttackPaths     AttackPathSummary       `json:"attackPaths"`
}

type SummaryEntry struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type AttackPathSummary struct {
	TotalBySeverity map[policy.Severity]int `json:"totalBySeverity"`
	TotalPaths      int                     `json:"totalPaths"`
	ByID            []SummaryEntry          `json:"byId"`
}

type ScanResult struct {
	APIVersion    string                   `json:"apiVersion"`
	Kind          string                   `json:"kind"`
	Schema        string                   `json:"schema"`
	SchemaVersion string                   `json:"schemaVersion"`
	GeneratedAt   time.Time                `json:"generatedAt"`
	Summary       Summary                  `json:"summary"`
	Compliance    *policy.ComplianceReport `json:"compliance,omitempty"`
	Findings      []policy.Finding         `json:"findings"`
	AttackPaths   []attackpath.Result      `json:"attackPaths,omitempty"`
}

func BuildScanResult(findings []policy.Finding) ScanResult {
	return BuildScanResultWithAttackPathsAndCompliance(findings, nil, nil, time.Now().UTC())
}

func BuildScanResultWithCompliance(findings []policy.Finding, compliance *policy.ComplianceReport) ScanResult {
	return BuildScanResultWithAttackPathsAndCompliance(findings, nil, compliance, time.Now().UTC())
}

func BuildScanResultWithAttackPaths(findings []policy.Finding, attackPaths []attackpath.Result) ScanResult {
	return BuildScanResultWithAttackPathsAndCompliance(findings, attackPaths, nil, time.Now().UTC())
}

func BuildScanResultWithAttackPathsAndCompliance(findings []policy.Finding, attackPaths []attackpath.Result, compliance *policy.ComplianceReport, now time.Time) ScanResult {
	summary := Summary{
		TotalBySeverity: map[policy.Severity]int{},
		AttackPaths: AttackPathSummary{
			TotalBySeverity: map[policy.Severity]int{},
		},
	}
	byRule := map[string]int{}
	byNamespace := map[string]int{}
	byCategory := map[string]int{}
	for _, finding := range findings {
		summary.TotalBySeverity[finding.Severity]++
		byRule[finding.RuleID]++
		namespace := finding.Resource.Namespace
		if namespace == "" {
			namespace = "cluster"
		}
		byNamespace[namespace]++
		category := string(finding.Category)
		if category == "" {
			category = "unknown"
		}
		byCategory[category]++
	}
	summary.TotalFindings = len(findings)
	summary.ByRule = summaryEntries(byRule)
	summary.ByNamespace = summaryEntries(byNamespace)
	summary.ByCategory = summaryEntries(byCategory)
	byAttackPathID := map[string]int{}
	for _, path := range attackPaths {
		summary.AttackPaths.TotalBySeverity[path.Severity]++
		summary.AttackPaths.TotalPaths++
		byAttackPathID[path.ID]++
	}
	summary.AttackPaths.ByID = summaryEntries(byAttackPathID)

	return ScanResult{
		GeneratedAt: now,
		Summary:     summary,
		Compliance:  compliance,
		Findings:    findings,
		AttackPaths: attackPaths,
	}.normalized()
}

func WriteJSON(w io.Writer, result ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result.normalized())
}

func WriteTable(w io.Writer, result ScanResult) error {
	return WriteTableWithOptions(w, result, TableOptions{})
}

func WriteTableWithOptions(w io.Writer, result ScanResult, options TableOptions) error {
	if err := writeCLIHeader(w, "Kubescan Scan Report", options); err != nil {
		return err
	}
	if err := writeOverviewSection(w, result, options); err != nil {
		return err
	}
	if err := writeComplianceSection(w, result.Compliance, options); err != nil {
		return err
	}
	if err := writeAttackPathsSection(w, result.AttackPaths, options); err != nil {
		return err
	}
	if err := writeSummaryBreakdownSection(w, "Top Rules", "RULE", result.Summary.ByRule, 5, options); err != nil {
		return err
	}
	if err := writeSummaryBreakdownSection(w, "Top Namespaces", "NAMESPACE", result.Summary.ByNamespace, 5, options); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\n"+colorize(options.Color, colorCyanBold, "Findings")+"\n"); err != nil {
		return err
	}

	findings := append([]policy.Finding(nil), result.Findings...)
	sortFindings(findings)
	if len(findings) == 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if _, err := io.WriteString(tw, "SEV\tCATEGORY\tRULE\tMESSAGE\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(tw, "none\t-\t-\t-\tNo findings\n"); err != nil {
			return err
		}
		return tw.Flush()
	}

	grouped := groupFindingsByResource(findings)
	for i, group := range grouped {
		if i > 0 {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, colorize(options.Color, colorBlueBold, group.Resource)+"\n"); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if _, err := io.WriteString(tw, "SEV\tCATEGORY\tRULE\tMESSAGE\n"); err != nil {
			return err
		}
		for _, finding := range group.Findings {
			if _, err := io.WriteString(tw, severityLabelStyled(finding.Severity, options.Color)+"\t"+categoryLabel(finding.Category)+"\t"+finding.RuleID+"\t"+finding.Message+"\n"); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func WriteSummaryTable(w io.Writer, result ScanResult) error {
	return WriteSummaryTableWithOptions(w, result, TableOptions{})
}

func WriteSummaryTableWithOptions(w io.Writer, result ScanResult, options TableOptions) error {
	if err := writeCLIHeader(w, "Kubescan Scan Summary", options); err != nil {
		return err
	}
	if err := writeOverviewSection(w, result, options); err != nil {
		return err
	}
	if err := writeComplianceSection(w, result.Compliance, options); err != nil {
		return err
	}
	if err := writeAttackPathSummarySection(w, result.Summary.AttackPaths, options); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, "\nSEVERITY\tCOUNT\n"); err != nil {
		return err
	}
	for _, severity := range []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow} {
		if _, err := io.WriteString(tw, string(severity)+"\t"+strconv.Itoa(result.Summary.TotalBySeverity[severity])+"\n"); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if err := writeSummaryBreakdownSection(w, "Rules", "RULE", result.Summary.ByRule, 10, options); err != nil {
		return err
	}
	if err := writeSummaryBreakdownSection(w, "Namespaces", "NAMESPACE", result.Summary.ByNamespace, 10, options); err != nil {
		return err
	}
	return writeSummaryBreakdownSection(w, "Categories", "CATEGORY", result.Summary.ByCategory, 10, options)
}

func (result ScanResult) normalized() ScanResult {
	if strings.TrimSpace(result.APIVersion) == "" {
		result.APIVersion = ScanResultAPIVersion
	}
	if strings.TrimSpace(result.Kind) == "" {
		result.Kind = ScanResultKind
	}
	if strings.TrimSpace(result.Schema) == "" {
		result.Schema = ScanResultSchema
	}
	if strings.TrimSpace(result.SchemaVersion) == "" {
		result.SchemaVersion = ScanResultVersion
	}
	return result
}

func summaryEntries(values map[string]int) []SummaryEntry {
	entries := make([]SummaryEntry, 0, len(values))
	for name, count := range values {
		entries = append(entries, SummaryEntry{Name: name, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Count > entries[j].Count
	})
	return entries
}

func writeOverviewSection(w io.Writer, result ScanResult, options TableOptions) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, "\n"+colorize(options.Color, colorCyanBold, "OVERVIEW")+"\tVALUE\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "generated\t"+result.GeneratedAt.Format(time.RFC3339)+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "findings\t"+strconv.Itoa(result.Summary.TotalFindings)+"\n"); err != nil {
		return err
	}
	if result.Summary.AttackPaths.TotalPaths > 0 {
		if _, err := io.WriteString(tw, "attack paths\t"+strconv.Itoa(result.Summary.AttackPaths.TotalPaths)+"\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(tw, "attack path mix\t"+severityMix(result.Summary.AttackPaths.TotalBySeverity)+"\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(tw, "severity mix\t"+severityMix(result.Summary.TotalBySeverity)+"\n"); err != nil {
		return err
	}
	for _, severity := range []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow} {
		if _, err := io.WriteString(tw, string(severity)+"\t"+strconv.Itoa(result.Summary.TotalBySeverity[severity])+"\n"); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeCLIHeader(w io.Writer, title string, options TableOptions) error {
	const asciiHeader = ` _  ___   _ ____  _____ ____   ____    _    _   _
| |/ / | | | __ )| ____/ ___| / ___|  / \  | \ | |
| ' /| | | |  _ \|  _| \___ \| |     / _ \ |  \| |
| . \| |_| | |_) | |___ ___) | |___ / ___ \| |\  |
|_|\_\\___/|____/|_____|____/ \____/_/   \_\_| \_|`

	if _, err := io.WriteString(w, colorize(options.Color, colorCyanBold, asciiHeader)+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(w, colorize(options.Color, colorBlueBold, "Kubescan (c) 2026 Daniel Wood https://www.github.com/automatesecurity/kubescan")+"\n"); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n"+colorize(options.Color, colorCyanBold, title)+"\n")
	return err
}

func writeAttackPathsSection(w io.Writer, attackPaths []attackpath.Result, options TableOptions) error {
	if len(attackPaths) == 0 {
		return nil
	}
	if _, err := io.WriteString(w, "\n"+colorize(options.Color, colorCyanBold, "Attack Paths")+"\n"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, "SEV\tID\tENTRY\tTARGET\tSUPPORTING RULES\tPATH\n"); err != nil {
		return err
	}
	for _, path := range attackPaths {
		if _, err := io.WriteString(tw,
			severityLabelStyled(path.Severity, options.Color)+"\t"+
				path.ID+"\t"+
				fullyQualifiedResource(path.Entry)+"\t"+
				path.Target+"\t"+
				strings.Join(path.SupportingRules, ",")+"\t"+
				path.Path+"\n"); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeAttackPathSummarySection(w io.Writer, summary AttackPathSummary, options TableOptions) error {
	if summary.TotalPaths == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, "\n"+colorize(options.Color, colorCyanBold, "ATTACK PATHS")+"\tVALUE\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "count\t"+strconv.Itoa(summary.TotalPaths)+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "severity mix\t"+severityMix(summary.TotalBySeverity)+"\n"); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeSummaryBreakdownSection(w, "Attack Path IDs", "PATH", summary.ByID, 10, options)
}

func writeComplianceSection(w io.Writer, compliance *policy.ComplianceReport, options TableOptions) error {
	if compliance == nil {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, "\n"+colorize(options.Color, colorCyanBold, "COMPLIANCE")+"\tVALUE\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "profile\t"+compliance.Profile+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "passed\t"+strconv.Itoa(compliance.PassedControls)+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "failed\t"+strconv.Itoa(compliance.FailedControls)+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, "status\t"+colorize(options.Color, complianceStatusColor(compliance), complianceStatus(compliance))+"\n"); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(compliance.Controls) == 0 {
		return nil
	}
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, "CONTROL\tSTATUS\tFAILING FINDINGS\n"); err != nil {
		return err
	}
	for _, control := range compliance.Controls {
		if _, err := io.WriteString(tw, control.ID+"\t"+colorize(options.Color, complianceControlColor(control.Status), string(control.Status))+"\t"+strconv.Itoa(control.FailingFindings)+"\n"); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeSummaryBreakdownSection(w io.Writer, title, header string, entries []SummaryEntry, limit int, options TableOptions) error {
	if len(entries) == 0 {
		return nil
	}
	if limit > len(entries) {
		limit = len(entries)
	}
	if _, err := io.WriteString(w, "\n"+colorize(options.Color, colorCyanBold, title)+"\n"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, header+"\tCOUNT\n"); err != nil {
		return err
	}
	for _, entry := range entries[:limit] {
		if _, err := io.WriteString(tw, entry.Name+"\t"+strconv.Itoa(entry.Count)+"\n"); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func sortFindings(findings []policy.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		leftRank := policy.SeverityWeight(findings[i].Severity)
		rightRank := policy.SeverityWeight(findings[j].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		leftResource := fullyQualifiedResource(findings[i].Resource)
		rightResource := fullyQualifiedResource(findings[j].Resource)
		if leftResource != rightResource {
			return leftResource < rightResource
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Message < findings[j].Message
	})
}

func severityWeight(severity policy.Severity) int {
	return policy.SeverityWeight(severity)
}

func fullyQualifiedResource(resource policy.ResourceRef) string {
	if resource.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", resource.Namespace, resource.Kind, resource.Name)
	}
	return fmt.Sprintf("%s/%s", resource.Kind, resource.Name)
}

type findingGroup struct {
	Resource string
	Findings []policy.Finding
}

func groupFindingsByResource(findings []policy.Finding) []findingGroup {
	order := []string{}
	byResource := map[string][]policy.Finding{}
	for _, finding := range findings {
		resource := fullyQualifiedResource(finding.Resource)
		if _, ok := byResource[resource]; !ok {
			order = append(order, resource)
		}
		byResource[resource] = append(byResource[resource], finding)
	}

	groups := make([]findingGroup, 0, len(order))
	for _, resource := range order {
		groups = append(groups, findingGroup{
			Resource: resource,
			Findings: byResource[resource],
		})
	}
	return groups
}

func severityLabel(severity policy.Severity) string {
	switch severity {
	case policy.SeverityCritical:
		return "CRIT"
	case policy.SeverityHigh:
		return "HIGH"
	case policy.SeverityMedium:
		return "MED"
	default:
		return "LOW"
	}
}

func severityLabelStyled(severity policy.Severity, enabled bool) string {
	return colorize(enabled, severityColor(severity), severityLabel(severity))
}

func categoryLabel(category policy.Category) string {
	if category == "" {
		return "unknown"
	}
	return string(category)
}

func severityMix(counts map[policy.Severity]int) string {
	return fmt.Sprintf("crit:%d high:%d med:%d low:%d",
		counts[policy.SeverityCritical],
		counts[policy.SeverityHigh],
		counts[policy.SeverityMedium],
		counts[policy.SeverityLow],
	)
}

func complianceStatus(compliance *policy.ComplianceReport) string {
	if compliance == nil {
		return ""
	}
	if compliance.FailedControls > 0 {
		return "failing"
	}
	return "passing"
}

const (
	colorReset    = "\x1b[0m"
	colorCyanBold = "\x1b[1;36m"
	colorBlueBold = "\x1b[1;34m"
	colorRedBold  = "\x1b[1;31m"
	colorRed      = "\x1b[31m"
	colorYellow   = "\x1b[33m"
	colorGreen    = "\x1b[32m"
)

func colorize(enabled bool, code, value string) string {
	if !enabled || value == "" || code == "" {
		return value
	}
	return code + value + colorReset
}

func severityColor(severity policy.Severity) string {
	switch severity {
	case policy.SeverityCritical:
		return colorRedBold
	case policy.SeverityHigh:
		return colorRed
	case policy.SeverityMedium:
		return colorYellow
	default:
		return colorGreen
	}
}

func complianceStatusColor(compliance *policy.ComplianceReport) string {
	if compliance == nil {
		return ""
	}
	if compliance.FailedControls > 0 {
		return colorYellow
	}
	return colorGreen
}

func complianceControlColor(status policy.ComplianceStatus) string {
	if status == policy.ComplianceStatusFail {
		return colorYellow
	}
	return colorGreen
}
