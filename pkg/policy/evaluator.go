package policy

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Rule struct {
	ID          string
	Category    Category
	Title       string
	Severity    Severity
	Remediation string
	Check       func(Inventory) []Finding
}

func Evaluate(inventory Inventory) []Finding {
	return EvaluateWithProfile(inventory, RuleProfileDefault)
}

func EvaluateWithProfile(inventory Inventory, profile RuleProfile) []Finding {
	var findings []Finding
	for _, rule := range allRules() {
		if !ruleEnabledInProfile(profile, rule.ID) {
			continue
		}
		findings = append(findings, rule.Check(inventory)...)
	}
	return findings
}

func makeFinding(rule Rule, resource ResourceRef, message string, evidence map[string]any) Finding {
	return makeFindingAt(rule, resource, message, evidence, time.Now().UTC())
}

func makeFindingAt(rule Rule, resource ResourceRef, message string, evidence map[string]any, now time.Time) Finding {
	sum := sha1.Sum([]byte(strings.Join([]string{
		string(rule.Category),
		rule.ID,
		resource.Kind,
		resource.Namespace,
		resource.Name,
		message,
	}, "|")))

	return Finding{
		ID:          hex.EncodeToString(sum[:12]),
		Category:    rule.Category,
		RuleID:      rule.ID,
		Title:       rule.Title,
		Severity:    rule.Severity,
		RuleVersion: "v1",
		Resource:    resource,
		Message:     message,
		Evidence:    evidence,
		Remediation: rule.Remediation,
		Timestamp:   now,
	}
}

func containerMessage(workload Workload, container Container, detail string) string {
	return fmt.Sprintf("%s/%s container %q %s", workload.Resource.Kind, workload.Resource.Name, container.Name, detail)
}
