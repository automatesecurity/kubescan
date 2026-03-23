package policy

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type RuleBundle struct {
	APIVersion  string           `json:"apiVersion,omitempty" yaml:"apiVersion"`
	Kind        string           `json:"kind,omitempty" yaml:"kind"`
	Rules       []RuleConfig     `json:"rules" yaml:"rules"`
	CustomRules []CustomRuleSpec `json:"customRules,omitempty" yaml:"customRules"`
}

const (
	RuleBundleAPIVersion = "kubescan.automatesecurity.github.io/v1alpha1"
	RuleBundleKind       = "RuleBundle"
)

type RuleConfig struct {
	ID       string    `json:"id" yaml:"id"`
	Enabled  *bool     `json:"enabled,omitempty" yaml:"enabled"`
	Severity *Severity `json:"severity,omitempty" yaml:"severity"`
}

type CustomRuleSpec struct {
	ID          string      `json:"id" yaml:"id"`
	Target      string      `json:"target" yaml:"target"`
	Category    Category    `json:"category" yaml:"category"`
	Title       string      `json:"title" yaml:"title"`
	Severity    Severity    `json:"severity" yaml:"severity"`
	Message     string      `json:"message" yaml:"message"`
	Remediation string      `json:"remediation" yaml:"remediation"`
	Match       MatchClause `json:"match" yaml:"match"`
}

type MatchClause struct {
	All []Predicate `json:"all,omitempty" yaml:"all"`
	Any []Predicate `json:"any,omitempty" yaml:"any"`
	Not []Predicate `json:"not,omitempty" yaml:"not"`
}

type Predicate struct {
	Field string      `json:"field" yaml:"field"`
	Op    string      `json:"op" yaml:"op"`
	Value any         `json:"value,omitempty" yaml:"value"`
	All   []Predicate `json:"all,omitempty" yaml:"all"`
	Any   []Predicate `json:"any,omitempty" yaml:"any"`
	Not   []Predicate `json:"not,omitempty" yaml:"not"`
}

func LoadRuleBundle(path string) (RuleBundle, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return RuleBundle{}, fmt.Errorf("read rule bundle: %w", err)
	}
	return LoadRuleBundleBytes(content)
}

func LoadRuleBundleBytes(content []byte) (RuleBundle, error) {
	var bundle RuleBundle
	if err := yaml.Unmarshal(content, &bundle); err != nil {
		return RuleBundle{}, fmt.Errorf("decode rule bundle: %w", err)
	}
	bundle = normalizeRuleBundle(bundle)
	if err := ValidateRuleBundle(bundle); err != nil {
		return RuleBundle{}, err
	}
	return bundle, nil
}

func ValidateRuleBundle(bundle RuleBundle) error {
	bundle = normalizeRuleBundle(bundle)
	if bundle.APIVersion != RuleBundleAPIVersion {
		return fmt.Errorf("unsupported rule bundle apiVersion %q", bundle.APIVersion)
	}
	if bundle.Kind != RuleBundleKind {
		return fmt.Errorf("rule bundle kind must be %s", RuleBundleKind)
	}
	knownRules := map[string]struct{}{}
	for _, rule := range allRules() {
		knownRules[rule.ID] = struct{}{}
	}
	for _, rule := range bundle.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule bundle entry id is required")
		}
		if _, ok := knownRules[rule.ID]; !ok {
			return fmt.Errorf("unknown rule id %q", rule.ID)
		}
		if rule.Severity != nil && !isValidSeverity(*rule.Severity) {
			return fmt.Errorf("invalid severity override %q for rule %s", *rule.Severity, rule.ID)
		}
	}
	for _, rule := range bundle.CustomRules {
		if rule.ID == "" {
			return fmt.Errorf("custom rule id is required")
		}
		if rule.Target != "container" && rule.Target != "workload" && rule.Target != "service" && rule.Target != "namespace" && rule.Target != "serviceAccount" {
			return fmt.Errorf("custom rule %s has unsupported target %q", rule.ID, rule.Target)
		}
		if !isValidSeverity(rule.Severity) {
			return fmt.Errorf("custom rule %s has invalid severity %q", rule.ID, rule.Severity)
		}
		if rule.Title == "" || rule.Message == "" || rule.Remediation == "" {
			return fmt.Errorf("custom rule %s requires title, message, and remediation", rule.ID)
		}
		if len(rule.Match.All) == 0 && len(rule.Match.Any) == 0 && len(rule.Match.Not) == 0 {
			return fmt.Errorf("custom rule %s requires at least one match predicate", rule.ID)
		}
		if err := validatePredicates(rule.ID, rule.Match.All); err != nil {
			return err
		}
		if err := validatePredicates(rule.ID, rule.Match.Any); err != nil {
			return err
		}
		if err := validatePredicates(rule.ID, rule.Match.Not); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRuleBundle(bundle RuleBundle) RuleBundle {
	if bundle.APIVersion == "" {
		bundle.APIVersion = RuleBundleAPIVersion
	} else if bundle.APIVersion == "kubescan.io/v1alpha1" {
		bundle.APIVersion = RuleBundleAPIVersion
	}
	if bundle.Kind == "" {
		bundle.Kind = RuleBundleKind
	}
	return bundle
}

func validatePredicates(ruleID string, predicates []Predicate) error {
	for _, predicate := range predicates {
		if err := validatePredicate(ruleID, predicate); err != nil {
			return err
		}
	}
	return nil
}

func validatePredicate(ruleID string, predicate Predicate) error {
	hasLeaf := predicate.Field != "" || predicate.Op != "" || predicate.Value != nil
	hasNested := len(predicate.All) > 0 || len(predicate.Any) > 0 || len(predicate.Not) > 0

	if hasLeaf && hasNested {
		return fmt.Errorf("custom rule %s cannot mix predicate fields with nested boolean clauses", ruleID)
	}
	if !hasLeaf && !hasNested {
		return fmt.Errorf("custom rule %s has empty predicate", ruleID)
	}
	if hasNested {
		if err := validatePredicates(ruleID, predicate.All); err != nil {
			return err
		}
		if err := validatePredicates(ruleID, predicate.Any); err != nil {
			return err
		}
		if err := validatePredicates(ruleID, predicate.Not); err != nil {
			return err
		}
		return nil
	}
	if predicate.Field == "" {
		return fmt.Errorf("custom rule %s has predicate with empty field", ruleID)
	}
	if predicate.Op == "" {
		return fmt.Errorf("custom rule %s has predicate %q with empty operator", ruleID, predicate.Field)
	}
	if !isSupportedOperator(predicate.Op) {
		return fmt.Errorf("custom rule %s has unsupported operator %q", ruleID, predicate.Op)
	}
	return nil
}

func isSupportedOperator(op string) bool {
	switch op {
	case "equals", "not_equals", "contains", "not_contains", "exists", "one_of", "greater_than", "greater_or_equal", "less_than", "less_or_equal":
		return true
	default:
		return false
	}
}
