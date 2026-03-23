package policy

import (
	"fmt"
	"strings"
)

type RuleProfile string

const (
	RuleProfileDefault    RuleProfile = "default"
	RuleProfileHardening  RuleProfile = "hardening"
	RuleProfileEnterprise RuleProfile = "enterprise"
)

var profileRuleIDs = map[RuleProfile]map[string]struct{}{
	RuleProfileDefault: toRuleSet(
		"KS001", "KS002", "KS003", "KS004", "KS005", "KS010", "KS011", "KS013",
		"KS015", "KS016", "KS017", "KS020", "KS021", "KS022", "KS023", "KS024",
		"KS026", "KS030", "KS031", "KS033", "KS034", "KS035", "KS037", "KS040",
		"KS044", "KS045", "KS046", "KS047", "KS048", "KS049", "KS050", "KS053",
		"KS054",
	),
	RuleProfileHardening: toRuleSet(
		"KS001", "KS002", "KS003", "KS004", "KS005", "KS006", "KS007", "KS008",
		"KS009", "KS010", "KS011", "KS012", "KS013", "KS015", "KS016", "KS017",
		"KS018", "KS019", "KS020", "KS021", "KS022", "KS023", "KS024", "KS026",
		"KS025", "KS027", "KS028", "KS030", "KS031", "KS033", "KS034", "KS035",
		"KS036", "KS037", "KS038", "KS039", "KS040", "KS041", "KS042", "KS043",
		"KS044", "KS045", "KS046", "KS047", "KS048", "KS049", "KS050", "KS051",
		"KS052", "KS053", "KS054", "KS055",
	),
	RuleProfileEnterprise: toRuleSet(
		"KS001", "KS002", "KS003", "KS004", "KS005", "KS006", "KS007", "KS008",
		"KS009", "KS010", "KS011", "KS012", "KS013", "KS015", "KS016", "KS017",
		"KS018", "KS019", "KS020", "KS021", "KS022", "KS023", "KS024", "KS025",
		"KS026", "KS027", "KS028", "KS029", "KS030", "KS031", "KS032", "KS033",
		"KS034", "KS035", "KS036", "KS037", "KS038", "KS039", "KS040", "KS041",
		"KS042", "KS043", "KS044", "KS045", "KS046", "KS047", "KS048", "KS049",
		"KS050", "KS051", "KS052", "KS053", "KS054", "KS055",
	),
}

func ParseRuleProfile(name string) (RuleProfile, error) {
	profile := RuleProfile(strings.ToLower(strings.TrimSpace(name)))
	switch profile {
	case RuleProfileDefault, RuleProfileHardening, RuleProfileEnterprise:
		return profile, nil
	default:
		return "", fmt.Errorf("unsupported rule profile %q", name)
	}
}

func ruleEnabledInProfile(profile RuleProfile, ruleID string) bool {
	rules, ok := profileRuleIDs[profile]
	if !ok {
		return false
	}
	_, ok = rules[ruleID]
	return ok
}

func toRuleSet(ruleIDs ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		result[ruleID] = struct{}{}
	}
	return result
}
