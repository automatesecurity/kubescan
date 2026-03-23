package policy

func EvaluateWithBundle(inventory Inventory, bundle RuleBundle) []Finding {
	return EvaluateWithProfileAndBundle(inventory, RuleProfileDefault, bundle)
}

func EvaluateWithProfileAndBundle(inventory Inventory, profile RuleProfile, bundle RuleBundle) []Finding {
	configByID := map[string]RuleConfig{}
	for _, config := range bundle.Rules {
		configByID[config.ID] = config
	}

	var findings []Finding
	for _, rule := range allRules() {
		enabled := ruleEnabledInProfile(profile, rule.ID)
		config, hasConfig := configByID[rule.ID]
		if hasConfig && config.Enabled != nil {
			enabled = *config.Enabled
		}
		if !enabled {
			continue
		}

		ruleFindings := rule.Check(inventory)
		if hasConfig {
			for i := range ruleFindings {
				if config.Severity != nil && ruleFindings[i].Severity != *config.Severity {
					ruleFindings[i].OriginalSeverity = ruleFindings[i].Severity
					ruleFindings[i].Severity = *config.Severity
				}
			}
		}
		findings = append(findings, ruleFindings...)
	}
	findings = append(findings, evaluateCustomRules(inventory, bundle.CustomRules)...)
	return findings
}
