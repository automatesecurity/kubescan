package policy

import (
	"fmt"
	"strings"
)

var severityRank = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func ParseSeverity(value string) (Severity, error) {
	severity := Severity(strings.ToLower(strings.TrimSpace(value)))
	if !isValidSeverity(severity) {
		return "", fmt.Errorf("invalid severity %q", value)
	}
	return severity, nil
}

func MeetsOrExceedsSeverity(severity, threshold Severity) bool {
	return severityRank[severity] >= severityRank[threshold]
}
