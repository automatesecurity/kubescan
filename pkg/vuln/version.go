package vuln

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type versionConstraint struct {
	operator string
	version  string
}

func matchesAffectedVersion(ecosystem, packageVersion string, affectedVersions []string) (bool, error) {
	for _, expression := range affectedVersions {
		match, err := matchesConstraintExpression(ecosystem, packageVersion, expression)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

func matchesConstraintExpression(ecosystem, packageVersion, expression string) (bool, error) {
	clauses := strings.Split(expression, ",")
	for _, clause := range clauses {
		constraint, err := parseConstraint(clause)
		if err != nil {
			return false, err
		}
		if !evaluateConstraint(ecosystem, packageVersion, constraint) {
			return false, nil
		}
	}
	return true, nil
}

func parseConstraint(value string) (versionConstraint, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return versionConstraint{}, fmt.Errorf("empty version constraint")
	}

	for _, operator := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(trimmed, operator) {
			version := strings.TrimSpace(strings.TrimPrefix(trimmed, operator))
			if version == "" {
				return versionConstraint{}, fmt.Errorf("missing version in constraint %q", value)
			}
			return versionConstraint{operator: operator, version: version}, nil
		}
	}

	return versionConstraint{operator: "=", version: trimmed}, nil
}

func evaluateConstraint(ecosystem, packageVersion string, constraint versionConstraint) bool {
	comparison := comparePackageVersions(ecosystem, packageVersion, constraint.version)
	switch constraint.operator {
	case "=", "==":
		return comparison == 0
	case ">":
		return comparison > 0
	case ">=":
		return comparison >= 0
	case "<":
		return comparison < 0
	case "<=":
		return comparison <= 0
	default:
		return false
	}
}

func comparePackageVersions(ecosystem, left, right string) int {
	switch ecosystem {
	case "deb":
		return compareDebianVersions(left, right)
	case "rpm", "apk":
		return compareSegmentedVersions(left, right, true)
	default:
		return compareSegmentedVersions(left, right, false)
	}
}

func compareDebianVersions(left, right string) int {
	leftEpoch, leftRest := splitDebianEpoch(left)
	rightEpoch, rightRest := splitDebianEpoch(right)
	if leftEpoch != rightEpoch {
		if leftEpoch < rightEpoch {
			return -1
		}
		return 1
	}

	leftUpstream, leftRevision := splitDebianRevision(leftRest)
	rightUpstream, rightRevision := splitDebianRevision(rightRest)

	if cmp := compareDebianPart(leftUpstream, rightUpstream); cmp != 0 {
		return cmp
	}
	return compareDebianPart(leftRevision, rightRevision)
}

func splitDebianEpoch(value string) (int, string) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return 0, value
	}
	epoch, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, value
	}
	return epoch, parts[1]
}

func splitDebianRevision(value string) (string, string) {
	index := strings.LastIndex(value, "-")
	if index == -1 {
		return value, "0"
	}
	return value[:index], value[index+1:]
}

func compareDebianPart(left, right string) int {
	for left != "" || right != "" {
		leftNonDigit, leftRest := debianLeading(left, false)
		rightNonDigit, rightRemaining := debianLeading(right, false)
		if cmp := compareDebianNonDigit(leftNonDigit, rightNonDigit); cmp != 0 {
			return cmp
		}
		left = leftRest
		right = rightRemaining

		leftDigits, leftRestDigits := debianLeading(left, true)
		rightDigits, rightRestDigits := debianLeading(right, true)
		if cmp := compareDebianDigits(leftDigits, rightDigits); cmp != 0 {
			return cmp
		}
		left = leftRestDigits
		right = rightRestDigits
	}
	return 0
}

func debianLeading(value string, digits bool) (string, string) {
	index := 0
	for index < len(value) {
		r := rune(value[index])
		if unicode.IsDigit(r) != digits {
			break
		}
		index++
	}
	return value[:index], value[index:]
}

func compareDebianNonDigit(left, right string) int {
	leftRunes := []rune(left)
	rightRunes := []rune(right)
	maxLen := len(leftRunes)
	if len(rightRunes) > maxLen {
		maxLen = len(rightRunes)
	}

	for i := 0; i < maxLen; i++ {
		l := rune(0)
		r := rune(0)
		if i < len(leftRunes) {
			l = leftRunes[i]
		}
		if i < len(rightRunes) {
			r = rightRunes[i]
		}
		if l == r {
			continue
		}
		if debianOrder(l) < debianOrder(r) {
			return -1
		}
		return 1
	}
	return 0
}

func debianOrder(r rune) int {
	switch {
	case r == 0:
		return 0
	case r == '~':
		return -1
	case unicode.IsLetter(r):
		return int(r)
	default:
		return int(r) + 256
	}
}

func compareDebianDigits(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareSegmentedVersions(left, right string, supportCaret bool) int {
	for left != "" || right != "" {
		switch {
		case strings.HasPrefix(left, "~") || strings.HasPrefix(right, "~"):
			if strings.HasPrefix(left, "~") && strings.HasPrefix(right, "~") {
				left = left[1:]
				right = right[1:]
				continue
			}
			if strings.HasPrefix(left, "~") {
				return -1
			}
			return 1
		case supportCaret && (strings.HasPrefix(left, "^") || strings.HasPrefix(right, "^")):
			if strings.HasPrefix(left, "^") && strings.HasPrefix(right, "^") {
				left = left[1:]
				right = right[1:]
				continue
			}
			if strings.HasPrefix(left, "^") {
				if right == "" {
					return 1
				}
				return -1
			}
			if left == "" {
				return -1
			}
			return 1
		}

		left = trimSeparators(left)
		right = trimSeparators(right)
		if left == "" && right == "" {
			return 0
		}
		if left == "" {
			return -1
		}
		if right == "" {
			return 1
		}

		leftSegment, leftRest, leftNumeric := nextSegment(left)
		rightSegment, rightRest, rightNumeric := nextSegment(right)

		switch {
		case leftNumeric && rightNumeric:
			if cmp := compareNumericStrings(leftSegment, rightSegment); cmp != 0 {
				return cmp
			}
		case leftNumeric:
			return 1
		case rightNumeric:
			return -1
		default:
			if leftSegment < rightSegment {
				return -1
			}
			if leftSegment > rightSegment {
				return 1
			}
		}

		left = leftRest
		right = rightRest
	}
	return 0
}

func trimSeparators(value string) string {
	return strings.TrimLeftFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '~' && r != '^'
	})
}

func nextSegment(value string) (segment, rest string, numeric bool) {
	if value == "" {
		return "", "", false
	}
	runes := []rune(value)
	numeric = unicode.IsDigit(runes[0])
	index := 0
	for index < len(runes) {
		if unicode.IsDigit(runes[index]) != numeric {
			break
		}
		if !unicode.IsLetter(runes[index]) && !unicode.IsDigit(runes[index]) {
			break
		}
		index++
	}
	return string(runes[:index]), string(runes[index:]), numeric
}

func compareNumericStrings(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
