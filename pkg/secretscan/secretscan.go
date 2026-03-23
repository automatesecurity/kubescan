package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
)

type Confidence string
type Mode string

const (
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"

	ModePatterns   Mode = "patterns"
	ModeBalanced   Mode = "balanced"
	ModeAggressive Mode = "aggressive"
)

type Match struct {
	Detector    string
	Description string
	Name        string
	Line        int
	Fingerprint string
	Confidence  Confidence
}

type patternDetector struct {
	id          string
	description string
	regex       *regexp.Regexp
}

var (
	privateKeyRegex    = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	assignmentKeyRegex = regexp.MustCompile(`^(?:["'` + "`" + `])?[A-Za-z0-9_.-]{1,80}(?:["'` + "`" + `])?$`)
	lineDetectors      = []patternDetector{
		{
			id:          "aws-access-key-id",
			description: "AWS access key pattern",
			regex:       regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		},
		{
			id:          "github-token",
			description: "GitHub token pattern",
			regex:       regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b`),
		},
		{
			id:          "slack-token",
			description: "Slack token pattern",
			regex:       regexp.MustCompile(`\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,}\b`),
		},
		{
			id:          "jwt",
			description: "JWT-like token",
			regex:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]{6,}\.[A-Za-z0-9._-]{6,}\b`),
		},
	}
)

func ScanText(content string) []Match {
	return scanText(content, true)
}

func ScanTextPatternsOnly(content string) []Match {
	return scanText(content, false)
}

func ScanTextWithMode(content string, mode Mode, allowGenericAssignments bool) []Match {
	switch normalizeMode(mode) {
	case ModePatterns:
		return ScanTextPatternsOnly(content)
	case ModeAggressive:
		return ScanText(content)
	default:
		if allowGenericAssignments {
			return ScanText(content)
		}
		return ScanTextPatternsOnly(content)
	}
}

func ParseMode(value string) (Mode, error) {
	switch normalizeMode(Mode(strings.TrimSpace(value))) {
	case ModePatterns, ModeBalanced, ModeAggressive:
		return normalizeMode(Mode(strings.TrimSpace(value))), nil
	default:
		return "", fmt.Errorf("unsupported secret scan mode %q", value)
	}
}

func normalizeMode(value Mode) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(string(value)))) {
	case "", ModeBalanced:
		return ModeBalanced
	case ModePatterns:
		return ModePatterns
	case ModeAggressive:
		return ModeAggressive
	default:
		return value
	}
}

func scanText(content string, includeNamedAssignments bool) []Match {
	var matches []Match
	if loc := privateKeyRegex.FindStringIndex(content); loc != nil {
		matches = append(matches, Match{
			Detector:    "private-key",
			Description: "private key material",
			Line:        1 + strings.Count(content[:loc[0]], "\n"),
			Fingerprint: fingerprint(content[loc[0]:loc[1]]),
			Confidence:  ConfidenceHigh,
		})
	}

	for i, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if includeNamedAssignments {
			if name, value, ok := extractAssignment(line); ok {
				match := DetectNamedValue(name, value)
				if match != nil {
					match.Line = i + 1
					matches = append(matches, *match)
					continue
				}
			}
		}

		for _, match := range DetectText(line) {
			match.Line = i + 1
			matches = append(matches, match)
		}
	}

	return dedupe(matches)
}

func DetectNamedValue(name, value string) *Match {
	name = normalizeKey(name)
	trimmed := normalizeValue(value)
	if name == "" || trimmed == "" || LooksTemplated(trimmed) || IsPlaceholder(trimmed) || IsSafeScalar(trimmed) {
		return nil
	}
	if privateKeyRegex.MatchString(trimmed) {
		return &Match{
			Detector:    "private-key",
			Description: "private key material",
			Name:        name,
			Fingerprint: fingerprint(trimmed),
			Confidence:  ConfidenceHigh,
		}
	}
	if matches := DetectText(trimmed); len(matches) > 0 {
		match := matches[0]
		match.Name = name
		return &match
	}
	if !IsCredentialLikeName(name) || !LooksSecretishValue(trimmed) {
		return nil
	}

	match := Match{
		Detector:    "plaintext-credential",
		Description: "plaintext credential-like value",
		Name:        name,
		Fingerprint: fingerprint(trimmed),
		Confidence:  ConfidenceMedium,
	}
	if len(trimmed) >= 20 && shannonEntropy(trimmed) >= 3.5 {
		match.Detector = "high-entropy-secret"
		match.Description = "high-entropy credential-like value"
		match.Confidence = ConfidenceHigh
	}
	return &match
}

func DetectText(value string) []Match {
	trimmed := normalizeValue(value)
	if trimmed == "" || LooksTemplated(trimmed) || IsPlaceholder(trimmed) {
		return nil
	}
	if privateKeyRegex.MatchString(trimmed) {
		return []Match{{
			Detector:    "private-key",
			Description: "private key material",
			Fingerprint: fingerprint(trimmed),
			Confidence:  ConfidenceHigh,
		}}
	}

	var matches []Match
	for _, detector := range lineDetectors {
		if !detector.regex.MatchString(trimmed) {
			continue
		}
		matches = append(matches, Match{
			Detector:    detector.id,
			Description: detector.description,
			Fingerprint: fingerprint(trimmed),
			Confidence:  ConfidenceHigh,
		})
	}
	return dedupe(matches)
}

func IsCredentialLikeName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), ".", "_"))
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	if len(parts) == 0 {
		return false
	}
	if isBenignCredentialName(parts, normalized) {
		return false
	}
	for i, part := range parts {
		switch part {
		case "password", "passwd", "pwd", "secret", "apikey":
			return true
		case "api", "access", "client", "refresh", "auth", "oauth", "bearer", "bot", "app", "personal":
			if i+1 < len(parts) {
				switch parts[i+1] {
				case "key", "token", "secret":
					return true
				}
			}
		case "key":
			if i > 0 {
				switch parts[i-1] {
				case "api", "access", "client", "secret":
					return true
				}
			}
		case "token":
			if i > 0 {
				switch parts[i-1] {
				case "api", "access", "refresh", "auth", "oauth", "bearer", "bot", "app", "personal", "github", "slack", "telegram", "discord", "hass", "openrouter", "anthropic", "groq", "elevenlabs":
					return true
				}
			}
			if i+1 < len(parts) && parts[i+1] == "secret" {
				return true
			}
		}
	}
	return false
}

func isBenignCredentialName(parts []string, normalized string) bool {
	switch normalized {
	case "id_token", "max_tokens", "min_tokens", "prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "thought_tokens", "total_tokens", "first_token", "token_count", "tokenizer_name", "tokenizer", "cached_read_tokens", "threshold_tokens", "display_tokens", "summary_target_tokens", "last_prompt_tokens", "last_completion_tokens", "last_total_tokens", "tokens_saved", "total_tokens_after", "total_tokens_before", "total_tokens_saved":
		return true
	}
	if strings.HasSuffix(normalized, "_tokens") || strings.Contains(normalized, "tokenizer") || strings.Contains(normalized, "subtoken") {
		return true
	}
	for _, part := range parts {
		switch part {
		case "tokens", "tokenizer", "subtoken", "tokenize", "integrity":
			return true
		}
	}
	return false
}

func LooksTemplated(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.Contains(trimmed, "${") || strings.Contains(trimmed, "$(") || strings.Contains(trimmed, "{{")
}

func IsPlaceholder(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "changeme", "change-me", "replace-me", "example", "example-value", "placeholder", "todo", "redacted", "<redacted>":
		return true
	default:
		return false
	}
}

func IsSafeScalar(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "{", "}", "[", "]", "true", "false", "null", "none", "nil", "read", "write", "allow", "deny", "optional", "required", "string", "str", "int", "integer", "bool", "boolean", "object", "array", "number":
		return true
	default:
		return false
	}
}

func normalizeValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"'`)
}

func normalizeKey(value string) string {
	normalized := strings.Trim(strings.TrimSpace(value), `"'`+"`")
	if !assignmentKeyRegex.MatchString(normalized) {
		return ""
	}
	return normalized
}

func LooksSecretishValue(value string) bool {
	trimmed := normalizeValue(value)
	if trimmed == "" || IsSafeScalar(trimmed) {
		return false
	}
	if len(trimmed) >= 12 {
		return true
	}
	if strings.ContainsAny(trimmed, "-_/@+:.=") {
		return true
	}
	return hasMixedClasses(trimmed) && len(trimmed) >= 8
}

func hasMixedClasses(value string) bool {
	var hasLower, hasUpper, hasDigit bool
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	count := 0
	for _, v := range []bool{hasLower, hasUpper, hasDigit} {
		if v {
			count++
		}
	}
	return count >= 2
}

func extractAssignment(line string) (string, string, bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	for _, separator := range []string{"=", ":"} {
		index := strings.Index(line, separator)
		if index <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:index])
		value := strings.TrimSpace(line[index+1:])
		if key == "" {
			return "", "", false
		}
		return key, value, true
	}
	return "", "", false
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, char := range value {
		counts[char]++
	}
	length := float64(len([]rune(value)))
	entropy := 0.0
	for _, count := range counts {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func dedupe(matches []Match) []Match {
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]Match, 0, len(matches))
	for _, match := range matches {
		key := strings.Join([]string{
			match.Detector,
			match.Name,
			match.Fingerprint,
			fmt.Sprintf("%d", match.Line),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, match)
	}
	return result
}
