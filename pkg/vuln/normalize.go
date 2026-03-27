package vuln

import (
	"regexp"
	"strings"
)

var pythonNameJoiner = regexp.MustCompile(`[-_.]+`)

func normalizePackageName(ecosystem, name string) string {
	trimmed := strings.TrimSpace(name)
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi":
		return strings.ToLower(pythonNameJoiner.ReplaceAllString(trimmed, "-"))
	case "npm", "gem", "composer", "cargo", "nuget", "apk", "deb", "rpm":
		return strings.ToLower(trimmed)
	default:
		return trimmed
	}
}
