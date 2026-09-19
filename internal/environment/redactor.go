package environment

import (
	"regexp"
)

var (
	// sensitiveKeyPatterns matches environment variable names containing sensitive tokens
	sensitiveKeyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)password`),
		regexp.MustCompile(`(?i)token`),
		regexp.MustCompile(`(?i)secret`),
		regexp.MustCompile(`(?i)api[_-]?key`),
		regexp.MustCompile(`(?i)auth`),
		regexp.MustCompile(`(?i)cred`),
		regexp.MustCompile(`(?i)private[_-]?key`),
		regexp.MustCompile(`(?i)access[_-]?key`),
		regexp.MustCompile(`(?i)jwt`),
		regexp.MustCompile(`(?i)cert`),
		regexp.MustCompile(`(?i)ssh`),
	}

	// sensitiveValuePatterns matches patterns in arbitrary values
	sensitiveValuePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`),
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
		regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`), // JWT
	}
)

// Redactor sanitizes environment variables and command arguments
type Redactor struct{}

// NewRedactor constructs a Redactor
func NewRedactor() *Redactor {
	return &Redactor{}
}

// RedactEnvVar checks if a key-value pair is sensitive, returning "[REDACTED]" if so
func (r *Redactor) RedactEnvVar(key, val string) string {
	for _, pat := range sensitiveKeyPatterns {
		if pat.MatchString(key) {
			return "[REDACTED]"
		}
	}

	for _, pat := range sensitiveValuePatterns {
		if pat.MatchString(val) {
			return "[REDACTED]"
		}
	}

	return val
}

// RedactString sanitizes inline secrets within command arguments or log lines
func (r *Redactor) RedactString(input string) string {
	result := input
	// Replace key=value or --token=xyz
	inlineRegex := regexp.MustCompile(`(?i)(--?(?:token|secret|password|key|auth|api-key)=)([^ \t\r\n"']+)`)
	result = inlineRegex.ReplaceAllString(result, "${1}[REDACTED]")

	for _, pat := range sensitiveValuePatterns {
		result = pat.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}
