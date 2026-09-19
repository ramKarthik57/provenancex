package environment

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSecretRedaction(t *testing.T) {
	redactor := NewRedactor()

	// Test sensitive environment keys
	sensitivePairs := map[string]string{
		"DATABASE_PASSWORD": "supersecretpassword123",
		"GITHUB_TOKEN":      "ghp_1234567890abcdef1234567890abcdef1234",
		"AWS_SECRET_KEY":    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"API_KEY":           "AIzaSyD-FakeApiKeyForTesting123456",
		"AUTH_HEADER":       "Bearer my-special-auth-token",
		"SSH_PRIVATE_KEY":   "key-material",
	}

	for k, v := range sensitivePairs {
		redacted := redactor.RedactEnvVar(k, v)
		if redacted != "[REDACTED]" {
			t.Errorf("expected key '%s' to be redacted, got '%s'", k, redacted)
		}
	}

	// Test benign keys
	benignPairs := map[string]string{
		"PATH":    "/usr/bin:/bin",
		"LANG":    "en_US.UTF-8",
		"USER":    "buildbot",
		"NODE_ENV": "production",
	}

	for k, v := range benignPairs {
		out := redactor.RedactEnvVar(k, v)
		if out != v {
			t.Errorf("expected benign key '%s' to remain '%s', got '%s'", k, v, out)
		}
	}

	// Test command argument inline redaction
	cmdLine := "npm publish --token=my_secret_token_12345 --access=public"
	sanitized := redactor.RedactString(cmdLine)
	if strings.Contains(sanitized, "my_secret_token_12345") {
		t.Errorf("failed to redact inline token in command: %s", sanitized)
	}
	if !strings.Contains(sanitized, "--token=[REDACTED]") {
		t.Errorf("expected --token=[REDACTED] in command, got %s", sanitized)
	}
}

func TestEnvironmentCollector(t *testing.T) {
	collector := NewCollector()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fp, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if fp.OS == "" {
		t.Errorf("expected non-empty OS")
	}
	if fp.Architecture == "" {
		t.Errorf("expected non-empty Architecture")
	}
	if fp.FingerprintHash == "" {
		t.Errorf("expected non-empty FingerprintHash")
	}

	// Verify no passwords or secrets leaked in collected environment vars
	for k, v := range fp.EnvironmentVars {
		if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") {
			if v != "[REDACTED]" {
				t.Errorf("unredacted sensitive environment variable found: %s=%s", k, v)
			}
		}
	}
}
