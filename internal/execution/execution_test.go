package execution

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecuteStageWithRedaction(t *testing.T) {
	runner := NewRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDir := t.TempDir()

	command := "cmd.exe"
	args := []string{"/c", "echo", "deploying", "--token=super_secret_auth_token_xyz"}
	if runtime.GOOS != "windows" {
		command = "sh"
		args = []string{"-c", "echo deploying --token=super_secret_auth_token_xyz"}
	}

	stage, err := runner.ExecuteStage(
		ctx,
		"build-step",
		tmpDir,
		command,
		args,
		nil,
	)
	if err != nil {
		t.Fatalf("ExecuteStage failed: %v", err)
	}

	if !stage.Success {
		t.Errorf("expected stage to succeed, got failure: %s", stage.Error)
	}
	if stage.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", stage.ExitCode)
	}

	// Verify sensitive token is redacted in RedactedArgs
	hasRedacted := false
	for _, a := range stage.RedactedArgs {
		if strings.Contains(a, "super_secret_auth_token_xyz") {
			t.Errorf("secret token leaked in RedactedArgs: %s", a)
		}
		if strings.Contains(a, "--token=[REDACTED]") {
			hasRedacted = true
		}
	}
	if !hasRedacted {
		t.Errorf("expected --token=[REDACTED] in RedactedArgs")
	}

	// Verify token is redacted in stdout
	if strings.Contains(stage.Stdout, "super_secret_auth_token_xyz") {
		t.Errorf("secret token leaked in stdout: %s", stage.Stdout)
	}
}

func TestGenerateBuildID(t *testing.T) {
	id1 := GenerateBuildID()
	id2 := GenerateBuildID()
	if id1 == "" || id2 == "" {
		t.Fatalf("expected non-empty build IDs")
	}
	if id1 == id2 {
		t.Fatalf("expected unique build IDs, got %s == %s", id1, id2)
	}
	if !strings.HasPrefix(id1, "bld-") {
		t.Errorf("expected 'bld-' prefix, got %s", id1)
	}
}
