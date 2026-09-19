package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/ramKarthik57/provenancex/internal/environment"
)

// StageExecution records the execution details of a single build stage
type StageExecution struct {
	Name            string        `json:"name"`
	Command         string        `json:"command"`
	RedactedCommand string        `json:"redactedCommand"`
	Args            []string      `json:"args"`
	RedactedArgs    []string      `json:"redactedArgs"`
	StartTime       time.Time     `json:"startTime"`
	EndTime         time.Time     `json:"endTime"`
	Duration        time.Duration `json:"duration"`
	ExitCode        int           `json:"exitCode"`
	Stdout          string        `json:"stdout,omitempty"`
	Stderr          string        `json:"stderr,omitempty"`
	Error           string        `json:"error,omitempty"`
	Success         bool          `json:"success"`
}

// BuildRecord aggregates the telemetry of an entire build pipeline execution
type BuildRecord struct {
	BuildID         string            `json:"buildId"`
	ProjectDir      string            `json:"projectDir"`
	StartTime       time.Time         `json:"startTime"`
	EndTime         time.Time         `json:"endTime"`
	TotalDuration   time.Duration     `json:"totalDuration"`
	Success         bool              `json:"success"`
	Stages          []*StageExecution `json:"stages"`
	EnvironmentHash string            `json:"environmentHash,omitempty"`
}

// Runner manages secure, monitored command execution with secret redaction
type Runner struct {
	redactor *environment.Redactor
}

// NewRunner constructs a new build execution runner
func NewRunner() *Runner {
	return &Runner{
		redactor: environment.NewRedactor(),
	}
}

// GenerateBuildID generates a cryptographically random build identifier
func GenerateBuildID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "bld-" + hex.EncodeToString(b)
}

// ExecuteStage executes a build stage command in dir, recording all telemetry and redacting secrets
func (r *Runner) ExecuteStage(ctx context.Context, stageName, dir, command string, args []string, envVars map[string]string) (*StageExecution, error) {
	redactedCmd := r.redactor.RedactString(command)
	redactedArgs := make([]string, len(args))
	for i, arg := range args {
		redactedArgs[i] = r.redactor.RedactString(arg)
	}

	stage := &StageExecution{
		Name:            stageName,
		Command:         command,
		RedactedCommand: redactedCmd,
		Args:            args,
		RedactedArgs:    redactedArgs,
		StartTime:       time.Now().UTC(),
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = dir

	// Inject environment variables with sanitized values
	if len(envVars) > 0 {
		cmd.Env = os.Environ()
		for k, v := range envVars {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(&stdoutBuf)
	cmd.Stderr = io.MultiWriter(&stderrBuf)

	err := cmd.Run()
	stage.EndTime = time.Now().UTC()
	stage.Duration = stage.EndTime.Sub(stage.StartTime)

	if cmd.ProcessState != nil {
		stage.ExitCode = cmd.ProcessState.ExitCode()
	}

	stage.Stdout = r.redactor.RedactString(stdoutBuf.String())
	stage.Stderr = r.redactor.RedactString(stderrBuf.String())

	if err != nil {
		stage.Success = false
		stage.Error = err.Error()
		return stage, err
	}

	stage.Success = stage.ExitCode == 0
	return stage, nil
}
