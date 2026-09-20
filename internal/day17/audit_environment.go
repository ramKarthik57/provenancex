package day17

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// GatherEnvironmentMetadata collects complete runtime and machine provenance for the audit
func GatherEnvironmentMetadata(historicalFrozenCount int) *EnvironmentMetadata {
	gitCommit := getGitOutput("rev-parse", "HEAD")
	gitBranch := getGitOutput("rev-parse", "--abbrev-ref", "HEAD")
	gitStatus := getGitOutput("status", "--porcelain")
	isClean := len(strings.TrimSpace(gitStatus)) == 0

	cpuModel := runtime.GOARCH
	if val, ok := os.LookupEnv("PROCESSOR_IDENTIFIER"); ok {
		cpuModel = val
	}

	return &EnvironmentMetadata{
		HostArchitecture:               runtime.GOARCH,
		OperatingSystem:                runtime.GOOS,
		KernelVersion:                  runtime.Version(),
		CPUModel:                       cpuModel,
		LogicalCores:                   runtime.NumCPU(),
		GoVersion:                      runtime.Version(),
		GitCommit:                      gitCommit,
		GitBranch:                      gitBranch,
		WorkingTreeClean:               isClean,
		AuditExecutionTimestamp:        time.Now().UTC(),
		HistoricalBaselinesFrozenCount: historicalFrozenCount,
	}
}

func getGitOutput(args ...string) string {
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
