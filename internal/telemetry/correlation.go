package telemetry

import (
	"fmt"
	"strings"
)

// StageCorrelator cross-references runtime process and network events with declared build stages
type StageCorrelator struct {
	allowedProcessesByStage map[string][]string
	allowedDomainsByStage   map[string][]string
}

// NewStageCorrelator constructs a stage-aware event correlator
func NewStageCorrelator() *StageCorrelator {
	return &StageCorrelator{
		allowedProcessesByStage: map[string][]string{
			"dependency-install": {"python", "python.exe", "pip", "pip.exe", "npm", "npm.cmd", "go", "go.exe"},
			"compilation":        {"go", "go.exe", "gcc", "gcc.exe", "clang", "rustc"},
			"packaging":          {"tar", "tar.exe", "zip", "zip.exe", "docker", "docker.exe"},
		},
		allowedDomainsByStage: map[string][]string{
			"dependency-install": {"registry.npmjs.org", "pypi.org", "proxy.golang.org"},
			"compilation":        {}, // No network allowed during compilation
			"packaging":          {}, // No network allowed during packaging
		},
	}
}

// CorrelateStage validates process and network telemetry against expectations for a build stage
func (sc *StageCorrelator) CorrelateStage(stage string, procs []*ProcessEvent, nets []*NetworkEvent) *StageCorrelation {
	report := &StageCorrelation{
		Stage:             stage,
		ExpectedProcesses: sc.allowedProcessesByStage[stage],
		ObservedProcesses: procs,
		NetworkEvents:     nets,
		UnexpectedEvents:  make([]string, 0),
	}

	allowedProcMap := make(map[string]bool)
	for _, p := range sc.allowedProcessesByStage[stage] {
		allowedProcMap[strings.ToLower(p)] = true
	}

	for _, proc := range procs {
		pName := strings.ToLower(proc.Name)
		if len(allowedProcMap) > 0 && !allowedProcMap[pName] {
			report.UnexpectedEvents = append(report.UnexpectedEvents,
				fmt.Sprintf("Unexpected process %q (PID %d) executed during stage %q", proc.Name, proc.PID, stage))
		}
	}

	for _, net := range nets {
		// If stage disallows network, or domain not allowed
		allowedDomains := sc.allowedDomainsByStage[stage]
		if len(allowedDomains) == 0 {
			report.UnexpectedEvents = append(report.UnexpectedEvents,
				fmt.Sprintf("UNAUTHORIZED NETWORK EGRESS: Process %q (PID %d) connected to %s during non-network stage %q",
					net.ProcessName, net.PID, net.Destination, stage))
		}
	}

	return report
}
