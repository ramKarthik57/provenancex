package process

import "time"

// ProcessNode represents a single process within an execution hierarchy
type ProcessNode struct {
	PID          int            `json:"pid"`
	ParentPID    int            `json:"parentPid"`
	Name         string         `json:"name"`
	Executable   string         `json:"executable"`
	CommandLine  string         `json:"commandLine"`
	StartTime    time.Time      `json:"startTime"`
	EndTime      time.Time      `json:"endTime,omitempty"`
	ExitCode     int            `json:"exitCode,omitempty"`
	IsSuspicious bool           `json:"isSuspicious"`
	AlertReason  string         `json:"alertReason,omitempty"`
	Children     []*ProcessNode `json:"children,omitempty"`
}

// Tree represents the hierarchical tree of processes spawned during a build
type Tree struct {
	Root           *ProcessNode   `json:"root"`
	TotalProcesses int            `json:"totalProcesses"`
	SuspiciousCount int           `json:"suspiciousCount"`
	Processes      []*ProcessNode `json:"processes"`
}
