package telemetry

import (
	"context"
	"time"
)

// ProviderType identifies the underlying telemetry mechanism
type ProviderType string

const (
	ProviderETW     ProviderType = "WINDOWS_ETW"
	ProviderEBPF    ProviderType = "LINUX_EBPF"
	ProviderPolling ProviderType = "POLLING_FALLBACK"
)

// ProcessEvent records process lifecycle events
type ProcessEvent struct {
	PID          int       `json:"pid"`
	PPID         int       `json:"ppid"`
	Name         string    `json:"name"`
	CommandLine  string    `json:"commandLine"`
	Executable   string    `json:"executable"`
	Timestamp    time.Time `json:"timestamp"`
	ExitCode     int       `json:"exitCode,omitempty"`
	BuildStage   string    `json:"buildStage,omitempty"`
	IsSuspicious bool      `json:"isSuspicious"`
}

// NetworkEvent records outbound/inbound socket operations
type NetworkEvent struct {
	PID         int       `json:"pid"`
	ProcessName string    `json:"processName"`
	Protocol    string    `json:"protocol"`
	Destination string    `json:"destination"`
	Port        int       `json:"port"`
	Timestamp   time.Time `json:"timestamp"`
	BuildStage  string    `json:"buildStage,omitempty"`
	IsAllowed   bool      `json:"isAllowed"`
}

// FileEvent records filesystem mutations
type FileEvent struct {
	PID       int       `json:"pid"`
	Path      string    `json:"path"`
	Action    string    `json:"action"` // CREATE, MODIFY, DELETE, RENAME
	Timestamp time.Time `json:"timestamp"`
}

// ProcessTelemetry defines the interface for capturing process execution telemetry
type ProcessTelemetry interface {
	Start(ctx context.Context, stage string) error
	Stop() ([]*ProcessEvent, error)
}

// NetworkTelemetry defines the interface for capturing network connection events
type NetworkTelemetry interface {
	Start(ctx context.Context, stage string) error
	Stop() ([]*NetworkEvent, error)
}

// FileTelemetry defines the interface for capturing filesystem mutation events
type FileTelemetry interface {
	Start(ctx context.Context, rootDir string) error
	Stop() ([]*FileEvent, error)
}

// TelemetrySession reports the active provider and resolution capabilities
type TelemetrySession struct {
	Provider           ProviderType `json:"provider"`
	IsFallback         bool         `json:"isFallback"`
	Resolution         string       `json:"resolution"` // "Microsecond (Kernel Native)" vs "Second (Polling Snapshot)"
	CapabilitiesNotice string       `json:"capabilitiesNotice"`
}

// StageCorrelation maps runtime events to specific build phases
type StageCorrelation struct {
	Stage             string          `json:"stage"`
	ExpectedProcesses []string        `json:"expectedProcesses"`
	ObservedProcesses []*ProcessEvent `json:"observedProcesses"`
	NetworkEvents     []*NetworkEvent `json:"networkEvents"`
	UnexpectedEvents  []string        `json:"unexpectedEvents"`
}
