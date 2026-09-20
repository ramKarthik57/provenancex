package windows

import (
	"testing"
)

func TestETWProviderInitialization(t *testing.T) {
	_, session := NewETWProvider()
	if session.Provider == "" {
		t.Fatalf("expected non-empty telemetry provider")
	}
	if session.CapabilitiesNotice == "" {
		t.Fatalf("expected non-empty capabilities notice")
	}
	t.Logf("Active Provider: %s (Fallback: %v, Notice: %s)", session.Provider, session.IsFallback, session.CapabilitiesNotice)
}
