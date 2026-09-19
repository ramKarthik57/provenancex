package network

import (
	"testing"
	"time"
)

func TestNetworkAllowlistEvaluation(t *testing.T) {
	monitor := NewMonitor([]string{"custom-internal-registry.corp"})

	connections := []*ConnectionRecord{
		{
			Timestamp:   time.Now().UTC(),
			PID:         101,
			ProcessName: "npm.cmd",
			Protocol:    "TCP",
			RemoteAddr:  "104.16.19.35:443",
			Destination: "registry.npmjs.org",
			Port:        443,
		},
		{
			Timestamp:   time.Now().UTC(),
			PID:         102,
			ProcessName: "pip.exe",
			Protocol:    "TCP",
			RemoteAddr:  "151.101.0.223:443",
			Destination: "pypi.org",
			Port:        443,
		},
		{
			Timestamp:   time.Now().UTC(),
			PID:         103,
			ProcessName: "node.exe",
			Protocol:    "TCP",
			RemoteAddr:  "192.168.1.50:5000",
			Destination: "custom-internal-registry.corp",
			Port:        5000,
		},
		{
			Timestamp:   time.Now().UTC(),
			PID:         104,
			ProcessName: "curl.exe",
			Protocol:    "TCP",
			RemoteAddr:  "198.51.100.44:8080",
			Destination: "malicious-c2-exfiltration.xyz",
			Port:        8080,
		},
	}

	audit := monitor.Audit(connections)

	if audit.TotalConnections != 4 {
		t.Fatalf("expected 4 connections, got %d", audit.TotalConnections)
	}

	if audit.AllowedCount != 3 {
		t.Errorf("expected 3 allowed connections, got %d", audit.AllowedCount)
	}

	if audit.ViolationCount != 1 {
		t.Fatalf("expected 1 violation, got %d", audit.ViolationCount)
	}

	if audit.IsPolicyCompliant {
		t.Errorf("expected non-compliant status due to unauthorized destination")
	}

	violation := audit.Violations[0]
	if violation.Destination != "malicious-c2-exfiltration.xyz" {
		t.Errorf("expected violation on malicious host, got %s", violation.Destination)
	}
	if violation.IsAllowed {
		t.Errorf("expected IsAllowed to be false for violation")
	}
}
