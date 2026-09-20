package process

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/environment"
)

var (
	// Suspicious process patterns commonly used in supply-chain attacks for C2 / exfiltration
	suspiciousBinaryPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:curl|wget|nc|netcat|ncat|certutil|bitsadmin)\b`),
		regexp.MustCompile(`(?i)-enc(?:odedcommand)?\s+[a-zA-Z0-9+/=]{16,}`),
		regexp.MustCompile(`(?i)\b(?:whoami|net\.exe|nltest)\b`),
		regexp.MustCompile(`(?i)downloadstring|invoke-expression|iex\b`),
	}
)

// Monitor captures process lifecycle telemetry
type Monitor struct {
	redactor *environment.Redactor
}

// NewMonitor constructs a process monitor
func NewMonitor() *Monitor {
	return &Monitor{
		redactor: environment.NewRedactor(),
	}
}

// InspectProcess checks whether a process command line or executable name exhibits suspicious behavior
func (m *Monitor) InspectProcess(node *ProcessNode) {
	node.CommandLine = m.redactor.RedactString(node.CommandLine)

	for _, pat := range suspiciousBinaryPatterns {
		if pat.MatchString(node.Name) || pat.MatchString(node.CommandLine) {
			node.IsSuspicious = true
			node.AlertReason = "Process matches unauthorized execution pattern: " + pat.String()
			return
		}
	}
}

// BuildTree converts a flat list of ProcessNodes into a hierarchical process tree
func (m *Monitor) BuildTree(nodes []*ProcessNode) *Tree {
	if len(nodes) == 0 {
		return &Tree{Processes: []*ProcessNode{}}
	}

	nodeMap := make(map[int]*ProcessNode)
	childMap := make(map[int][]*ProcessNode)
	suspiciousCount := 0

	for _, node := range nodes {
		m.InspectProcess(node)
		if node.IsSuspicious {
			suspiciousCount++
		}
		nodeMap[node.PID] = node
		childMap[node.ParentPID] = append(childMap[node.ParentPID], node)
	}

	for pid, children := range childMap {
		if parent, exists := nodeMap[pid]; exists {
			parent.Children = children
		}
	}

	// Find root node (parent not in map, or lowest PID)
	var root *ProcessNode
	for _, node := range nodes {
		if _, parentExists := nodeMap[node.ParentPID]; !parentExists {
			root = node
			break
		}
	}
	if root == nil && len(nodes) > 0 {
		root = nodes[0]
	}

	return &Tree{
		Root:            root,
		TotalProcesses:  len(nodes),
		SuspiciousCount: suspiciousCount,
		Processes:       nodes,
	}
}

// SnapshotWindowsProcesses takes a point-in-time snapshot of active processes on Windows
func (m *Monitor) SnapshotWindowsProcesses(ctx context.Context) ([]*ProcessNode, error) {
	// Query tasklist or WMIC/PowerShell
	cmd := exec.CommandContext(ctx, "tasklist.exe", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var nodes []*ProcessNode
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, `","`)
		if len(parts) >= 2 {
			name := strings.Trim(parts[0], `"`)
			pidStr := strings.Trim(parts[1], `"`)
			pid, _ := strconv.Atoi(pidStr)
			if pid > 0 {
				nodes = append(nodes, &ProcessNode{
					PID:       pid,
					Name:      name,
					StartTime: time.Now().UTC(),
				})
			}
		}
	}

	return nodes, nil
}
