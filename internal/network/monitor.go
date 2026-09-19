package network

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultAllowedDestinations contains standard authorized build package registries
var DefaultAllowedDestinations = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"registry.npmjs.org",
	"proxy.golang.org",
	"sum.golang.org",
	"github.com",
	"raw.githubusercontent.com",
	"docker.io",
	"registry.hub.docker.com",
	"ghcr.io",
	"127.0.0.1",
	"localhost",
	"::1",
}

// Monitor checks build-time network destinations against policy
type Monitor struct {
	allowedRules []string
}

// NewMonitor constructs a network evidence monitor with an allowlist
func NewMonitor(allowedDestinations []string) *Monitor {
	rules := DefaultAllowedDestinations
	if len(allowedDestinations) > 0 {
		rules = append(rules, allowedDestinations...)
	}
	return &Monitor{
		allowedRules: rules,
	}
}

// EvaluateConnection tests a connection record against the allowlist
func (m *Monitor) EvaluateConnection(conn *ConnectionRecord) {
	dest := strings.ToLower(strings.TrimSpace(conn.Destination))

	// If destination is an IP:port, split host
	if host, _, err := net.SplitHostPort(dest); err == nil {
		dest = host
	}

	for _, allowed := range m.allowedRules {
		cleanAllowed := strings.ToLower(strings.TrimSpace(allowed))
		// Exact match or subdomain match (e.g. repo.pypi.org matches pypi.org)
		if dest == cleanAllowed || strings.HasSuffix(dest, "."+cleanAllowed) {
			conn.IsAllowed = true
			return
		}
	}

	conn.IsAllowed = false
	conn.AlertReason = "UNAUTHORIZED BUILD NETWORK DESTINATION: " + conn.Destination
}

// Audit evaluates a set of connection records and produces an audit evaluation
func (m *Monitor) Audit(records []*ConnectionRecord) *Evaluation {
	eval := &Evaluation{
		TotalConnections: len(records),
		Connections:      records,
		Violations:       []*ConnectionRecord{},
	}

	for _, rec := range records {
		m.EvaluateConnection(rec)
		if rec.IsAllowed {
			eval.AllowedCount++
		} else {
			eval.ViolationCount++
			eval.Violations = append(eval.Violations, rec)
		}
	}

	eval.IsPolicyCompliant = eval.ViolationCount == 0
	return eval
}

var netstatRegex = regexp.MustCompile(`^\s*(TCP|UDP)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s+(\d+)\s*$`)

// SnapshotWindowsSockets snapshots active connections associated with a target PID or all build processes
func (m *Monitor) SnapshotWindowsSockets(ctx context.Context, targetPID int) ([]*ConnectionRecord, error) {
	cmd := exec.CommandContext(ctx, "netstat.exe", "-ano")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var records []*ConnectionRecord
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := netstatRegex.FindStringSubmatch(line)
		if len(matches) >= 6 {
			proto := matches[1]
			local := matches[2]
			remote := matches[3]
			pidStr := matches[5]
			pid, _ := strconv.Atoi(pidStr)

			if targetPID > 0 && pid != targetPID {
				continue
			}

			// Exclude listening or loopback noise unless relevant
			if remote == "*:*" || strings.HasPrefix(remote, "0.0.0.0") || strings.HasPrefix(remote, "[::]") {
				continue
			}

			remoteHost, portStr, _ := net.SplitHostPort(remote)
			port, _ := strconv.Atoi(portStr)

			records = append(records, &ConnectionRecord{
				Timestamp:   time.Now().UTC(),
				PID:         pid,
				Protocol:    proto,
				LocalAddr:   local,
				RemoteAddr:  remote,
				Destination: remoteHost,
				Port:        port,
			})
		}
	}

	return records, nil
}
