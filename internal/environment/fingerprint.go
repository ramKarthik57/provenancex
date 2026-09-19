package environment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ToolVersion represents an installed compiler, runtime, or package manager
type ToolVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// Fingerprint captures the complete build environment state with sensitive data redacted
type Fingerprint struct {
	Timestamp       time.Time         `json:"timestamp"`
	OS              string            `json:"os"`
	Architecture    string            `json:"architecture"`
	OSVersion       string            `json:"osVersion"`
	Hostname        string            `json:"hostname"`
	Tools           []ToolVersion     `json:"tools"`
	EnvironmentVars map[string]string `json:"environmentVars"`
	FingerprintHash string            `json:"fingerprintHash"`
}

// Collector inspects and fingerprints host and build environments
type Collector struct {
	redactor *Redactor
}

// NewCollector constructs an environment collector
func NewCollector() *Collector {
	return &Collector{
		redactor: NewRedactor(),
	}
}

// Collect captures host environment and computes a reproducible fingerprint
func (c *Collector) Collect(ctx context.Context) (*Fingerprint, error) {
	hostname, _ := os.Hostname()

	fp := &Fingerprint{
		Timestamp:       time.Now().UTC(),
		OS:              runtime.GOOS,
		Architecture:    runtime.GOARCH,
		Hostname:        hostname,
		Tools:           []ToolVersion{},
		EnvironmentVars: make(map[string]string),
	}

	// Detect OS release / version
	fp.OSVersion = c.detectOSVersion(ctx)

	// Collect tool versions
	toolsToInspect := []struct {
		name string
		args []string
	}{
		{"go", []string{"version"}},
		{"node", []string{"--version"}},
		{"npm", []string{"--version"}},
		{"python", []string{"--version"}},
		{"docker", []string{"--version"}},
		{"git", []string{"--version"}},
	}

	for _, tool := range toolsToInspect {
		if path, err := exec.LookPath(tool.name); err == nil {
			cmd := exec.CommandContext(ctx, path, tool.args...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				versionStr := strings.TrimSpace(string(out))
				// take first line
				if idx := strings.Index(versionStr, "\n"); idx != -1 {
					versionStr = strings.TrimSpace(versionStr[:idx])
				}
				fp.Tools = append(fp.Tools, ToolVersion{
					Name:    tool.name,
					Version: versionStr,
					Path:    path,
				})
			}
		}
	}

	// Collect and redact environment variables
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			k := parts[0]
			v := parts[1]
			fp.EnvironmentVars[k] = c.redactor.RedactEnvVar(k, v)
		}
	}

	// Compute deterministic SHA-256 fingerprint hash over stable attributes
	fp.FingerprintHash = c.computeHash(fp)

	return fp, nil
}

func (c *Collector) detectOSVersion(ctx context.Context) string {
	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "cmd.exe", "/c", "ver")
		if out, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	} else {
		cmd := exec.CommandContext(ctx, "uname", "-sr")
		if out, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return runtime.GOOS
}

func (c *Collector) computeHash(fp *Fingerprint) string {
	// Canonical representation of OS, Arch, and Tools
	h := sha256.New()
	fmt.Fprintf(h, "os:%s|arch:%s|osver:%s|", fp.OS, fp.Architecture, fp.OSVersion)

	sort.Slice(fp.Tools, func(i, j int) bool {
		return fp.Tools[i].Name < fp.Tools[j].Name
	})
	for _, t := range fp.Tools {
		fmt.Fprintf(h, "tool:%s=%s|", t.Name, t.Version)
	}

	return hex.EncodeToString(h.Sum(nil))
}
