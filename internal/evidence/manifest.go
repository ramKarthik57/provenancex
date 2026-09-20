package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/process"
)

// EvidenceManifest is the unified evidence record captured across all layers during build execution
type EvidenceManifest struct {
	BuildID          string                   `json:"buildId"`
	Timestamp        time.Time                `json:"timestamp"`
	Duration         time.Duration            `json:"duration"`
	Success          bool                     `json:"success"`
	Command          string                   `json:"command"`
	RedactedArgs     []string                 `json:"redactedArgs"`
	ExitCode         int                      `json:"exitCode"`
	Environment      *environment.Fingerprint `json:"environment"`
	FilesystemDelta  *filesystem.Delta        `json:"filesystemDelta"`
	CreatedArtifacts []*artifact.Metadata     `json:"createdArtifacts"`
	ArtifactMerkle   string                   `json:"artifactMerkleRoot,omitempty"`
	ProcessTree      *process.Tree            `json:"processTree,omitempty"`
	NetworkAudit     *network.Evaluation      `json:"networkAudit,omitempty"`
}

// LoadManifest reads and parses an EvidenceManifest from a JSON file
func LoadManifest(path string) (*EvidenceManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifest EvidenceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	return &manifest, nil
}

// SaveManifest writes an EvidenceManifest to a JSON file
func SaveManifest(path string, m *EvidenceManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize manifest: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write manifest to %s: %w", path, err)
	}

	return nil
}
