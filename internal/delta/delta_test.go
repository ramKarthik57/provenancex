package delta

import (
	"strings"
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
)

func makeSampleManifest(id string, artHash string, toolVersion string) *evidence.EvidenceManifest {
	return &evidence.EvidenceManifest{
		BuildID:      id,
		Timestamp:    time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC),
		Duration:     5 * time.Second,
		Success:      true,
		Command:      "go build -trimpath",
		RedactedArgs: []string{"-trimpath", "-o", "app"},
		ExitCode:     0,
		Environment: &environment.Fingerprint{
			OS:           "linux",
			Architecture: "amd64",
			Tools: []environment.ToolVersion{
				{Name: "go", Version: toolVersion, Path: "/usr/local/go/bin/go"},
			},
			FingerprintHash: "fp-" + toolVersion,
		},
		FilesystemDelta: &filesystem.Delta{
			CreatedFiles: []*filesystem.FileSnapshot{
				{RelativePath: "app", SHA256: artHash, Size: 1024},
			},
		},
		CreatedArtifacts: []*artifact.Metadata{
			{Name: "app", RelativePath: "app", SHA256: artHash, Size: 1024},
		},
		ArtifactMerkle: "merkle-" + artHash,
		NetworkAudit: &network.Evaluation{
			TotalConnections: 0,
			Violations:       []*network.ConnectionRecord{},
		},
	}
}

func TestDeltaIdentical(t *testing.T) {
	m1 := makeSampleManifest("build-1", "hash123", "go1.23.6")
	m2 := makeSampleManifest("build-2", "hash123", "go1.23.6")

	report := CompareManifests(m1, m2)

	if report.OverallClassification != "IDENTICAL" {
		t.Errorf("expected IDENTICAL, got %s", report.OverallClassification)
	}
	if !report.ArtifactsIdentical || !report.EnvironmentIdentical || !report.CommandIdentical {
		t.Errorf("expected all layers identical")
	}
	if len(report.Differences) != 0 {
		t.Errorf("expected 0 differences, got %d", len(report.Differences))
	}

	term := FormatTerminal(report)
	if !strings.Contains(term, "IDENTICAL") {
		t.Errorf("terminal format missing IDENTICAL: %s", term)
	}
}

func TestDeltaArtifactDivergence(t *testing.T) {
	m1 := makeSampleManifest("build-1", "hash_original", "go1.23.6")
	m2 := makeSampleManifest("build-2", "hash_tampered", "go1.23.6")

	report := CompareManifests(m1, m2)

	if report.OverallClassification != "ARTIFACT_DIVERGENCE" {
		t.Errorf("expected ARTIFACT_DIVERGENCE, got %s", report.OverallClassification)
	}
	if report.ArtifactsIdentical {
		t.Errorf("expected ArtifactsIdentical to be false")
	}

	foundHashDiff := false
	for _, diff := range report.Differences {
		if diff.Category == CategoryArtifact && strings.Contains(diff.Field, "ArtifactSHA256") {
			foundHashDiff = true
			if diff.Severity != SeverityCritical {
				t.Errorf("expected SeverityCritical for artifact mismatch")
			}
		}
	}
	if !foundHashDiff {
		t.Errorf("expected ArtifactSHA256 difference item")
	}
}

func TestDeltaEnvironmentDrift(t *testing.T) {
	m1 := makeSampleManifest("build-1", "hash123", "go1.22.0")
	m2 := makeSampleManifest("build-2", "hash123", "go1.23.6")

	report := CompareManifests(m1, m2)

	if report.OverallClassification != "ENVIRONMENT_OR_COMMAND_DRIFT" {
		t.Errorf("expected ENVIRONMENT_OR_COMMAND_DRIFT, got %s", report.OverallClassification)
	}
	if !report.ArtifactsIdentical {
		t.Errorf("expected ArtifactsIdentical to be true despite environment drift")
	}
	if report.EnvironmentIdentical {
		t.Errorf("expected EnvironmentIdentical to be false")
	}
}

func TestDeltaFilesystemMutation(t *testing.T) {
	m1 := makeSampleManifest("build-1", "hash123", "go1.23.6")
	m2 := makeSampleManifest("build-2", "hash123", "go1.23.6")

	// Add unexpected extra created file to build 2
	m2.FilesystemDelta.CreatedFiles = append(m2.FilesystemDelta.CreatedFiles, &filesystem.FileSnapshot{
		RelativePath: ".backdoor",
		SHA256:       "badhash",
		Size:         500,
	})

	report := CompareManifests(m1, m2)

	if report.FilesystemIdentical {
		t.Errorf("expected FilesystemIdentical to be false")
	}

	foundExtra := false
	for _, diff := range report.Differences {
		if diff.Field == "CreatedFileExtra:.backdoor" {
			foundExtra = true
			break
		}
	}
	if !foundExtra {
		t.Errorf("expected CreatedFileExtra:.backdoor difference")
	}
}
