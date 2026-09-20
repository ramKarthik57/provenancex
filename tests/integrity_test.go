package tests

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

func TestEndToEndSampleArtifactIntegrity(t *testing.T) {
	samplePath := filepath.Join("fixtures", "sample-artifact.txt")
	meta, err := artifact.Inspect(samplePath, ".")
	if err != nil {
		t.Fatalf("failed inspecting sample artifact fixture: %v", err)
	}

	if meta.SHA256 == "" {
		t.Errorf("expected non-empty SHA-256 for sample artifact")
	}
	if meta.Size <= 0 {
		t.Errorf("expected positive artifact size, got %d", meta.Size)
	}

	// Double check by hashing manually
	calculatedHash, size, err := crypto.HashFile(samplePath)
	if err != nil {
		t.Fatalf("crypto.HashFile failed: %v", err)
	}

	if calculatedHash != meta.SHA256 {
		t.Errorf("hash mismatch: metadata has %s, calculated %s", meta.SHA256, calculatedHash)
	}
	if size != meta.Size {
		t.Errorf("size mismatch: metadata has %d, calculated %d", meta.Size, size)
	}
}

func TestEndToEndRepositoryInspection(t *testing.T) {
	col, err := repository.NewCollector()
	if err != nil {
		t.Fatalf("failed to create repository collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state, err := col.Collect(ctx, "..")
	if err != nil {
		t.Fatalf("failed collecting repository state: %v", err)
	}

	if state.Branch != "main" && state.Branch != "research-validation" {
		t.Errorf("expected branch 'main' or 'research-validation', got '%s'", state.Branch)
	}
	if state.CommitSHA == "" {
		t.Errorf("expected non-empty commit SHA")
	}
}
