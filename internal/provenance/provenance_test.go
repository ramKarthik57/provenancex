package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/repository"
)

func TestGenerateAndVerifyProvenance(t *testing.T) {
	art := &artifact.Metadata{
		Name:   "app.exe",
		SHA256: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
		Size:   1024,
	}

	repo := &repository.State{
		RepoURL:   "https://github.com/ramKarthik57/provenancex",
		CommitSHA: "9af08e100f749553f1d248fe4ebf32b12bf087e5",
	}

	start := time.Now().Add(-1 * time.Minute)
	end := time.Now()

	stmt, err := GenerateSLSAv1(art, repo, "bld-test-123", "go", []string{"build"}, start, end)
	if err != nil {
		t.Fatalf("GenerateSLSAv1 failed: %v", err)
	}

	tmpDir := t.TempDir()
	provFile := filepath.Join(tmpDir, "provenance.json")
	data, _ := json.MarshalIndent(stmt, "", "  ")
	os.WriteFile(provFile, data, 0644)

	parsed, err := ParseInTotoStatement(provFile)
	if err != nil {
		t.Fatalf("ParseInTotoStatement failed: %v", err)
	}

	verifier := NewVerifier(nil)
	res := verifier.Verify(parsed, art, repo)

	if !res.Valid {
		t.Errorf("expected valid verification, got contradictions: %+v", res.Contradictions)
	}
	if len(res.Contradictions) != 0 {
		t.Errorf("expected 0 contradictions, got %d", len(res.Contradictions))
	}
}

func TestProvenanceContradictionDetection(t *testing.T) {
	art := &artifact.Metadata{
		Name:   "app.exe",
		SHA256: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
	}

	repo := &repository.State{
		RepoURL:   "https://github.com/ramKarthik57/provenancex",
		CommitSHA: "9af08e100f749553f1d248fe4ebf32b12bf087e5",
	}

	// 1. Provenance claiming a different artifact SHA (Artifact Tampering / Fake Provenance)
	tamperedStmt := &InTotoStatement{
		Type:          InTotoStatementV1,
		PredicateType: SLSAProvenanceV1,
		Subject: []Subject{
			{
				Name: "app.exe",
				Digest: map[string]string{
					"sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // FAKE HASH
				},
			},
		},
		Predicate: SLSAv1Predicate{
			BuildDefinition: BuildDefinition{
				BuildType: GenericBuildType,
				ResolvedDependencies: []ResourceDescriptor{
					{
						URI: repo.RepoURL,
						Digest: map[string]string{
							"sha1": "0000000000000000000000000000000000000000", // FAKE COMMIT
						},
					},
				},
			},
			RunDetails: RunDetails{
				Builder: BuilderMetadata{
					ID: "https://evil-hacker.com/builder",
				},
			},
		},
	}

	verifier := NewVerifier(nil)
	res := verifier.Verify(tamperedStmt, art, repo)

	if res.Valid {
		t.Fatalf("expected tampered provenance to fail verification")
	}

	if len(res.Contradictions) < 2 {
		t.Errorf("expected at least 2 contradictions (hash mismatch and commit mismatch), got %d", len(res.Contradictions))
	}

	hasHashContradiction := false
	hasCommitContradiction := false
	for _, c := range res.Contradictions {
		if c.Field == "subject.digest.sha256" {
			hasHashContradiction = true
		}
		if c.Field == "materials.digest" {
			hasCommitContradiction = true
		}
	}

	if !hasHashContradiction {
		t.Errorf("expected subject.digest.sha256 contradiction")
	}
	if !hasCommitContradiction {
		t.Errorf("expected materials.digest contradiction")
	}
}
