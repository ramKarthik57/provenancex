package correlation

import (
	"testing"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/execution"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/signature"
)

func TestCorrelatorConsistentBuild(t *testing.T) {
	correlator := NewCorrelator()

	input := &CorrelationInput{
		Repository: &repository.State{
			Branch:    "main",
			CommitSHA: "abc1234",
			IsClean:   true,
		},
		Dependencies: &dependency.Report{
			HasLockfile:  true,
			IsConsistent: true,
			DirectCount:  5,
		},
		Environment: &environment.Fingerprint{
			OS:              "windows",
			Architecture:    "amd64",
			FingerprintHash: "hash123",
		},
		Execution: &execution.StageExecution{
			Success:  true,
			ExitCode: 0,
		},
		ProcessTree: &process.Tree{
			SuspiciousCount: 0,
		},
		InputEvaluation: &filesystem.InputEvaluation{
			HasDiscrepancy: false,
		},
		NetworkAudit: &network.Evaluation{
			IsPolicyCompliant: true,
		},
		Artifact: &artifact.Metadata{
			Name:   "app.exe",
			SHA256: "deadbeef",
		},
		Signature: &signature.VerificationResult{
			Valid: true,
		},
	}

	result := correlator.Correlate(input)

	if !result.IsConsistent {
		t.Fatalf("expected build to be consistent, got contradictions: %+v", result.Contradictions)
	}

	if result.LayerStatuses[evidence.LayerSource] != evidence.StatusVerified {
		t.Errorf("expected source to be VERIFIED")
	}
	if result.LayerStatuses[evidence.LayerArtifact] != evidence.StatusVerified {
		t.Errorf("expected artifact to be VERIFIED")
	}
}

func TestCorrelatorContradictionDetection(t *testing.T) {
	correlator := NewCorrelator()

	// Scenario: Unexpected injected file observed during build + unauthorized network egress
	input := &CorrelationInput{
		Repository: &repository.State{
			IsClean: true,
		},
		InputEvaluation: &filesystem.InputEvaluation{
			UnexpectedInputs: []string{"/tmp/hidden-backdoor.sh"},
			HasDiscrepancy:   true,
		},
		NetworkAudit: &network.Evaluation{
			IsPolicyCompliant: false,
			Violations: []*network.ConnectionRecord{
				{
					Destination: "malicious-c2.xyz",
					AlertReason: "UNAUTHORIZED BUILD NETWORK DESTINATION: malicious-c2.xyz",
				},
			},
		},
	}

	result := correlator.Correlate(input)

	if result.IsConsistent {
		t.Fatalf("expected inconsistencies, got IsConsistent=true")
	}

	if len(result.Contradictions) < 2 {
		t.Errorf("expected at least 2 contradictions (unexpected input + network egress), got %d", len(result.Contradictions))
	}

	if result.LayerStatuses[evidence.LayerFilesystem] != evidence.StatusContradicted {
		t.Errorf("expected filesystem layer to be CONTRADICTED")
	}
	if result.LayerStatuses[evidence.LayerNetwork] != evidence.StatusContradicted {
		t.Errorf("expected network layer to be CONTRADICTED")
	}
}
