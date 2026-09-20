package gaps

import (
	"testing"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

func TestEvidenceGapDetection(t *testing.T) {
	// Only provide artifact, leaving all other required planes missing
	in := &correlation.CorrelationInput{
		Artifact: &artifact.Metadata{
			Name:   "app.exe",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	analyzer := NewAnalyzer(nil)
	report := analyzer.Analyze(in, nil)

	if report.CoverageComplete {
		t.Fatalf("expected coverage to be incomplete")
	}
	if report.Verdict != "WARNING" {
		t.Fatalf("expected verdict WARNING on missing evidence, got %s", report.Verdict)
	}
	if report.MissingCount == 0 {
		t.Fatalf("expected missing count > 0, got 0")
	}

	// Verify unobserved / missing distinction
	foundMissing := false
	for _, l := range report.Layers {
		if l.Layer == evidence.LayerNetwork && l.Status == StatusMissing {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatalf("expected network layer to be marked MISSING")
	}

	terminal := report.FormatTerminal()
	if len(terminal) == 0 {
		t.Fatalf("expected non-empty formatted terminal report")
	}
}

func TestLineageGeneration(t *testing.T) {
	in := &correlation.CorrelationInput{
		Artifact: &artifact.Metadata{
			Name:   "app.exe",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	res := &correlation.Result{
		IsConsistent: false,
		Contradictions: []*correlation.Contradiction{
			{
				Layer1:      evidence.LayerArtifact,
				Layer2:      evidence.LayerProvenance,
				Subject:     "Artifact SHA-256",
				Claim1:      "sha256:1111",
				Claim2:      "sha256:2222",
				Description: "Post-build byte tampering detected",
			},
		},
	}

	analyzer := NewAnalyzer(nil)
	report := analyzer.Analyze(in, res)

	if len(report.Lineage) == 0 {
		t.Fatalf("expected lineage trail for contradicted build")
	}
	step := report.Lineage[0]
	if step.ContradictionID != "C-01" {
		t.Fatalf("expected contradiction ID C-01, got %s", step.ContradictionID)
	}
}
