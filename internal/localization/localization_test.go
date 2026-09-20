package localization

import (
	"testing"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

func TestLocalizeEarliestTrustBreak(t *testing.T) {
	localizer := NewLocalizer()

	// Scenario: Source and Dependencies are fine, but Filesystem has unexpected input, causing Artifact to differ
	res := &correlation.Result{
		IsConsistent: false,
		LayerStatuses: map[evidence.Layer]evidence.Status{
			evidence.LayerSource:       evidence.StatusVerified,
			evidence.LayerDependencies: evidence.StatusVerified,
			evidence.LayerLockfile:     evidence.StatusVerified,
			evidence.LayerEnvironment:  evidence.StatusVerified,
			evidence.LayerBuild:        evidence.StatusVerified,
			evidence.LayerFilesystem:   evidence.StatusContradicted, // Earliest failure!
			evidence.LayerArtifact:     evidence.StatusContradicted,
		},
		UnexpectedInputs: []string{"/tmp/hidden-injected-config.json"},
		Contradictions: []*correlation.Contradiction{
			{
				Layer1:      evidence.LayerSource,
				Layer2:      evidence.LayerFilesystem,
				Subject:     "/tmp/hidden-injected-config.json",
				Description: "UNEXPECTED BUILD INPUT",
			},
			{
				Layer1:      evidence.LayerArtifact,
				Layer2:      evidence.LayerProvenance,
				Subject:     "sha256",
				Description: "ARTIFACT HASH CONTRADICTION",
			},
		},
	}

	report := localizer.Localize(res)

	if !report.HasTrustBreak {
		t.Fatalf("expected trust break report to be true")
	}

	if report.EarliestLayer != evidence.LayerFilesystem {
		t.Errorf("expected earliest layer to be FILESYSTEM, got %s", report.EarliestLayer)
	}

	if len(report.SupportingEvidence) == 0 {
		t.Errorf("expected supporting evidence items")
	}
}

func TestLocalizeNoBreak(t *testing.T) {
	localizer := NewLocalizer()

	res := &correlation.Result{
		IsConsistent: true,
		LayerStatuses: map[evidence.Layer]evidence.Status{
			evidence.LayerSource:   evidence.StatusVerified,
			evidence.LayerArtifact: evidence.StatusVerified,
		},
	}

	report := localizer.Localize(res)
	if report.HasTrustBreak {
		t.Errorf("expected no trust break for consistent build")
	}
}
