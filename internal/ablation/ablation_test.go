package ablation

import (
	"context"
	"testing"

	"github.com/ramKarthik57/provenancex/internal/experiment"
)

func TestBaselinesAThroughF(t *testing.T) {
	eval := NewEvaluator()
	scenarios := experiment.DefaultScenarios()
	ctx := context.Background()

	baselines := []BaselineSystem{
		BaselineA_Checksum,
		BaselineB_Signature,
		BaselineC_SBOM,
		BaselineD_Attestation,
		BaselineE_NoCorrelation,
		BaselineF_ProvenanceX,
	}

	scores := make(map[BaselineSystem]int)

	for _, sc := range scenarios {
		in, err := sc.Simulate(ctx)
		if err != nil {
			t.Fatalf("scenario simulate error: %v", err)
		}

		for _, b := range baselines {
			out := eval.EvaluateBaseline(b, sc, in)
			if out.Detected {
				scores[b]++
			}
		}
	}

	t.Logf("Baselines A-F Empirical Detection Rates:")
	for _, b := range baselines {
		pct := float64(scores[b]) / float64(len(scenarios)) * 100.0
		t.Logf("  %-30s : %5.1f%% (%d/%d)", b, pct, scores[b], len(scenarios))
	}

	// Full ProvenanceX must outperform all isolated baselines
	if scores[BaselineF_ProvenanceX] <= scores[BaselineA_Checksum] {
		t.Errorf("expected ProvenanceX to outperform Baseline A")
	}
	if scores[BaselineF_ProvenanceX] <= scores[BaselineE_NoCorrelation] {
		t.Errorf("expected ProvenanceX to outperform Baseline E (No Correlation)")
	}
}

func TestLayerAblationStudy(t *testing.T) {
	eval := NewEvaluator()
	results, err := eval.RunLayerAblation(context.Background())
	if err != nil {
		t.Fatalf("RunLayerAblation failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected ablation results")
	}

	t.Logf("Layer Ablation 2.0 (Impact of omitting single planes):")
	for _, r := range results {
		t.Logf("  Omitted: %-15s | Detection: %5.1f%% | FAR: %5.1f%% | Loc Accuracy: %5.1f%%",
			r.OmittedLayer, r.DetectionRatePercent, r.FalseAcceptanceRate, r.LocalizationAccuracy)
	}
}

func TestBenignVariabilityEvaluation(t *testing.T) {
	eval := NewEvaluator()
	results := eval.EvaluateBenignVariability()

	if len(results) != 4 {
		t.Fatalf("expected 4 benign variability evaluations, got %d", len(results))
	}

	for _, r := range results {
		if !r.CorrectlyPassed {
			t.Errorf("variability %s failed expected decision: %s", r.VariabilityType, r.Verdict)
		}
		t.Logf("Benign Variability [%s]: %s (%s)", r.VariabilityType, r.Verdict, r.Description)
	}
}
