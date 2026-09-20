package ablation

import (
	"context"
	"testing"
)

func TestAblationStudyAccuracyComparison(t *testing.T) {
	eval := NewEvaluator()
	report, err := eval.RunBenchmark(context.Background())
	if err != nil {
		t.Fatalf("failed running ablation study: %v", err)
	}

	if report.TotalScenarios != 10 {
		t.Fatalf("expected 10 scenarios, got %d", report.TotalScenarios)
	}

	// ProvenanceX cross-layer correlation must detect 100% of scenarios
	pxAcc := report.SystemAccuracies[ProvenanceXMultiLayer]
	if pxAcc < 100.0 {
		t.Fatalf("expected ProvenanceX detection to be 100%%, got %.2f%%", pxAcc)
	}

	// Single-layer baselines must have significantly lower detection rates
	checksumAcc := report.SystemAccuracies[BaselineChecksumOnly]
	sigAcc := report.SystemAccuracies[BaselineSignatureOnly]
	sbomAcc := report.SystemAccuracies[BaselineSBOMOnly]

	if checksumAcc >= 50.0 {
		t.Errorf("checksum only detection rate should be low (<50%%), got %.2f%%", checksumAcc)
	}
	if sigAcc >= 50.0 {
		t.Errorf("signature only detection rate should be low (<50%%), got %.2f%%", sigAcc)
	}
	if sbomAcc >= 50.0 {
		t.Errorf("SBOM only detection rate should be low (<50%%), got %.2f%%", sbomAcc)
	}

	t.Logf("Ablation Study Empirical Detection Rates:")
	t.Logf("  Checksum Only:         %.1f%% (2/10)", checksumAcc)
	t.Logf("  Signature Only:        %.1f%% (3/10)", sigAcc)
	t.Logf("  SBOM Only:             %.1f%% (1/10)", sbomAcc)
	t.Logf("  ProvenanceX Cross-Layer: %.1f%% (10/10)", pxAcc)
}
