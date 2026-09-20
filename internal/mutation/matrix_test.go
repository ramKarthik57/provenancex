package mutation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMonteCarlo1000Trials(t *testing.T) {
	runner := NewTrialRunner()
	report, err := runner.RunTrials(1000)
	if err != nil {
		t.Fatalf("RunTrials failed: %v", err)
	}

	if report.TotalTrials != 1000 {
		t.Fatalf("expected 1000 trials, got %d", report.TotalTrials)
	}
	if report.AttackTrials == 0 || report.BenignTrials == 0 {
		t.Fatalf("expected both attack and benign trials")
	}

	// Ensure empirical metrics are calculated
	if report.Precision < 90.0 {
		t.Errorf("expected Precision >= 90%%, got %.2f%%", report.Precision)
	}
	if report.Recall < 95.0 {
		t.Errorf("expected Recall >= 95%%, got %.2f%%", report.Recall)
	}
	if report.LocalizationAccuracy < 90.0 {
		t.Errorf("expected Localization Accuracy >= 90%%, got %.2f%%", report.LocalizationAccuracy)
	}

	t.Logf("Empirical 1,000-Trial Research Results:")
	t.Logf("  Total Trials:          %d (Attacks: %d, Benign: %d)", report.TotalTrials, report.AttackTrials, report.BenignTrials)
	t.Logf("  TP: %d, FP: %d, TN: %d, FN: %d", report.TruePositives, report.FalsePositives, report.TrueNegatives, report.FalseNegatives)
	t.Logf("  Precision:             %.2f%%", report.Precision)
	t.Logf("  Recall (Sensitivity):  %.2f%%", report.Recall)
	t.Logf("  F1 Score:              %.2f", report.F1Score)
	t.Logf("  Localization Accuracy: %.2f%%", report.LocalizationAccuracy)
	t.Logf("  Mean In-Memory Latency:%.1f µs", report.MeanLatencyMicros)

	// Export CSV results to results/
	resultsDir := filepath.Join("..", "..", "results")
	if err := report.ExportCSVResults(resultsDir); err != nil {
		t.Fatalf("ExportCSVResults failed: %v", err)
	}

	for _, name := range []string{"raw.csv", "summary.csv", "confusion-matrix.csv"} {
		p := filepath.Join(resultsDir, name)
		if info, err := os.Stat(p); err != nil || info.Size() == 0 {
			t.Errorf("expected generated CSV file %s", p)
		}
	}
}
