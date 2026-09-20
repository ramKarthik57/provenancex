package blind

import (
	"testing"
)

func TestBlindValidationSeparation(t *testing.T) {
	harness := NewHarness()
	report, err := harness.RunBlindBenchmark(1000)
	if err != nil {
		t.Fatalf("RunBlindBenchmark failed: %v", err)
	}

	if report.TotalTrials != 1000 {
		t.Fatalf("expected 1000 trials, got %d", report.TotalTrials)
	}

	// Verify Dev partition (70% = 700)
	if report.DevMetrics.Total != 700 {
		t.Errorf("expected 700 dev trials, got %d", report.DevMetrics.Total)
	}
	// Verify Val partition (15% = 150)
	if report.ValMetrics.Total != 150 {
		t.Errorf("expected 150 val trials, got %d", report.ValMetrics.Total)
	}
	// Verify Holdout partition (15% = 150)
	if report.HoldoutMetrics.Total != 150 {
		t.Errorf("expected 150 holdout trials, got %d", report.HoldoutMetrics.Total)
	}

	// Assert Holdout Generalization
	if report.HoldoutMetrics.Recall < 90.0 {
		t.Errorf("expected holdout recall >= 90%%, got %.2f%%", report.HoldoutMetrics.Recall)
	}
	if report.HoldoutMetrics.Precision < 90.0 {
		t.Errorf("expected holdout precision >= 90%%, got %.2f%%", report.HoldoutMetrics.Precision)
	}

	t.Log("\n" + report.FormatTerminal())
}
