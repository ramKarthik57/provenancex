package generalization

import (
	"testing"
)

func TestGeneralizationSuite(t *testing.T) {
	runner := NewCampaignRunner(2, 5, t.TempDir())
	report, err := runner.Run()
	if err != nil {
		t.Fatalf("campaign run failed: %v", err)
	}

	if report.TotalTrials == 0 {
		t.Fatalf("expected >0 trials, got %d", report.TotalTrials)
	}

	if report.OverallRecall < 80.0 {
		t.Errorf("expected recall >= 80%%, got %.2f%%", report.OverallRecall)
	}

	if report.OverallPrecision < 95.0 {
		t.Errorf("expected precision >= 95%%, got %.2f%%", report.OverallPrecision)
	}

	// Test dataset export
	if err := report.ExportAllDatasets(t.TempDir()); err != nil {
		t.Fatalf("export datasets failed: %v", err)
	}
}

func TestArtifactScaling(t *testing.T) {
	results := RunArtifactScalingBenchmark()
	if len(results) != 5 {
		t.Fatalf("expected 5 artifact scaling results, got %d", len(results))
	}
	for _, r := range results {
		if r.HashLatencyMicros <= 0 {
			t.Errorf("invalid hash latency for %s: %d", r.SizeLabel, r.HashLatencyMicros)
		}
	}
}

func TestDependencyScaling(t *testing.T) {
	results := RunDependencyScalingBenchmark()
	if len(results) != 5 {
		t.Fatalf("expected 5 dependency scaling results, got %d", len(results))
	}
}

func TestGraphScaling(t *testing.T) {
	results := RunGraphScalingBenchmark()
	if len(results) != 5 {
		t.Fatalf("expected 5 graph scaling results, got %d", len(results))
	}
}
