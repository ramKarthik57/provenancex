package experiments_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ramKarthik57/provenancex/internal/experiment"
)

func TestEmpiricalSupplyChainAttackBenchmark(t *testing.T) {
	runner := experiment.NewRunner(nil)
	ctx := context.Background()

	scenarios := experiment.DefaultScenarios()
	report, err := runner.RunAll(ctx, scenarios)
	if err != nil {
		t.Fatalf("Benchmark run failed: %v", err)
	}

	t.Logf("Total scenarios: %d", report.TotalScenarios)
	t.Logf("Detection rate: %.1f%% (%d/%d)", report.DetectionRatePercent, report.DetectedAttacks, report.TotalScenarios)
	t.Logf("Localization accuracy: %.1f%%", report.LocalizationAccPercent)
	t.Logf("Average latency: %.2f ms", report.AverageLatencyMs)

	if report.DetectionRatePercent < 100.0 {
		t.Errorf("Expected 100%% detection rate, got %.1f%%", report.DetectionRatePercent)
	}
	if report.LocalizationAccPercent < 100.0 {
		t.Errorf("Expected 100%% localization accuracy, got %.1f%%", report.LocalizationAccPercent)
	}

	// Persist benchmark results to experiments/ directory for research paper citation
	resultsJSONPath := filepath.Join(".", "benchmark_results.json")
	if err := experiment.SaveJSON(report, resultsJSONPath); err != nil {
		t.Fatalf("Failed to save benchmark_results.json: %v", err)
	}

	reportMDPath := filepath.Join(".", "BENCHMARK_REPORT.md")
	mdContent := experiment.FormatMarkdown(report)
	if err := os.WriteFile(reportMDPath, []byte(mdContent), 0644); err != nil {
		t.Fatalf("Failed to save BENCHMARK_REPORT.md: %v", err)
	}
}
