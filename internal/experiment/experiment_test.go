package experiment

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunAllScenarios(t *testing.T) {
	runner := NewRunner(nil)
	ctx := context.Background()

	scenarios := DefaultScenarios()
	if len(scenarios) != 10 {
		t.Fatalf("expected 10 default scenarios, got %d", len(scenarios))
	}

	report, err := runner.RunAll(ctx, scenarios)
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	if report.TotalScenarios != 10 {
		t.Errorf("expected 10 total scenarios, got %d", report.TotalScenarios)
	}

	if report.DetectionRatePercent < 100.0 {
		t.Errorf("expected 100%% detection rate, got %.1f%% (%d/%d detected)",
			report.DetectionRatePercent, report.DetectedAttacks, report.TotalScenarios)
	}

	for _, res := range report.Results {
		if !res.Detected {
			t.Errorf("scenario %s (%s) was NOT detected", res.ScenarioID, res.ScenarioName)
		}
		if !res.LocalizationMatched {
			t.Errorf("scenario %s (%s) localization mismatch: expected %s, got %s",
				res.ScenarioID, res.ScenarioName, res.ExpectedBreakLayer, res.LocalizedLayer)
		}
	}

	term := FormatTerminal(report)
	if len(term) == 0 {
		t.Errorf("FormatTerminal produced empty output")
	}

	md := FormatMarkdown(report)
	if len(md) == 0 {
		t.Errorf("FormatMarkdown produced empty output")
	}

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "benchmark.json")
	if err := SaveJSON(report, jsonPath); err != nil {
		t.Fatalf("SaveJSON failed: %v", err)
	}

	if info, err := os.Stat(jsonPath); err != nil || info.Size() == 0 {
		t.Errorf("benchmark JSON not saved or empty")
	}
}
