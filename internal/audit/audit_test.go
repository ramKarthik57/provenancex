package audit

import (
	"path/filepath"
	"testing"
)

func TestAuditSuite(t *testing.T) {
	tempOut := t.TempDir()
	rawDay14Path := filepath.Join("..", "..", "results", "day14", "raw_trials.csv")

	runner := NewAuditCampaignRunner(tempOut, rawDay14Path)
	runner.TempWorkDir = tempOut

	report, err := runner.Run()
	if err != nil {
		t.Fatalf("Day 15 audit campaign run failed: %v", err)
	}

	if len(report.RecomputedMetrics) == 0 {
		t.Fatalf("expected >0 recomputed metric records")
	}

	for _, m := range report.RecomputedMetrics {
		if !m.IsSumValid {
			t.Errorf("sum check failed for %s: %d != %d", m.ScenarioID, m.SumCheck, m.TotalTrials)
		}
	}

	if len(report.EndToEndResults) == 0 {
		t.Fatalf("expected >0 end to end build records")
	}

	if err := report.ExportAllDay15Datasets(tempOut); err != nil {
		t.Fatalf("failed exporting Day 15 datasets: %v", err)
	}
}
