package day16

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
)

func TestProcessVisibility(t *testing.T) {
	records, cov := EvaluateProcessVisibility()
	if len(records) == 0 {
		t.Fatal("expected process visibility records")
	}

	adminKey := "Administrator_Mode B: Kernel ETW"
	if cov[adminKey] != 100.0 {
		t.Fatalf("expected admin ETW coverage to be 100%%, got %.2f%%", cov[adminKey])
	}

	pollKey := "Non-Administrator_Mode A: 100ms Polling"
	if cov[pollKey] >= 50.0 {
		t.Fatalf("expected polling coverage to be bounded low, got %.2f%%", cov[pollKey])
	}
}

func TestFilesystemVisibility(t *testing.T) {
	records, cov := EvaluateFilesystemVisibility()
	if len(records) == 0 {
		t.Fatal("expected filesystem records")
	}

	if cov["Mode A: Snapshot/Delta"] != 0.0 {
		t.Fatalf("expected snapshot/delta to have 0%% recall on transient deleted files, got %.2f%%", cov["Mode A: Snapshot/Delta"])
	}

	if cov["Mode B: User-Mode Change Events (ReadDirectoryChangesW)"] < 70.0 {
		t.Fatalf("expected mode B event coverage >= 70%%, got %.2f%%", cov["Mode B: User-Mode Change Events (ReadDirectoryChangesW)"])
	}
}

func TestDNSTunneling(t *testing.T) {
	correlator := correlation.NewCorrelator()
	engine := decision.NewEngine()

	records := EvaluateDNSTunneling(correlator, engine)
	if len(records) == 0 {
		t.Fatal("expected DNS tunneling records")
	}

	for _, r := range records {
		if !r.IsCorrect {
			t.Errorf("DNS record %s expected %s, got %s (%s)", r.QueryDomain, r.ExpectedVerdict, r.ObservedVerdict, r.Reason)
		}
	}
}

func TestGeneratedFilePolicy(t *testing.T) {
	correlator := correlation.NewCorrelator()
	engine := decision.NewEngine()

	records := EvaluateGeneratedFilePolicy(correlator, engine)
	if len(records) != 6 {
		t.Fatalf("expected 6 policy records, got %d", len(records))
	}

	for _, r := range records {
		if r.IsFalsePositive {
			t.Errorf("false positive in scenario %s: %s", r.ScenarioID, r.Explanation)
		}
		if r.IsFalseNegative {
			t.Errorf("false negative in scenario %s: %s", r.ScenarioID, r.Explanation)
		}
	}
}

func TestBenignCampaign(t *testing.T) {
	correlator := correlation.NewCorrelator()
	engine := decision.NewEngine()

	records, tot, fp, fpRate := RunBenignCampaign(correlator, engine)
	if tot != 1000 {
		t.Fatalf("expected exactly 1,000 benign trials, got %d", tot)
	}
	if fp != 0 {
		t.Fatalf("expected 0 false positives in benign campaign, got %d (rate: %.2f%%)", fp, fpRate)
	}
	if len(records) != 1000 {
		t.Fatalf("expected 1,000 records, got %d", len(records))
	}
}

func TestDay16CampaignRunnerAndExport(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "day16_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	runner := NewDay16CampaignRunner(tmpDir)
	rep, err := runner.Run()
	if err != nil {
		t.Fatalf("campaign run failed: %v", err)
	}

	if err := rep.ExportAllDay16Datasets(tmpDir); err != nil {
		t.Fatalf("dataset export failed: %v", err)
	}

	expectedFiles := []string{
		"process_visibility.csv",
		"filesystem_visibility.csv",
		"dns_tunneling.csv",
		"generated_file_policy.csv",
		"adversarial_reattack.csv",
		"benign_campaign.csv",
		"performance.csv",
		"blind_spot_matrix.csv",
		"before_after.csv",
		"ablation.csv",
		"raw_trials.csv",
		"environment.json",
		"experiment_manifest.json",
		"dataset_hashes.txt",
	}

	for _, ef := range expectedFiles {
		p := filepath.Join(tmpDir, ef)
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("expected non-empty output file %s", ef)
		}
	}
}
