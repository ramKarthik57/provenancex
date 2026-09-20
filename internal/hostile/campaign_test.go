package hostile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdversarialCampaignExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "provx-hostile-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Run 5 independent runs with 5 cases per family for fast unit testing
	campaign := NewAdversarialCampaign(5, 5, tempDir)
	report, err := campaign.Run()
	if err != nil {
		t.Fatalf("campaign run failed: %v", err)
	}

	if report.TotalTrials != 5*5*len(AllFamilies()) {
		t.Errorf("expected %d total trials, got %d", 5*5*len(AllFamilies()), report.TotalTrials)
	}

	if len(report.RunSummaries) != 5 {
		t.Errorf("expected 5 run summaries, got %d", len(report.RunSummaries))
	}

	// Verify that the 4 specific blind spot families had False Negatives
	expectedBlindSpots := []FamilyID{
		FamProcessShortLived,
		FamFilesystemBoundaryEscape,
		FamNetworkEphemeralDNS,
		FamSourceMetadataSpoof,
	}

	for _, fam := range expectedBlindSpots {
		metrics, ok := report.FamilyStats[fam]
		if !ok {
			t.Errorf("missing family stats for %s", fam)
			continue
		}
		if !metrics.IsBlindSpot {
			t.Errorf("expected %s to be flagged as an empirical blind spot", fam)
		}
		if metrics.FN == 0 {
			t.Errorf("expected FN > 0 for blind spot %s, got FN=%d", fam, metrics.FN)
		}
	}

	// Verify that benign families produced zero false alarms
	benignFamilies := []FamilyID{
		FamBenignCompilerPatch,
		FamBenignPathRelocation,
		FamBenignLockfileSync,
		FamBenignMetadataReorder,
		FamBenignCacheHit,
	}

	for _, fam := range benignFamilies {
		metrics, ok := report.FamilyStats[fam]
		if !ok {
			t.Errorf("missing family stats for %s", fam)
			continue
		}
		if metrics.FP > 0 {
			t.Errorf("expected 0 false alarms for benign family %s, got FP=%d", fam, metrics.FP)
		}
	}

	// Export CSVs and verify files exist and are non-empty
	if err := report.ExportCSVs(tempDir); err != nil {
		t.Fatalf("export CSVs failed: %v", err)
	}

	rawFile := filepath.Join(tempDir, "adversarial_campaign_raw.csv")
	famFile := filepath.Join(tempDir, "adversarial_per_family.csv")

	if fi, err := os.Stat(rawFile); err != nil || fi.Size() == 0 {
		t.Errorf("raw CSV file missing or empty: %v", err)
	}
	if fi, err := os.Stat(famFile); err != nil || fi.Size() == 0 {
		t.Errorf("per-family CSV file missing or empty: %v", err)
	}

	// Format terminal and verify string contains header
	output := report.FormatTerminal()
	if len(output) == 0 {
		t.Errorf("empty terminal output")
	}
	t.Logf("\n%s", output)
}
