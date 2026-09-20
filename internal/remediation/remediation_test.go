package remediation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
)

func TestDiagnosePreVerdict(t *testing.T) {
	correlator := correlation.NewCorrelator()
	engine := decision.NewEngine()

	// 1. Git
	gitScenarios := GenerateGitScenarios(1)
	for _, sc := range gitScenarios {
		trial := EvaluateGitScenario(sc, ModePreRemediation, correlator, engine)
		t.Logf("GIT PRE [%s]: Verdict=%s, Detection=%s, isAttack=%t", sc.SubCase, trial.PredictedVerdict, trial.Detection, sc.IsAttack)
	}

	// 2. FS
	fsCases := GetFilesystemTestCases()
	for _, fc := range fsCases {
		trial, _ := EvaluateFilesystemScenario(fc, ModePreRemediation, correlator, engine)
		t.Logf("FS PRE [%s]: Verdict=%s, Detection=%s, isAttack=%t", fc.LocationClass, trial.PredictedVerdict, trial.Detection, fc.LocationClass != "1. Workspace Root")
	}

	// 3. Net
	netCases := GetNetworkTrafficCases()
	for _, nc := range netCases {
		trial, _ := EvaluateNetworkScenario(nc, ModePreRemediation, correlator, engine)
		t.Logf("NET PRE [%s]: Verdict=%s, Detection=%s, isAttack=%t", nc.TrafficType, trial.PredictedVerdict, trial.Detection, nc.IsAttack)
	}
}

func TestRemediationCampaign(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "provx-remediation-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	runner := NewCampaignRunner(5, 10, tempDir)
	report, err := runner.Run()
	if err != nil {
		t.Fatalf("remediation run failed: %v", err)
	}

	if len(report.FamilyComparisons) != 4 {
		t.Errorf("expected 4 family comparisons, got %d", len(report.FamilyComparisons))
	}

	// Verify each blind spot had pre recall = 0.00%
	for _, fc := range report.FamilyComparisons {
		if fc.PreRecall != 0.0 {
			t.Errorf("expected pre-remediation recall 0.00%% for %s, got %.2f%%", fc.Family, fc.PreRecall)
		}
		if fc.PostRecall <= fc.PreRecall {
			t.Errorf("expected post-remediation recall > pre-remediation for %s, got %.2f%%", fc.Family, fc.PostRecall)
		}
	}

	// Verify Lifetime records (7 ranges)
	if len(report.LifetimeRecords) != 7 {
		t.Errorf("expected 7 lifetime records, got %d", len(report.LifetimeRecords))
	}

	// Verify Filesystem records (5 classes)
	if len(report.FilesystemRecords) != 5 {
		t.Errorf("expected 5 filesystem records, got %d", len(report.FilesystemRecords))
	}

	// Verify Network records (4 classes)
	if len(report.NetworkRecords) != 4 {
		t.Errorf("expected 4 network records, got %d", len(report.NetworkRecords))
	}

	// Verify Ablations (6 configurations)
	if len(report.Ablations) != 6 {
		t.Errorf("expected 6 ablation records, got %d", len(report.Ablations))
	}

	// Export datasets
	if err := report.ExportDatasets(tempDir); err != nil {
		t.Fatalf("export datasets failed: %v", err)
	}

	expectedFiles := []string{
		"raw_trials.csv",
		"per_family.csv",
		"confusion_matrix.csv",
		"latency.csv",
		"observation_coverage.csv",
		"ablation.csv",
		"environment.json",
		"experiment_manifest.json",
	}

	for _, ef := range expectedFiles {
		p := filepath.Join(tempDir, ef)
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("expected non-empty output file %s: %v", ef, err)
		}
	}

	// Verify Terminal Output
	termOut := report.FormatTerminal()
	if len(termOut) == 0 {
		t.Errorf("expected non-empty terminal report")
	}
	t.Logf("\n%s", termOut)
}
