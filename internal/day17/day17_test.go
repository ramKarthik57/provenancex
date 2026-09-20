package day17

import (
	"path/filepath"
	"testing"
)

func TestDay17AuditExecution(t *testing.T) {
	tmpDir := t.TempDir()

	runner := NewDay17AuditRunner(tmpDir)
	runner.RootDir = filepath.Join("..", "..")

	report, err := runner.Run()
	if err != nil {
		t.Fatalf("Day 17 audit Run failed: %v", err)
	}

	if len(report.ClaimInventory) != 10 {
		t.Errorf("expected 10 claims in inventory, got %d", len(report.ClaimInventory))
	}

	for _, c := range report.ClaimInventory {
		switch c.AuditedClassification {
		case "VALIDATED", "PARTIALLY_VALIDATED", "BOUNDED", "UNSUPPORTED", "CONTRADICTED":
			// valid classification
		default:
			t.Errorf("invalid claim classification for %s: %s", c.ClaimID, c.AuditedClassification)
		}
	}

	if len(report.Scorecard) != 10 {
		t.Errorf("expected 10 scorecard categories, got %d", len(report.Scorecard))
	}

	for _, s := range report.Scorecard {
		switch s.AuditResult {
		case "PASS", "PASS_WITH_LIMITATION", "REQUIRES_REVISION", "FAIL":
			// valid result
		default:
			t.Errorf("invalid scorecard result for %s: %s", s.Category, s.AuditResult)
		}
	}

	if err := report.ExportAll(tmpDir); err != nil {
		t.Fatalf("ExportAll failed: %v", err)
	}

	// Verify all expected files are present in tmpDir
	expectedFiles := []string{
		"confusion_matrix_audit.csv",
		"claim_inventory.csv",
		"benchmark_scope_audit.csv",
		"observability_audit.csv",
		"offline_verifier_audit.csv",
		"final_scorecard.csv",
		"reproducibility_environment.json",
		"data_leakage_audit.md",
		"reproduction_report.md",
		"dataset_hashes.txt",
	}

	for _, ef := range expectedFiles {
		fp := filepath.Join(tmpDir, ef)
		if !fileExists(fp) {
			t.Errorf("expected exported file %s was not created", ef)
		}
	}
}
