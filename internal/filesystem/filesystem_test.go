package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemBoundaryDelta(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "source.go")
	file2 := filepath.Join(tmpDir, "config.json")

	os.WriteFile(file1, []byte("package main"), 0644)
	os.WriteFile(file2, []byte(`{"env":"test"}`), 0644)

	monitor := NewBoundaryMonitor()

	// Initial snapshot before build
	snapBefore, err := monitor.TakeSnapshot(tmpDir)
	if err != nil {
		t.Fatalf("TakeSnapshot before failed: %v", err)
	}
	if len(snapBefore.Files) != 2 {
		t.Fatalf("expected 2 files in initial snapshot, got %d", len(snapBefore.Files))
	}

	// Simulate build: create binary, modify config, delete source
	outputBin := filepath.Join(tmpDir, "app.exe")
	os.WriteFile(outputBin, []byte("MZ binary data"), 0755)
	os.WriteFile(file2, []byte(`{"env":"production","updated":true}`), 0644)
	os.Remove(file1)

	// Snapshot after build
	snapAfter, err := monitor.TakeSnapshot(tmpDir)
	if err != nil {
		t.Fatalf("TakeSnapshot after failed: %v", err)
	}

	delta := monitor.ComputeDelta(snapBefore, snapAfter)

	if len(delta.CreatedFiles) != 1 || delta.CreatedFiles[0].RelativePath != "app.exe" {
		t.Errorf("expected 1 created file 'app.exe', got %+v", delta.CreatedFiles)
	}
	if len(delta.ModifiedFiles) != 1 || delta.ModifiedFiles[0].RelativePath != "config.json" {
		t.Errorf("expected 1 modified file 'config.json', got %+v", delta.ModifiedFiles)
	}
	if len(delta.DeletedFiles) != 1 || delta.DeletedFiles[0] != "source.go" {
		t.Errorf("expected 1 deleted file 'source.go', got %+v", delta.DeletedFiles)
	}
}

func TestEvaluateInputsSetDifference(t *testing.T) {
	monitor := NewBoundaryMonitor()

	expected := []string{
		"src/main.go",
		"package.json",
		"package-lock.json",
		"Dockerfile",
	}

	observed := []string{
		"src/main.go",
		"package.json",
		"package-lock.json",
		// Dockerfile missing
		"/tmp/hidden-injected-config.json", // unexpected injected input
	}

	eval := monitor.EvaluateInputs(expected, observed)

	if !eval.HasDiscrepancy {
		t.Fatalf("expected discrepancy between expected and observed inputs")
	}

	if len(eval.UnexpectedInputs) != 1 || eval.UnexpectedInputs[0] != "/tmp/hidden-injected-config.json" {
		t.Errorf("unexpected inputs failed: got %+v", eval.UnexpectedInputs)
	}

	if len(eval.MissingInputs) != 1 || eval.MissingInputs[0] != "Dockerfile" {
		t.Errorf("missing inputs failed: got %+v", eval.MissingInputs)
	}
}
