package reproducibility

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReproducibleBitwiseMatch(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "artifact1.bin")
	file2 := filepath.Join(tmpDir, "artifact2.bin")

	content := []byte("identical compiled binary content with deterministic output")
	if err := os.WriteFile(file1, content, 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2, content, 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	report, err := CompareArtifacts(file1, file2)
	if err != nil {
		t.Fatalf("CompareArtifacts failed: %v", err)
	}

	if report.Status != StatusReproducible {
		t.Errorf("expected status REPRODUCIBLE, got %s", report.Status)
	}
	if !report.BitwiseMatch {
		t.Errorf("expected BitwiseMatch to be true")
	}
	if len(report.DivergenceCauses) != 0 {
		t.Errorf("expected 0 divergence causes, got %d", len(report.DivergenceCauses))
	}
}

func TestZipArchiveTimestampDivergence(t *testing.T) {
	tmpDir := t.TempDir()
	zip1Path := filepath.Join(tmpDir, "build1.zip")
	zip2Path := filepath.Join(tmpDir, "build2.zip")

	// Create zip 1 with time1
	t1 := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	createZip(t, zip1Path, "app.js", []byte("console.log('hello');"), t1)

	// Create zip 2 with time2
	t2 := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)
	createZip(t, zip2Path, "app.js", []byte("console.log('hello');"), t2)

	report, err := CompareArtifacts(zip1Path, zip2Path)
	if err != nil {
		t.Fatalf("CompareArtifacts failed: %v", err)
	}

	if report.Status != StatusDivergent {
		t.Errorf("expected status DIVERGENT, got %s", report.Status)
	}
	if report.BitwiseMatch {
		t.Errorf("expected BitwiseMatch to be false")
	}

	foundTimestampCause := false
	for _, cause := range report.DivergenceCauses {
		if cause.Category == CategoryTimestamp {
			foundTimestampCause = true
			break
		}
	}
	if !foundTimestampCause {
		t.Errorf("expected CategoryTimestamp divergence cause, got %v", report.DivergenceCauses)
	}
}

func TestPathLeakageDivergence(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "bin1")
	file2 := filepath.Join(tmpDir, "bin2")

	// Binary containing host build path
	content1 := []byte("binary prefix /home/runner/workspace/build-123/main.go binary suffix")
	content2 := []byte("binary prefix /home/ubuntu/workspace/build-456/main.go binary suffix")

	if err := os.WriteFile(file1, content1, 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2, content2, 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	report, err := CompareArtifacts(file1, file2)
	if err != nil {
		t.Fatalf("CompareArtifacts failed: %v", err)
	}

	if report.Status != StatusDivergent {
		t.Errorf("expected status DIVERGENT, got %s", report.Status)
	}

	foundPathCause := false
	for _, cause := range report.DivergenceCauses {
		if cause.Category == CategoryPathLeakage {
			foundPathCause = true
			break
		}
	}
	if !foundPathCause {
		t.Errorf("expected CategoryPathLeakage, got %v", report.DivergenceCauses)
	}
}

func TestControlledRebuilder(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("failed to create src dir: %v", err)
	}

	scriptContent := "hello reproducible build"
	if err := os.WriteFile(filepath.Join(sourceDir, "input.txt"), []byte(scriptContent), 0644); err != nil {
		t.Fatalf("failed to write input.txt: %v", err)
	}

	// Cross-platform copy command
	var buildCmd string
	if os.PathSeparator == '\\' {
		buildCmd = "cmd.exe /c copy input.txt output.txt"
	} else {
		buildCmd = "cp input.txt output.txt"
	}

	opts := RebuildOptions{
		BuildCmd:    buildCmd,
		BuildDir:    sourceDir,
		ArtifactRel: "output.txt",
	}

	report, err := ControlledRebuilder(opts)
	if err != nil {
		t.Fatalf("ControlledRebuilder failed: %v", err)
	}

	if report.Status != StatusReproducible {
		t.Errorf("expected StatusReproducible, got %s", report.Status)
	}
	if !report.BitwiseMatch {
		t.Errorf("expected BitwiseMatch == true")
	}
}

func createZip(t *testing.T, targetPath, entryName string, data []byte, modTime time.Time) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	hdr := &zip.FileHeader{
		Name:     entryName,
		Method:   zip.Deflate,
		Modified: modTime,
	}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("failed to create zip header: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("failed to write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	if err := os.WriteFile(targetPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}
}
