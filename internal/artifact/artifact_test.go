package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectArtifact(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "app.exe")
	content := []byte("MZ\x90\x00\x03\x00\x00\x00Dummy Windows PE Header")
	if err := os.WriteFile(filePath, content, 0755); err != nil {
		t.Fatalf("failed to write test artifact: %v", err)
	}

	meta, err := Inspect(filePath, tmpDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if meta.Name != "app.exe" {
		t.Errorf("expected name 'app.exe', got '%s'", meta.Name)
	}
	if meta.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), meta.Size)
	}
	if meta.MIMEType != "application/x-msdownload" {
		t.Errorf("expected MIME 'application/x-msdownload', got '%s'", meta.MIMEType)
	}
	if meta.SHA256 == "" {
		t.Errorf("expected non-empty SHA-256")
	}
}

func TestArtifactCollectionAndMerkle(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "lib.dll")
	file2 := filepath.Join(tmpDir, "run.json")

	os.WriteFile(file1, []byte("DLL data"), 0644)
	os.WriteFile(file2, []byte(`{"status": "ok"}`), 0644)

	coll, err := ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if coll.Count != 2 {
		t.Errorf("expected 2 artifacts, got %d", coll.Count)
	}
	if coll.MerkleRoot == "" {
		t.Errorf("expected non-empty Merkle root")
	}
	if coll.TotalSize <= 0 {
		t.Errorf("expected positive total size")
	}
}
