package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashBytes(t *testing.T) {
	// SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	emptyHash := HashBytes([]byte(""))
	expectedEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if emptyHash != expectedEmpty {
		t.Errorf("expected %s, got %s", expectedEmpty, emptyHash)
	}

	// SHA-256 of "hello world"
	hwHash := HashBytes([]byte("hello world"))
	expectedHW := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hwHash != expectedHW {
		t.Errorf("expected %s, got %s", expectedHW, hwHash)
	}
}

func TestHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	content := []byte("ProvenanceX Research Artifact")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	hash, size, err := HashFile(filePath)
	if err != nil {
		t.Fatalf("unexpected error hashing file: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), size)
	}
	expectedHash := HashBytes(content)
	if hash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, hash)
	}

	// Test non-existent file
	_, _, err = HashFile(filepath.Join(tmpDir, "nonexistent.bin"))
	if err == nil {
		t.Errorf("expected error for non-existent file, got nil")
	}
}

func TestMerkleTreeDeterministic(t *testing.T) {
	leaves := []string{
		"a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
		"b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01",
		"c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef012",
	}

	tree1, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatalf("failed to create tree1: %v", err)
	}

	// Reverse order input: tree must still be deterministic due to canonical sorting
	reversedLeaves := []string{leaves[2], leaves[1], leaves[0]}
	tree2, err := NewMerkleTree(reversedLeaves)
	if err != nil {
		t.Fatalf("failed to create tree2: %v", err)
	}

	if tree1.RootHash() != tree2.RootHash() {
		t.Errorf("expected identical root hashes regardless of input ordering, got %s vs %s",
			tree1.RootHash(), tree2.RootHash())
	}
}

func TestMerkleTreeEmptyAndSingle(t *testing.T) {
	emptyTree, err := NewMerkleTree([]string{})
	if err != nil {
		t.Fatalf("unexpected error on empty tree: %v", err)
	}
	if emptyTree.RootHash() == "" {
		t.Errorf("expected non-empty root hash for empty tree")
	}

	singleTree, err := NewMerkleTree([]string{"abc"})
	if err != nil {
		t.Fatalf("unexpected error on single-node tree: %v", err)
	}
	if singleTree.RootHash() == "" {
		t.Errorf("expected non-empty root hash for single-node tree")
	}
}
