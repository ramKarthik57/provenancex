package forensics

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestStructuralZIPComparison(t *testing.T) {
	tmpDir := t.TempDir()
	zipA := filepath.Join(tmpDir, "buildA.zip")
	zipB := filepath.Join(tmpDir, "buildB.zip")

	// Create Zip A
	fA, err := os.Create(zipA)
	if err != nil {
		t.Fatalf("failed creating zipA: %v", err)
	}
	zwA := zip.NewWriter(fA)
	wA, _ := zwA.Create("main.go")
	wA.Write([]byte("package main\nfunc main() {}\n"))
	zwA.Close()
	fA.Close()

	// Create Zip B with additional backdoored member
	fB, err := os.Create(zipB)
	if err != nil {
		t.Fatalf("failed creating zipB: %v", err)
	}
	zwB := zip.NewWriter(fB)
	wB1, _ := zwB.Create("main.go")
	wB1.Write([]byte("package main\nfunc main() {}\n"))
	wB2, _ := zwB.Create("backdoor.dll")
	wB2.Write([]byte("MZ...payload"))
	zwB.Close()
	fB.Close()

	comp := NewBinaryComparator()
	div, err := comp.Compare(zipA, zipB)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if div.DivergenceType != "STRUCTURAL_DIVERGENCE" {
		t.Fatalf("expected STRUCTURAL_DIVERGENCE, got %s", div.DivergenceType)
	}
	if len(div.SectionsAdded) != 1 || div.SectionsAdded[0] != "backdoor.dll" {
		t.Fatalf("expected backdoor.dll in SectionsAdded, got %v", div.SectionsAdded)
	}

	term := div.FormatTerminal()
	if len(term) == 0 {
		t.Fatalf("expected formatted terminal output")
	}
}
