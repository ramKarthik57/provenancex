package mutation

import (
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/evidence"
)

func TestMutatorCorruptDigest(t *testing.T) {
	m := NewMutator()
	orig := "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"
	corrupted := m.CorruptDigest(orig)

	if orig == corrupted {
		t.Fatalf("CorruptDigest failed to modify the hash digest")
	}
	if corrupted[:8] != "deadbeef" {
		t.Fatalf("Expected leading deadbeef, got %s", corrupted[:8])
	}
}

func TestMutatorSkewTimestamp(t *testing.T) {
	m := NewMutator()
	orig := time.Now()
	skewed := m.SkewTimestamp(orig, 24*time.Hour)

	if !skewed.After(orig) {
		t.Fatalf("Expected skewed timestamp to be after original")
	}
}

func TestMutatorLogEntryTamperDetection(t *testing.T) {
	m := NewMutator()
	log := evidence.NewLog()
	item := log.Append(
		evidence.LayerSource,
		evidence.CategoryDirect,
		evidence.StatusVerified,
		"git.commit",
		"main",
		"9af08e100f749553f1d248fe4ebf32b12bf087e5",
		"clean repository working tree",
		"internal/repository",
	)

	tampered := m.MutateLogEntry(item)
	if tampered.Hash == item.Hash {
		t.Fatalf("expected tampered item to have different hash")
	}
	if tampered.Status != evidence.StatusMismatch {
		t.Fatalf("expected status mismatch, got %s", tampered.Status)
	}
}
