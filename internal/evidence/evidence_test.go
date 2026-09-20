package evidence

import (
	"testing"
)

func TestAppendOnlyEvidenceChainIntegrity(t *testing.T) {
	log := NewLog()

	item1 := log.Append(
		LayerSource,
		CategoryDirect,
		StatusVerified,
		"git.commit",
		"main",
		"9af08e100f749553f1d248fe4ebf32b12bf087e5",
		"clean repository working tree",
		"internal/repository",
	)
	if item1.Hash == "" {
		t.Errorf("expected non-empty hash for item1")
	}

	item2 := log.Append(
		LayerArtifact,
		CategoryDerived,
		StatusVerified,
		"app.exe",
		"sha256:abcd",
		"sha256:abcd",
		"artifact SHA matches Merkle leaf",
		"internal/artifact",
	)

	item3 := log.Append(
		LayerNetwork,
		CategoryDirect,
		StatusContradicted,
		"registry.npmjs.org",
		"allowed-registries",
		"unauthorized-c2.xyz",
		"unauthorized network connection during build",
		"internal/network",
	)

	if len(log.Items) != 3 {
		t.Fatalf("expected 3 items in log, got %d", len(log.Items))
	}

	// Verify chain integrity
	if !log.VerifyIntegrity() {
		t.Fatalf("expected untouched log to pass integrity verification")
	}

	// Tamper with item2 claim -> must fail integrity check
	item2.Claim = "tampered-claim"
	if log.VerifyIntegrity() {
		t.Errorf("expected tampered log to fail integrity verification")
	}

	// Reset and tamper with prevHash
	item2.Claim = "sha256:abcd"
	item3.PrevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if log.VerifyIntegrity() {
		t.Errorf("expected altered prevHash to fail integrity verification")
	}
}
