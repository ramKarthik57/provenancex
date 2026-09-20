package mutation

import (
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// MutationType defines adversarial manipulations applied to supply chain evidence
type MutationType string

const (
	TypeCorruptDigest       MutationType = "CORRUPT_DIGEST"
	TypeTamperSignature    MutationType = "TAMPER_SIGNATURE"
	TypeSkewTimestamp       MutationType = "SKEW_TIMESTAMP"
	TypeOmitEvidence        MutationType = "OMIT_EVIDENCE"
	TypeReplayStaleEvidence MutationType = "REPLAY_STALE_EVIDENCE"
	TypeInjectContradiction MutationType = "INJECT_CONTRADICTION"
)

// MutationResult records the outcome of an adversarial evidence mutation test
type MutationResult struct {
	MutationType       MutationType `json:"mutationType"`
	TargetLayer        evidence.Layer `json:"targetLayer"`
	Description        string       `json:"description"`
	TamperingDetected  bool         `json:"tamperingDetected"`
	DetectionMechanism string       `json:"detectionMechanism"`
	DetectionLatencyMs int64        `json:"detectionLatencyMs"`
}

// Mutator applies targeted adversarial mutations to test verifier robustness
type Mutator struct{}

// NewMutator creates an evidence mutator
func NewMutator() *Mutator {
	return &Mutator{}
}

// CorruptDigest simulates an attacker modifying an artifact digest in an attestation
func (m *Mutator) CorruptDigest(originalDigest string) string {
	if len(originalDigest) < 8 {
		return "00000000deadbeef"
	}
	// Flip bits in the leading hex characters
	return "deadbeef" + originalDigest[8:]
}

// SkewTimestamp shifts a timestamp outside the valid build window (Milestone 17: Time-order attacks)
func (m *Mutator) SkewTimestamp(original time.Time, offset time.Duration) time.Time {
	return original.Add(offset)
}

// MutateLogEntry generates a tampered RFC 6962 tree entry (Milestone 13: Log tampering)
func (m *Mutator) MutateLogEntry(item *evidence.Item) *evidence.Item {
	tampered := *item
	tampered.Hash = fmt.Sprintf("tampered-%s", item.Hash)
	tampered.Status = evidence.StatusMismatch
	return &tampered
}
