package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Layer represents one of the 12 software supply-chain evidence planes
type Layer string

const (
	LayerSource       Layer = "SOURCE"
	LayerDependencies Layer = "DEPENDENCIES"
	LayerLockfile     Layer = "LOCKFILE"
	LayerSBOM         Layer = "SBOM"
	LayerEnvironment  Layer = "ENVIRONMENT"
	LayerBuild        Layer = "BUILD"
	LayerProcess      Layer = "PROCESS"
	LayerFilesystem   Layer = "FILESYSTEM"
	LayerNetwork      Layer = "NETWORK"
	LayerArtifact     Layer = "ARTIFACT"
	LayerProvenance   Layer = "PROVENANCE"
	LayerSignature    Layer = "SIGNATURE"
)

// Category classifies the origin and verification nature of evidence
type Category string

const (
	CategoryDirect       Category = "DIRECT"       // Directly observed during build execution (e.g. process, filesystem, socket)
	CategoryDerived      Category = "DERIVED"      // Mathematically calculated (e.g. SHA-256 hash, Merkle root)
	CategoryExternal     Category = "EXTERNAL"     // Imported from third parties (e.g. GitHub attestation, SBOM, vendor signature)
	CategoryUnverified   Category = "UNVERIFIED"   // Declared metadata without corroborating proof
	CategoryContradicted Category = "CONTRADICTED" // Proved false or conflicting with ground truth
)

// Status represents the cross-layer verification state of a claim
type Status string

const (
	StatusVerified     Status = "VERIFIED"     // Cryptographically or observationally proven consistent
	StatusMatch        Status = "MATCH"        // Agrees with expectations
	StatusMismatch     Status = "MISMATCH"     // Minor deviation or warning
	StatusUnobserved   Status = "UNOBSERVED"   // Not captured or omitted
	StatusUnverified   Status = "UNVERIFIED"   // Present but uncorroborated
	StatusContradicted Status = "CONTRADICTED" // Fatal contradiction detected
)

// Item represents a normalized piece of supply chain evidence
type Item struct {
	ID        string    `json:"id"`
	Layer     Layer     `json:"layer"`
	Category  Category  `json:"category"`
	Status    Status    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Subject   string    `json:"subject"`
	Claim     string    `json:"claim"`
	Observed  string    `json:"observed"`
	Details   string    `json:"details,omitempty"`
	Source    string    `json:"source"`
	Hash      string    `json:"hash"`
	PrevHash  string    `json:"prevHash,omitempty"` // For append-only tamper-evident log
}

// ComputeHash computes a SHA-256 integrity hash for an evidence item linked to previous item
func ComputeItemHash(prevHash string, layer Layer, cat Category, stat Status, subject, claim, observed string) string {
	h := sha256.New()
	fmt.Fprintf(h, "prev:%s|layer:%s|cat:%s|stat:%s|subj:%s|claim:%s|obs:%s",
		prevHash, layer, cat, stat, subject, claim, observed)
	return hex.EncodeToString(h.Sum(nil))
}

// Log represents an append-only, tamper-evident chain of evidence items
type Log struct {
	Items    []*Item `json:"items"`
	LastHash string  `json:"lastHash"`
}

// NewLog constructs an empty evidence log
func NewLog() *Log {
	return &Log{
		Items:    []*Item{},
		LastHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

// Append adds a new evidence item to the append-only chain
func (l *Log) Append(layer Layer, cat Category, stat Status, subject, claim, observed, details, source string) *Item {
	now := time.Now().UTC()
	hash := ComputeItemHash(l.LastHash, layer, cat, stat, subject, claim, observed)
	id := fmt.Sprintf("ev-%d-%s", len(l.Items)+1, string(layer)[:3])

	item := &Item{
		ID:        id,
		Layer:     layer,
		Category:  cat,
		Status:    stat,
		Timestamp: now,
		Subject:   subject,
		Claim:     claim,
		Observed:  observed,
		Details:   details,
		Source:    source,
		Hash:      hash,
		PrevHash:  l.LastHash,
	}

	l.Items = append(l.Items, item)
	l.LastHash = hash
	return item
}

// VerifyIntegrity verifies that the evidence chain has not been tampered with
func (l *Log) VerifyIntegrity() bool {
	prev := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, item := range l.Items {
		if item.PrevHash != prev {
			return false
		}
		expectedHash := ComputeItemHash(prev, item.Layer, item.Category, item.Status, item.Subject, item.Claim, item.Observed)
		if item.Hash != expectedHash {
			return false
		}
		prev = item.Hash
	}
	return true
}
