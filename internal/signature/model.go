package signature

import "time"

// Algorithm specifies the asymmetric cryptographic signature scheme
type Algorithm string

const (
	AlgoECDSAP256 Algorithm = "ECDSA_P256_SHA256"
	AlgoEd25519   Algorithm = "Ed25519"
	AlgoRSASHA256 Algorithm = "RSA_PKCS1V15_SHA256"
	AlgoUnknown   Algorithm = "UNKNOWN"
)

// Distinction constants for supply chain artifacts:
// HASH: A mathematical one-way digest of contents (proves content identity)
// SIGNATURE: An asymmetric cryptographic assertion produced with a private key (proves author identity)
// ATTESTATION: An authenticated statement declaring claims about a subject
// PROVENANCE: A specific verifiable record of software artifact origin, build recipe, and materials
const (
	ArtifactTypeHash        = "HASH"
	ArtifactTypeSignature   = "SIGNATURE"
	ArtifactTypeAttestation = "ATTESTATION"
	ArtifactTypeProvenance  = "PROVENANCE"
)

// VerificationResult summarizes the cryptographic validation of an artifact or attestation
type VerificationResult struct {
	Valid       bool      `json:"valid"`
	Algorithm   Algorithm `json:"algorithm"`
	KeyID       string    `json:"keyId,omitempty"`
	SignedAt    time.Time `json:"signedAt,omitempty"`
	Error       string    `json:"error,omitempty"`
	Distinction string    `json:"distinction"` // Always "SIGNATURE"
}
