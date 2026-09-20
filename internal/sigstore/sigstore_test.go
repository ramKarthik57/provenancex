package sigstore

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestSigstoreBundleVerificationValid(t *testing.T) {
	artifactContent := []byte("binary payload content")
	hasher := sha256.New()
	hasher.Write(artifactContent)
	digest := hex.EncodeToString(hasher.Sum(nil))

	att := &ExternalAttestation{
		Scope:              ScopeExternal,
		Source:             "Sigstore/Fulcio",
		Issuer:             "https://token.actions.githubusercontent.com",
		Identity:           "https://github.com/ramKarthik57/provenancex/.github/workflows/build.yml@refs/heads/main",
		ArtifactDigest:     digest,
		LogIndex:           1234567,
		LogID:              "c0ffee-uuid-rekor",
		Timestamp:          time.Now(),
		VerificationStatus: "PASSED",
	}

	verifier := NewVerifier("https://token.actions.githubusercontent.com", "")
	res, err := verifier.VerifyBundle(artifactContent, att, true)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}

	if !res.SignatureVerified || !res.CertificateVerified || !res.ArtifactDigestMatched || !res.TransparencyLogVerified {
		t.Fatalf("expected all checks to pass")
	}

	term := res.FormatTerminal()
	if len(term) == 0 {
		t.Fatalf("expected non-empty formatted terminal output")
	}
}

func TestSigstoreDigestMismatch(t *testing.T) {
	artifactContent := []byte("binary payload content")
	att := &ExternalAttestation{
		Scope:          ScopeExternal,
		ArtifactDigest: "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000",
	}

	verifier := NewVerifier("", "")
	res, err := verifier.VerifyBundle(artifactContent, att, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.ArtifactDigestMatched {
		t.Fatalf("expected digest mismatch")
	}
}
