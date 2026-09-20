package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/signature"
	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

// VerifyOffline executes comprehensive, self-contained offline verification of an evidence bundle
func VerifyOffline(bundlePath string) (*OfflineVerificationResult, error) {
	start := time.Now().UTC()

	tmpDir, err := os.MkdirTemp("", "provx-verify-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating temporary verification sandbox: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	result := &OfflineVerificationResult{
		Verdict:      "REJECTED",
		PassedChecks: make([]string, 0),
		FailedChecks: make([]string, 0),
		Warnings:     make([]string, 0),
		EvaluatedAt:  start,
	}

	// 1. Unpack and verify bundle integrity against manifest checksums
	manifest, err := Unpack(bundlePath, tmpDir)
	if err != nil {
		result.FailedChecks = append(result.FailedChecks, fmt.Sprintf("Bundle unpack & integrity check: %v", err))
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}

	result.BundleValid = true
	result.PassedChecks = append(result.PassedChecks, "Bundle archive structure and cryptographic checksums verified")
	result.ExpectedSHA256 = manifest.ArtifactSHA256

	// 2. Verify target artifact
	artRelPath := "artifact/" + manifest.ArtifactName
	artHostPath := filepath.Join(tmpDir, filepath.FromSlash(artRelPath))

	artDigest, _, err := crypto.HashFile(artHostPath)
	if err != nil {
		result.FailedChecks = append(result.FailedChecks, fmt.Sprintf("Artifact hashing failed: %v", err))
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}
	result.ArtifactSHA256 = artDigest

	if artDigest == manifest.ArtifactSHA256 {
		result.ArtifactMatch = true
		result.PassedChecks = append(result.PassedChecks, fmt.Sprintf("Artifact SHA-256 match (%s)", artDigest))
	} else {
		result.FailedChecks = append(result.FailedChecks, fmt.Sprintf("Artifact digest mismatch: manifest=%s, observed=%s", manifest.ArtifactSHA256, artDigest))
	}

	// 3. Verify in-toto / SLSA Provenance
	provPath := filepath.Join(tmpDir, "provenance", "provenance.json")
	if _, err := os.Stat(provPath); err == nil {
		stmt, err := provenance.ParseInTotoStatement(provPath)
		if err != nil {
			result.FailedChecks = append(result.FailedChecks, fmt.Sprintf("Provenance parsing failed: %v", err))
		} else {
			result.BuilderID = stmt.Predicate.RunDetails.Builder.ID

			// Verify subject digest
			foundSubjectMatch := false
			for _, subj := range stmt.Subject {
				if d, ok := subj.Digest["sha256"]; ok && d == artDigest {
					foundSubjectMatch = true
					break
				}
			}

			if foundSubjectMatch {
				result.ProvenanceValid = true
				result.PassedChecks = append(result.PassedChecks, fmt.Sprintf("Provenance attestation subject verified (Builder: %s)", stmt.Predicate.RunDetails.Builder.ID))
			} else {
				result.FailedChecks = append(result.FailedChecks, "Provenance statement subject digest contradicts target artifact digest")
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "No provenance attestation included in bundle")
	}

	// 4. Verify Digital Signature
	sigPath := filepath.Join(tmpDir, "signature", "signature.sig")
	keyPath := filepath.Join(tmpDir, "signature", "public.key")

	if fileExists(sigPath) && fileExists(keyPath) {
		sigBytes, sErr := os.ReadFile(sigPath)
		keyBytes, kErr := os.ReadFile(keyPath)

		if sErr == nil && kErr == nil {
			alg := detectAlgorithm(keyBytes)
			result.SignerAlgorithm = string(alg)

			artBytes, _ := os.ReadFile(artHostPath)
			verifier := signature.NewVerifier()
			verRes := verifier.VerifyBytes(alg, keyBytes, artBytes, sigBytes)

			if verRes.Valid {
				result.SignerValid = true
				result.PassedChecks = append(result.PassedChecks, fmt.Sprintf("Digital signature cryptographically valid (%s)", alg))
			} else {
				result.FailedChecks = append(result.FailedChecks, fmt.Sprintf("Signature verification failed: %s", verRes.Error))
			}
		}
	} else {
		result.Warnings = append(result.Warnings, "No digital signature or public key present in bundle")
	}

	// 5. Verify Append-Only Evidence Log
	logPath := filepath.Join(tmpDir, "evidence", "evidence-log.json")
	if fileExists(logPath) {
		logData, err := os.ReadFile(logPath)
		if err == nil {
			var evLog evidence.Log
			if err := json.Unmarshal(logData, &evLog); err == nil {
				if evLog.VerifyIntegrity() {
					result.TamperEvidentLogValid = true
					result.PassedChecks = append(result.PassedChecks, fmt.Sprintf("Tamper-evident append-only hash log verified (%d items)", len(evLog.Items)))
				} else {
					result.FailedChecks = append(result.FailedChecks, "Append-only evidence log hash chain broken (tamper detected)")
				}
			}
		}
	}

	// 6. Synthesize Verdict
	if len(result.FailedChecks) > 0 || !result.ArtifactMatch {
		result.Verdict = "REJECTED"
	} else if len(result.Warnings) > 0 {
		result.Verdict = "WARNING"
	} else {
		result.Verdict = "TRUSTED"
	}

	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func detectAlgorithm(pubKeyPEM []byte) signature.Algorithm {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return signature.AlgoECDSAP256
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return signature.AlgoECDSAP256
	}

	switch pub.(type) {
	case *ecdsa.PublicKey:
		return signature.AlgoECDSAP256
	case ed25519.PublicKey:
		return signature.AlgoEd25519
	case *rsa.PublicKey:
		return signature.AlgoRSASHA256
	default:
		return signature.AlgoECDSAP256
	}
}
