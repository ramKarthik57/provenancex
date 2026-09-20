package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Verifier validates digital signatures on software artifacts and attestations
type Verifier struct{}

// NewVerifier constructs a digital signature verifier
func NewVerifier() *Verifier {
	return &Verifier{}
}

// VerifyBytes verifies a digital signature against a byte slice payload using the public key
func (v *Verifier) VerifyBytes(alg Algorithm, pubKeyPEM, payload, signature []byte) *VerificationResult {
	res := &VerificationResult{
		Valid:       false,
		Algorithm:   alg,
		Distinction: ArtifactTypeSignature,
	}

	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		res.Error = "invalid PEM block for public key"
		return res
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		res.Error = fmt.Sprintf("failed parsing public key: %v", err)
		return res
	}

	digest := sha256.Sum256(payload)

	switch alg {
	case AlgoECDSAP256:
		ecdsaPub, ok := pubInterface.(*ecdsa.PublicKey)
		if !ok {
			res.Error = "public key is not ECDSA"
			return res
		}
		if ecdsa.VerifyASN1(ecdsaPub, digest[:], signature) {
			res.Valid = true
		} else {
			res.Error = "ECDSA signature verification failed (signature or payload mismatch)"
		}

	case AlgoEd25519:
		edPub, ok := pubInterface.(ed25519.PublicKey)
		if !ok {
			res.Error = "public key is not Ed25519"
			return res
		}
		if ed25519.Verify(edPub, payload, signature) {
			res.Valid = true
		} else {
			res.Error = "Ed25519 signature verification failed"
		}

	case AlgoRSASHA256:
		rsaPub, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			res.Error = "public key is not RSA"
			return res
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature); err == nil {
			res.Valid = true
		} else {
			res.Error = fmt.Sprintf("RSA signature verification failed: %v", err)
		}

	default:
		res.Error = fmt.Sprintf("unsupported signature algorithm: %s", alg)
	}

	return res
}

// VerifyFile streams and verifies a digital signature on a file
func (v *Verifier) VerifyFile(alg Algorithm, pubKeyPEM []byte, filePath string, signature []byte) (*VerificationResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading file %s: %w", filePath, err)
	}
	return v.VerifyBytes(alg, pubKeyPEM, data, signature), nil
}
