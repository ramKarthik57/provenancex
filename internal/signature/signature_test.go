package signature

import (
	"testing"
)

func TestECDSASigningAndVerification(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKeyPair ECDSA failed: %v", err)
	}

	payload := []byte("Build artifact binary: sample.exe sha256:123456")
	sig, err := SignPayload(AlgoECDSAP256, kp.PrivateKeyPEM, payload)
	if err != nil {
		t.Fatalf("SignPayload ECDSA failed: %v", err)
	}

	verifier := NewVerifier()
	res := verifier.VerifyBytes(AlgoECDSAP256, kp.PublicKeyPEM, payload, sig)
	if !res.Valid {
		t.Errorf("expected valid ECDSA signature, got error: %s", res.Error)
	}

	// Test tampered payload -> MUST FAIL
	tamperedPayload := []byte("Build artifact binary: sample.exe sha256:TAMPERED")
	tamperedRes := verifier.VerifyBytes(AlgoECDSAP256, kp.PublicKeyPEM, tamperedPayload, sig)
	if tamperedRes.Valid {
		t.Errorf("expected tampered payload to fail ECDSA verification")
	}

	// Test corrupted signature bytes -> MUST FAIL
	corruptedSig := make([]byte, len(sig))
	copy(corruptedSig, sig)
	corruptedSig[len(corruptedSig)-2] ^= 0xFF
	corruptedRes := verifier.VerifyBytes(AlgoECDSAP256, kp.PublicKeyPEM, payload, corruptedSig)
	if corruptedRes.Valid {
		t.Errorf("expected corrupted signature to fail ECDSA verification")
	}
}

func TestEd25519SigningAndVerification(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoEd25519)
	if err != nil {
		t.Fatalf("GenerateKeyPair Ed25519 failed: %v", err)
	}

	payload := []byte("in-toto SLSA attestation payload JSON")
	sig, err := SignPayload(AlgoEd25519, kp.PrivateKeyPEM, payload)
	if err != nil {
		t.Fatalf("SignPayload Ed25519 failed: %v", err)
	}

	verifier := NewVerifier()
	res := verifier.VerifyBytes(AlgoEd25519, kp.PublicKeyPEM, payload, sig)
	if !res.Valid {
		t.Errorf("expected valid Ed25519 signature, got error: %s", res.Error)
	}

	// Tampered payload
	tamperedRes := verifier.VerifyBytes(AlgoEd25519, kp.PublicKeyPEM, []byte("tampered attestation"), sig)
	if tamperedRes.Valid {
		t.Errorf("expected tampered payload to fail Ed25519 verification")
	}
}

func TestRSASigningAndVerification(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoRSASHA256)
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA failed: %v", err)
	}

	payload := []byte("Release package checksum manifest")
	sig, err := SignPayload(AlgoRSASHA256, kp.PrivateKeyPEM, payload)
	if err != nil {
		t.Fatalf("SignPayload RSA failed: %v", err)
	}

	verifier := NewVerifier()
	res := verifier.VerifyBytes(AlgoRSASHA256, kp.PublicKeyPEM, payload, sig)
	if !res.Valid {
		t.Errorf("expected valid RSA signature, got error: %s", res.Error)
	}

	// Test with wrong public key
	wrongKP, _ := GenerateKeyPair(AlgoRSASHA256)
	wrongKeyRes := verifier.VerifyBytes(AlgoRSASHA256, wrongKP.PublicKeyPEM, payload, sig)
	if wrongKeyRes.Valid {
		t.Errorf("expected verification with wrong public key to fail")
	}
}
