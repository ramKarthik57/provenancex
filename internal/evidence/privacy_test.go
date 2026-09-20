package evidence

import (
	"testing"
)

func TestSelectiveDisclosureAndCommitment(t *testing.T) {
	rawPath := `C:\Users\Ram\Projects\CompanySecret\Build\app.exe`
	salt := []byte("provenancex-enterprise-salt")

	item := RedactPath(rawPath, salt)
	if !item.PrivacyPreserved {
		t.Fatalf("expected path to be privacy preserved")
	}
	if item.RedactedValue == rawPath {
		t.Fatalf("expected redacted value to differ from raw path")
	}
	if item.CommitmentHash == "" {
		t.Fatalf("expected non-empty cryptographic commitment")
	}

	// Verify commitment validity
	if !VerifyPathCommitment(rawPath, item.CommitmentHash, salt) {
		t.Fatalf("expected valid path commitment verification")
	}

	// Tampered path must fail commitment verification
	if VerifyPathCommitment(`C:\Users\Attacker\malware.exe`, item.CommitmentHash, salt) {
		t.Fatalf("expected tampered path to fail commitment verification")
	}
}
