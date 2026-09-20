package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// SelectiveDisclosureItem holds a privacy-preserved evidence field
type SelectiveDisclosureItem struct {
	OriginalField      string `json:"originalField"`
	RedactedValue      string `json:"redactedValue"`
	CommitmentHash     string `json:"commitmentHash"`
	IsCommitted        bool   `json:"isCommitted"`
	PrivacyPreserved   bool   `json:"privacyPreserved"`
}

var (
	userHomeRegex = regexp.MustCompile(`[A-Za-z]:\\[Uu]sers\\[^\\]+|/home/[^/]+`)
)

// RedactPath sanitizes local username and internal repository directories while computing a cryptographic commitment
func RedactPath(path string, secretSalt []byte) *SelectiveDisclosureItem {
	// 1. Compute HMAC SHA-256 commitment of raw path
	mac := hmac.New(sha256.New, secretSalt)
	mac.Write([]byte(path))
	commitment := hex.EncodeToString(mac.Sum(nil))

	// 2. Perform selective disclosure string redaction
	redacted := userHomeRegex.ReplaceAllString(path, "<REDACTED-HOME>")
	if strings.Contains(redacted, "CompanySecret") {
		redacted = strings.ReplaceAll(redacted, "CompanySecret", "<CONFIDENTIAL>")
	}

	return &SelectiveDisclosureItem{
		OriginalField:    "path",
		RedactedValue:    redacted,
		CommitmentHash:   commitment,
		IsCommitted:      true,
		PrivacyPreserved: (redacted != path),
	}
}

// VerifyPathCommitment checks that a disclosed raw path matches the commitment hash without storing raw path
func VerifyPathCommitment(rawPath string, commitment string, secretSalt []byte) bool {
	mac := hmac.New(sha256.New, secretSalt)
	mac.Write([]byte(rawPath))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(commitment), []byte(expected))
}
