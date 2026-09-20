package bundle

import (
	"time"
)

// BundleManifest contains the index and cryptographic checksums of all items in a portable bundle
type BundleManifest struct {
	ManifestVersion string            `json:"manifestVersion"`
	CreatedAt       time.Time         `json:"createdAt"`
	Creator         string            `json:"creator"`
	ArtifactName    string            `json:"artifactName"`
	ArtifactSHA256  string            `json:"artifactSha256"`
	Files           map[string]string `json:"files"` // internal relPath -> SHA-256
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// PackOptions defines inputs for assembling a portable evidence bundle
type PackOptions struct {
	ArtifactPath         string            `json:"artifactPath"`
	ProvenancePath       string            `json:"provenancePath,omitempty"`
	SBOMPath             string            `json:"sbomPath,omitempty"`
	SignaturePath        string            `json:"signaturePath,omitempty"`
	PublicKeyPath        string            `json:"publicKeyPath,omitempty"`
	EvidenceLogPath      string            `json:"evidenceLogPath,omitempty"`
	EvidenceManifestPath string            `json:"evidenceManifestPath,omitempty"`
	OutputPath           string            `json:"outputPath"`
	Metadata             map[string]string `json:"metadata,omitempty"`
}

// OfflineVerificationResult details the complete cryptographic and provenance verification done offline
type OfflineVerificationResult struct {
	Verdict               string    `json:"verdict"` // TRUSTED, WARNING, REJECTED
	BundleValid           bool      `json:"bundleValid"`
	ArtifactMatch         bool      `json:"artifactMatch"`
	ArtifactSHA256        string    `json:"artifactSha256"`
	ExpectedSHA256        string    `json:"expectedSha256"`
	SignerValid           bool      `json:"signerValid"`
	SignerAlgorithm       string    `json:"signerAlgorithm,omitempty"`
	TamperEvidentLogValid bool      `json:"tamperEvidentLogValid"`
	ProvenanceValid       bool      `json:"provenanceValid"`
	BuilderID             string    `json:"builderId,omitempty"`
	PassedChecks          []string  `json:"passedChecks"`
	FailedChecks          []string  `json:"failedChecks"`
	Warnings              []string  `json:"warnings"`
	EvaluatedAt           time.Time `json:"evaluatedAt"`
	DurationMs            int64     `json:"durationMs"`
}
