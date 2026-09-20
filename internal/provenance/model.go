package provenance

import "time"

// In-toto and SLSA specification constants
const (
	InTotoStatementV1 = "https://in-toto.io/Statement/v1"
	SLSAProvenanceV1  = "https://slsa.dev/provenance/v1"
	SLSAProvenanceV02 = "https://slsa.dev/provenance/v0.2"
	GenericBuildType  = "https://provenancex.dev/build/v1"
	DefaultBuilderID  = "https://provenancex.dev/builder/isolated-runner@v1"
)

// Subject describes an artifact identified by cryptographic digest
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"` // e.g. "sha256": "..."
}

// ResourceDescriptor describes an external material, dependency, or builder
type ResourceDescriptor struct {
	Name      string            `json:"name,omitempty"`
	URI       string            `json:"uri,omitempty"`
	Digest    map[string]string `json:"digest,omitempty"`
	Content   string            `json:"content,omitempty"`
	MediaType string            `json:"mediaType,omitempty"`
}

// SLSAv1Predicate models SLSA Provenance v1.0
type SLSAv1Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]any       `json:"externalParameters,omitempty"`
	InternalParameters   map[string]any       `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

type RunDetails struct {
	Builder  BuilderMetadata `json:"builder"`
	Metadata BuildMetadata   `json:"metadata"`
}

type BuilderMetadata struct {
	ID                  string               `json:"id"`
	Version             map[string]string    `json:"version,omitempty"`
	BuilderDependencies []ResourceDescriptor `json:"builderDependencies,omitempty"`
}

type BuildMetadata struct {
	InvocationID string    `json:"invocationId,omitempty"`
	StartedOn    time.Time `json:"startedOn,omitempty"`
	FinishedOn   time.Time `json:"finishedOn,omitempty"`
}

// InTotoStatement is the standard in-toto envelope for SLSA provenance
type InTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     SLSAv1Predicate `json:"predicate"`
}

// Contradiction records a specific trust break where provenance claims conflict with reality
type Contradiction struct {
	Field       string `json:"field"`    // e.g. "subject.digest.sha256", "material.commit"
	Claimed     string `json:"claimed"`  // claimed by provenance
	Observed    string `json:"observed"` // verified from actual artifact/repository
	Description string `json:"description"`
}

// VerificationResult summarizes the verification of a provenance attestation
type VerificationResult struct {
	Valid          bool             `json:"valid"`
	Contradictions []*Contradiction `json:"contradictions"`
	BuilderID      string           `json:"builderId"`
	BuildType      string           `json:"buildType"`
	SubjectCount   int              `json:"subjectCount"`
}
