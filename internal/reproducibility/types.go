package reproducibility

import (
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
)

// Status represents the reproducibility verification verdict
type Status string

const (
	StatusReproducible Status = "REPRODUCIBLE"
	StatusDivergent    Status = "DIVERGENT"
	StatusFailed       Status = "FAILED"
)

// DivergenceCategory categorizes the root cause of build divergence
type DivergenceCategory string

const (
	CategoryBitwiseMatch     DivergenceCategory = "BITWISE_MATCH"
	CategoryTimestamp        DivergenceCategory = "TIMESTAMP_VARIATION"
	CategoryPathLeakage      DivergenceCategory = "BUILD_PATH_LEAKAGE"
	CategoryCompilerDrift    DivergenceCategory = "COMPILER_OR_RUNTIME_DRIFT"
	CategoryDependencyDrift  DivergenceCategory = "DEPENDENCY_DRIFT"
	CategoryArchiveOrdering  DivergenceCategory = "ARCHIVE_ORDER_OR_METADATA"
	CategoryCodeModification DivergenceCategory = "CODE_OR_BINARY_MODIFICATION"
	CategoryUnknown          DivergenceCategory = "UNKNOWN_DIVERGENCE"
)

// DivergenceCause provides granular diagnostic evidence for a discovered difference
type DivergenceCause struct {
	Category       DivergenceCategory `json:"category"`
	Severity       string             `json:"severity"` // INFO, WARNING, HIGH
	Description    string             `json:"description"`
	Evidence       string             `json:"evidence,omitempty"`
	Recommendation string             `json:"recommendation,omitempty"`
}

// RebuildOptions configures controlled rebuild executions
type RebuildOptions struct {
	BuildCmd    string            `json:"buildCmd"`
	BuildDir    string            `json:"buildDir"`
	ArtifactRel string            `json:"artifactRel"`
	Environment map[string]string `json:"environment,omitempty"`
	CleanEnv    bool              `json:"cleanEnv"`
	Iterations  int               `json:"iterations"`
	SourceEpoch int64             `json:"sourceEpoch,omitempty"`
}

// Report contains the complete reproducibility analysis between two build runs or artifacts
type Report struct {
	Status           Status            `json:"status"`
	BitwiseMatch     bool              `json:"bitwiseMatch"`
	Artifact1        artifact.Metadata `json:"artifact1"`
	Artifact2        artifact.Metadata `json:"artifact2"`
	ByteDifference   int64             `json:"byteDifference"`
	DivergenceCauses []DivergenceCause `json:"divergenceCauses"`
	Recommendations  []string          `json:"recommendations"`
	EvaluatedAt      time.Time         `json:"evaluatedAt"`
	DurationMs       int64             `json:"durationMs"`
}
