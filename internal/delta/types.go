package delta

import (
	"time"
)

// DriftSeverity classifies the security impact of a detected difference
type DriftSeverity string

const (
	SeverityNone     DriftSeverity = "NONE"
	SeverityInfo     DriftSeverity = "INFO"
	SeverityWarning  DriftSeverity = "WARNING"
	SeverityCritical DriftSeverity = "CRITICAL"
)

// DriftCategory identifies the system layer where a variance occurred
type DriftCategory string

const (
	CategoryMetadata    DriftCategory = "METADATA"
	CategoryCommand     DriftCategory = "COMMAND"
	CategoryEnvironment DriftCategory = "ENVIRONMENT"
	CategoryFilesystem  DriftCategory = "FILESYSTEM"
	CategoryArtifact    DriftCategory = "ARTIFACT"
	CategoryNetwork     DriftCategory = "NETWORK"
)

// DiffItem represents an individual localized change between two builds
type DiffItem struct {
	Category    DriftCategory `json:"category"`
	Severity    DriftSeverity `json:"severity"`
	Field       string        `json:"field"`
	Value1      string        `json:"value1"`
	Value2      string        `json:"value2"`
	Description string        `json:"description"`
}

// Report contains the complete comparative analysis between two evidence manifests
type Report struct {
	Build1ID              string     `json:"build1Id"`
	Build2ID              string     `json:"build2Id"`
	Timestamp1            time.Time  `json:"timestamp1"`
	Timestamp2            time.Time  `json:"timestamp2"`
	OverallClassification string     `json:"overallClassification"`
	ArtifactsIdentical    bool       `json:"artifactsIdentical"`
	EnvironmentIdentical  bool       `json:"environmentIdentical"`
	CommandIdentical      bool       `json:"commandIdentical"`
	FilesystemIdentical   bool       `json:"filesystemIdentical"`
	NetworkIdentical      bool       `json:"networkIdentical"`
	Differences           []DiffItem `json:"differences"`
	TotalDifferences      int        `json:"totalDifferences"`
	Summary               string     `json:"summary"`
	EvaluatedAt           time.Time  `json:"evaluatedAt"`
}
