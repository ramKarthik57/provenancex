package filesystem

import "time"

// FileSnapshot records metadata and hash of an individual file within the evidence boundary
type FileSnapshot struct {
	RelativePath string    `json:"relativePath"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"modTime"`
	SHA256       string    `json:"sha256"`
}

// Snapshot represents a full point-in-time state of the build boundary
type Snapshot struct {
	RootDir   string                   `json:"rootDir"`
	Timestamp time.Time                `json:"timestamp"`
	Files     map[string]*FileSnapshot `json:"files"`
}

// Delta records changes between two boundary snapshots
type Delta struct {
	CreatedFiles  []*FileSnapshot `json:"createdFiles"`
	ModifiedFiles []*FileSnapshot `json:"modifiedFiles"`
	DeletedFiles  []string        `json:"deletedFiles"`
}

// InputEvaluation models the formal Expected vs Observed inputs set difference:
// Unexpected = Observed - Expected
// Missing    = Expected - Observed
type InputEvaluation struct {
	ExpectedInputs   []string `json:"expectedInputs"`
	ObservedInputs   []string `json:"observedInputs"`
	UnexpectedInputs []string `json:"unexpectedInputs"`
	MissingInputs    []string `json:"missingInputs"`
	HasDiscrepancy   bool     `json:"hasDiscrepancy"`
}
