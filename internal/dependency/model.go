package dependency

import "time"

// Ecosystem identifies the package ecosystem
type Ecosystem string

const (
	EcosystemPython Ecosystem = "python"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemDocker Ecosystem = "docker"
	EcosystemGo     Ecosystem = "go"
)

// Dependency represents a direct or transitive software package dependency
type Dependency struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Ecosystem    Ecosystem     `json:"ecosystem"`
	Direct       bool          `json:"direct"`
	Registry     string        `json:"registry,omitempty"`
	Checksum     string        `json:"checksum,omitempty"`
	Constraint   string        `json:"constraint,omitempty"`
	Dependencies []*Dependency `json:"dependencies,omitempty"`
}

// MismatchType defines the category of dependency discrepancies detected
type MismatchType string

const (
	MismatchVersionDrift        MismatchType = "VERSION_DRIFT"
	MismatchMissingLockfile     MismatchType = "MISSING_LOCKFILE"
	MismatchUndeclared          MismatchType = "UNDECLARED_DEPENDENCY"
	MismatchHashMismatch        MismatchType = "HASH_MISMATCH"
	MismatchUntrustedRegistry   MismatchType = "UNTRUSTED_REGISTRY"
	MismatchLockfileDiscrepancy MismatchType = "LOCKFILE_DISCREPANCY"
)

// Mismatch records a detected inconsistency between manifest and lockfile or policy
type Mismatch struct {
	Type        MismatchType `json:"type"`
	Package     string       `json:"package"`
	Ecosystem   Ecosystem    `json:"ecosystem"`
	Expected    string       `json:"expected"`
	Observed    string       `json:"observed"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"` // "WARNING" or "REJECTED"
}

// Report contains full dependency intelligence and analysis for a workspace
type Report struct {
	Timestamp    time.Time     `json:"timestamp"`
	Directory    string        `json:"directory"`
	Ecosystems   []Ecosystem   `json:"ecosystems"`
	DirectCount  int           `json:"directCount"`
	TotalCount   int           `json:"totalCount"`
	Dependencies []*Dependency `json:"dependencies"`
	Mismatches   []*Mismatch   `json:"mismatches"`
	HasLockfile  bool          `json:"hasLockfile"`
	IsConsistent bool          `json:"isConsistent"`
}
