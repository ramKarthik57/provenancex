package sbom

import (
	"time"

	"github.com/ramKarthik57/provenancex/internal/dependency"
)

// Format specifies the SBOM specification standard
type Format string

const (
	FormatCycloneDX Format = "CycloneDX"
	FormatSPDX      Format = "SPDX"
	FormatUnknown   Format = "Unknown"
)

// Component represents a software dependency or module in an SBOM
type Component struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	PURL        string            `json:"purl,omitempty"`
	Type        string            `json:"type"`             // e.g. "library", "application", "container"
	Hashes      map[string]string `json:"hashes,omitempty"` // algorithm -> hex digest
	License     string            `json:"license,omitempty"`
	Supplier    string            `json:"supplier,omitempty"`
	Description string            `json:"description,omitempty"`
}

// Document is the normalized in-memory representation of any parsed or generated SBOM
type Document struct {
	Format      Format       `json:"format"`
	SpecVersion string       `json:"specVersion"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Timestamp   time.Time    `json:"timestamp"`
	Author      string       `json:"author,omitempty"`
	Components  []*Component `json:"components"`
}

// Discrepancy represents an inconsistency between declared SBOM and actual observed dependencies
type Discrepancy struct {
	Component   string `json:"component"`
	Type        string `json:"type"` // "MISSING_IN_BUILD", "MISSING_IN_SBOM", "VERSION_MISMATCH", "HASH_MISMATCH"
	SBOMValue   string `json:"sbomValue"`
	ActualValue string `json:"actualValue"`
	Description string `json:"description"`
}

// ValidationResult summarizes the integrity correlation between an SBOM and observed dependencies
type ValidationResult struct {
	Valid          bool           `json:"valid"`
	Format         Format         `json:"format"`
	SpecVersion    string         `json:"specVersion"`
	ComponentCount int            `json:"componentCount"`
	Discrepancies  []*Discrepancy `json:"discrepancies"`
}

// Converter converts internal dependency models to Package URLs (PURL)
func ToPURL(dep *dependency.Dependency) string {
	switch dep.Ecosystem {
	case dependency.EcosystemPython:
		return "pkg:pypi/" + dep.Name + "@" + dep.Version
	case dependency.EcosystemNPM:
		return "pkg:npm/" + dep.Name + "@" + dep.Version
	case dependency.EcosystemGo:
		return "pkg:golang/" + dep.Name + "@" + dep.Version
	case dependency.EcosystemDocker:
		return "pkg:docker/" + dep.Name + "@" + dep.Version
	default:
		return "pkg:generic/" + dep.Name + "@" + dep.Version
	}
}
