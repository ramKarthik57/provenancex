package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/dependency"
)

// CycloneDX JSON structs
type cdxDoc struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     cdxMetadata  `json:"metadata"`
	Components   []cdxComp    `json:"components"`
}

type cdxMetadata struct {
	Timestamp string      `json:"timestamp"`
	Tools     []cdxTool   `json:"tools,omitempty"`
	Component *cdxComp    `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComp struct {
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	PURL        string    `json:"purl,omitempty"`
	Description string    `json:"description,omitempty"`
	Hashes      []cdxHash `json:"hashes,omitempty"`
}

type cdxHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// ParseCycloneDX parses a CycloneDX JSON file into a normalized Document
func ParseCycloneDX(filePath string) (*Document, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var raw cdxDoc
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed parsing CycloneDX JSON: %w", err)
	}

	if strings.ToLower(raw.BOMFormat) != "cyclonedx" {
		return nil, fmt.Errorf("not a valid CycloneDX document (bomFormat is %q)", raw.BOMFormat)
	}

	ts, _ := time.Parse(time.RFC3339, raw.Metadata.Timestamp)
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	doc := &Document{
		Format:      FormatCycloneDX,
		SpecVersion: raw.SpecVersion,
		Timestamp:   ts,
		Components:  make([]*Component, 0, len(raw.Components)),
	}

	if raw.Metadata.Component != nil {
		doc.Name = raw.Metadata.Component.Name
		doc.Version = raw.Metadata.Component.Version
	}

	for _, c := range raw.Components {
		comp := &Component{
			Name:        c.Name,
			Version:     c.Version,
			PURL:        c.PURL,
			Type:        c.Type,
			Description: c.Description,
			Hashes:      make(map[string]string),
		}
		for _, h := range c.Hashes {
			comp.Hashes[h.Algorithm] = h.Content
		}
		doc.Components = append(doc.Components, comp)
	}

	return doc, nil
}

// GenerateCycloneDX generates a CycloneDX v1.5 compliant JSON byte array from a dependency report
func GenerateCycloneDX(projectName, projectVersion string, report *dependency.Report) ([]byte, error) {
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:provenancex-%d", time.Now().UnixNano()),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{
					Vendor:  "ProvenanceX",
					Name:    "provenancex-sbom",
					Version: "0.1.0",
				},
			},
			Component: &cdxComp{
				Type:    "application",
				Name:    projectName,
				Version: projectVersion,
			},
		},
		Components: make([]cdxComp, 0, len(report.Dependencies)),
	}

	for _, dep := range report.Dependencies {
		comp := cdxComp{
			Type:    "library",
			Name:    dep.Name,
			Version: dep.Version,
			PURL:    ToPURL(dep),
		}
		if dep.Checksum != "" {
			comp.Hashes = []cdxHash{
				{
					Algorithm: "SHA-256",
					Content:   dep.Checksum,
				},
			}
		}
		doc.Components = append(doc.Components, comp)
	}

	return json.MarshalIndent(doc, "", "  ")
}
