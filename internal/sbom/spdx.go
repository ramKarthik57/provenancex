package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/dependency"
)

type spdxDoc struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	CreationInfo      spdxCreation  `json:"creationInfo"`
	Packages          []spdxPackage `json:"packages"`
}

type spdxCreation struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// ParseSPDX parses an SPDX 2.3 JSON document
func ParseSPDX(filePath string) (*Document, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var raw spdxDoc
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed parsing SPDX JSON: %w", err)
	}

	if !strings.HasPrefix(raw.SPDXVersion, "SPDX-") {
		return nil, fmt.Errorf("invalid SPDX document (spdxVersion is %q)", raw.SPDXVersion)
	}

	ts, _ := time.Parse(time.RFC3339, raw.CreationInfo.Created)
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	doc := &Document{
		Format:      FormatSPDX,
		SpecVersion: raw.SPDXVersion,
		Name:        raw.Name,
		Timestamp:   ts,
		Components:  make([]*Component, 0, len(raw.Packages)),
	}

	for _, p := range raw.Packages {
		comp := &Component{
			Name:    p.Name,
			Version: p.VersionInfo,
			Type:    "library",
			Hashes:  make(map[string]string),
		}

		for _, cs := range p.Checksums {
			comp.Hashes[cs.Algorithm] = cs.ChecksumValue
		}

		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" {
				comp.PURL = ref.ReferenceLocator
			}
		}

		doc.Components = append(doc.Components, comp)
	}

	return doc, nil
}

// GenerateSPDX generates an SPDX 2.3 JSON document from dependency analysis
func GenerateSPDX(projectName, projectVersion string, report *dependency.Report) ([]byte, error) {
	nowStr := time.Now().UTC().Format(time.RFC3339)

	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              projectName,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/provenancex-%s-%d", projectName, time.Now().UnixNano()),
		CreationInfo: spdxCreation{
			Created:  nowStr,
			Creators: []string{"Tool: ProvenanceX-0.1.0"},
		},
		Packages: make([]spdxPackage, 0, len(report.Dependencies)+1),
	}

	// Root application package
	doc.Packages = append(doc.Packages, spdxPackage{
		SPDXID:           "SPDXRef-Package-Root",
		Name:             projectName,
		VersionInfo:      projectVersion,
		DownloadLocation: "NOASSERTION",
	})

	for i, dep := range report.Dependencies {
		pkg := spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             dep.Name,
			VersionInfo:      dep.Version,
			DownloadLocation: dep.Registry,
			ExternalRefs: []spdxExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  ToPURL(dep),
				},
			},
		}

		if dep.Checksum != "" {
			pkg.Checksums = []spdxChecksum{
				{
					Algorithm:     "SHA256",
					ChecksumValue: dep.Checksum,
				},
			}
		}

		doc.Packages = append(doc.Packages, pkg)
	}

	return json.MarshalIndent(doc, "", "  ")
}
