package sbom

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/dependency"
)

func createSampleReport() *dependency.Report {
	return &dependency.Report{
		Timestamp:    time.Now().UTC(),
		Directory:    "/workspace",
		Ecosystems:   []dependency.Ecosystem{dependency.EcosystemPython, dependency.EcosystemNPM},
		DirectCount:  2,
		TotalCount:   3,
		HasLockfile:  true,
		IsConsistent: true,
		Dependencies: []*dependency.Dependency{
			{
				Name:      "requests",
				Version:   "2.31.0",
				Ecosystem: dependency.EcosystemPython,
				Direct:    true,
				Registry:  "https://pypi.org/simple",
				Checksum:  "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			{
				Name:      "urllib3",
				Version:   "2.0.7",
				Ecosystem: dependency.EcosystemPython,
				Direct:    false,
				Registry:  "https://pypi.org/simple",
				Checksum:  "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			{
				Name:      "express",
				Version:   "4.18.2",
				Ecosystem: dependency.EcosystemNPM,
				Direct:    true,
				Registry:  "https://registry.npmjs.org",
			},
		},
	}
}

func TestCycloneDXGenerationAndParsing(t *testing.T) {
	report := createSampleReport()
	cdxBytes, err := GenerateCycloneDX("test-app", "1.0.0", report)
	if err != nil {
		t.Fatalf("GenerateCycloneDX failed: %v", err)
	}

	tmpDir := t.TempDir()
	cdxPath := filepath.Join(tmpDir, "bom.cdx.json")
	if err := os.WriteFile(cdxPath, cdxBytes, 0644); err != nil {
		t.Fatalf("failed writing cdx file: %v", err)
	}

	doc, err := ParseCycloneDX(cdxPath)
	if err != nil {
		t.Fatalf("ParseCycloneDX failed: %v", err)
	}

	if doc.Format != FormatCycloneDX {
		t.Errorf("expected format %s, got %s", FormatCycloneDX, doc.Format)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(doc.Components))
	}

	// Validate against same report -> must be valid
	validator := NewValidator()
	valRes := validator.Validate(doc, report)
	if !valRes.Valid {
		t.Errorf("expected valid validation result, got discrepancies: %+v", valRes.Discrepancies)
	}
}

func TestSPDXGenerationAndParsing(t *testing.T) {
	report := createSampleReport()
	spdxBytes, err := GenerateSPDX("test-app", "1.0.0", report)
	if err != nil {
		t.Fatalf("GenerateSPDX failed: %v", err)
	}

	tmpDir := t.TempDir()
	spdxPath := filepath.Join(tmpDir, "bom.spdx.json")
	if err := os.WriteFile(spdxPath, spdxBytes, 0644); err != nil {
		t.Fatalf("failed writing spdx file: %v", err)
	}

	doc, err := ParseSPDX(spdxPath)
	if err != nil {
		t.Fatalf("ParseSPDX failed: %v", err)
	}

	if doc.Format != FormatSPDX {
		t.Errorf("expected format %s, got %s", FormatSPDX, doc.Format)
	}
	// doc.Components has packages (including root)
	if len(doc.Components) < 3 {
		t.Fatalf("expected at least 3 packages, got %d", len(doc.Components))
	}

	validator := NewValidator()
	valRes := validator.Validate(doc, report)
	if !valRes.Valid {
		t.Errorf("expected valid validation result for SPDX, got discrepancies: %+v", valRes.Discrepancies)
	}
}

func TestSBOMDiscrepancyDetection(t *testing.T) {
	report := createSampleReport()
	validator := NewValidator()

	// Tampered SBOM: requests version is 2.32.0 instead of 2.31.0, and urllib3 is missing
	tamperedDoc := &Document{
		Format:      FormatCycloneDX,
		SpecVersion: "1.5",
		Components: []*Component{
			{
				Name:    "requests",
				Version: "2.32.0", // version drift
			},
		},
	}

	valRes := validator.Validate(tamperedDoc, report)
	if valRes.Valid {
		t.Fatalf("expected tampered SBOM to fail validation")
	}

	if len(valRes.Discrepancies) < 2 {
		t.Errorf("expected at least 2 discrepancies (version mismatch + missing components), got %d", len(valRes.Discrepancies))
	}

	hasVersionMismatch := false
	hasMissingInSBOM := false
	for _, d := range valRes.Discrepancies {
		if d.Type == "VERSION_MISMATCH" && d.Component == "requests" {
			hasVersionMismatch = true
		}
		if d.Type == "MISSING_IN_SBOM" {
			hasMissingInSBOM = true
		}
	}

	if !hasVersionMismatch {
		t.Errorf("expected VERSION_MISMATCH for requests")
	}
	if !hasMissingInSBOM {
		t.Errorf("expected MISSING_IN_SBOM for missing packages")
	}
}
