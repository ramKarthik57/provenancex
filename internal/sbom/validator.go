package sbom

import (
	"fmt"
	"strings"

	"github.com/ramKarthik57/provenancex/internal/dependency"
)

// Validator cross-verifies SBOMs against observed build dependencies
type Validator struct{}

// NewValidator constructs an SBOM validator
func NewValidator() *Validator {
	return &Validator{}
}

// Validate compares a parsed SBOM Document against observed dependencies
func (v *Validator) Validate(doc *Document, report *dependency.Report) *ValidationResult {
	result := &ValidationResult{
		Valid:          true,
		Format:         doc.Format,
		SpecVersion:    doc.SpecVersion,
		ComponentCount: len(doc.Components),
		Discrepancies:  []*Discrepancy{},
	}

	sbomMap := make(map[string]*Component)
	for _, c := range doc.Components {
		sbomMap[strings.ToLower(c.Name)] = c
	}

	observedMap := make(map[string]*dependency.Dependency)
	for _, d := range report.Dependencies {
		observedMap[strings.ToLower(d.Name)] = d
	}

	// 1. Check all observed dependencies are represented in SBOM
	for name, obs := range observedMap {
		sbomComp, exists := sbomMap[name]
		if !exists {
			result.Valid = false
			result.Discrepancies = append(result.Discrepancies, &Discrepancy{
				Component:   obs.Name,
				Type:        "MISSING_IN_SBOM",
				ActualValue: obs.Version,
				SBOMValue:   "not declared",
				Description: fmt.Sprintf("Observed dependency %q was used in build but missing from SBOM", obs.Name),
			})
			continue
		}

		// 2. Version comparison
		if obs.Version != "" && sbomComp.Version != "" && obs.Version != sbomComp.Version {
			result.Valid = false
			result.Discrepancies = append(result.Discrepancies, &Discrepancy{
				Component:   obs.Name,
				Type:        "VERSION_MISMATCH",
				ActualValue: obs.Version,
				SBOMValue:   sbomComp.Version,
				Description: fmt.Sprintf("Version mismatch for %q: SBOM declares %s, but build observed %s", obs.Name, sbomComp.Version, obs.Version),
			})
		}

		// 3. Hash comparison if both present
		if obs.Checksum != "" {
			for alg, h := range sbomComp.Hashes {
				cleanAlg := strings.ToUpper(strings.ReplaceAll(alg, "-", ""))
				if strings.Contains(cleanAlg, "SHA256") {
					cleanObs := strings.TrimPrefix(obs.Checksum, "sha256:")
					cleanSBOM := strings.TrimPrefix(h, "sha256:")
					if !strings.EqualFold(cleanObs, cleanSBOM) {
						result.Valid = false
						result.Discrepancies = append(result.Discrepancies, &Discrepancy{
							Component:   obs.Name,
							Type:        "HASH_MISMATCH",
							ActualValue: cleanObs,
							SBOMValue:   cleanSBOM,
							Description: fmt.Sprintf("Hash discrepancy for %q: SBOM has %s, but observed dependency has %s", obs.Name, cleanSBOM, cleanObs),
						})
					}
				}
			}
		}
	}

	return result
}
