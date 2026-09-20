package localization

import (
	"fmt"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// PipelineOrder defines the chronological, causal sequence of software generation layers
var PipelineOrder = []evidence.Layer{
	evidence.LayerSource,       // 1. Source code / Git commit
	evidence.LayerDependencies, // 2. Declared dependency manifests
	evidence.LayerLockfile,     // 3. Lockfile resolution & integrity hashes
	evidence.LayerEnvironment,  // 4. Build host / compiler toolchain environment
	evidence.LayerBuild,        // 5. Build command execution & arguments
	evidence.LayerProcess,      // 6. Process tree spawned during execution
	evidence.LayerFilesystem,   // 7. Filesystem boundary & unexpected inputs
	evidence.LayerNetwork,      // 8. Network egress & package registries
	evidence.LayerArtifact,     // 9. Output binary / artifact generation
	evidence.LayerSBOM,         // 10. Software Bill of Materials declarations
	evidence.LayerProvenance,   // 11. SLSA / in-toto build attestations
	evidence.LayerSignature,    // 12. Cryptographic signature assertions
}

// TrustBreakReport identifies the earliest inconsistent layer in the build pipeline
type TrustBreakReport struct {
	HasTrustBreak      bool             `json:"hasTrustBreak"`
	EarliestLayer      evidence.Layer   `json:"earliestLayer,omitempty"`
	LayerIndex         int              `json:"layerIndex"`
	Status             evidence.Status  `json:"status,omitempty"`
	Reason             string           `json:"reason,omitempty"`
	SupportingEvidence []string         `json:"supportingEvidence"`
	CausalChain        []evidence.Layer `json:"causalChain"`
}

// Localizer pinpoints where supply-chain trust collapses
type Localizer struct{}

// NewLocalizer constructs a trust-break localizer
func NewLocalizer() *Localizer {
	return &Localizer{}
}

// Localize analyzes correlation results to pinpoint the earliest causal trust-break layer
func (l *Localizer) Localize(res *correlation.Result) *TrustBreakReport {
	report := &TrustBreakReport{
		HasTrustBreak:      false,
		LayerIndex:         -1,
		SupportingEvidence: []string{},
		CausalChain:        []evidence.Layer{},
	}

	if res.IsConsistent && len(res.Contradictions) == 0 && len(res.UnexpectedInputs) == 0 {
		return report
	}

	for idx, layer := range PipelineOrder {
		status, exists := res.LayerStatuses[layer]
		report.CausalChain = append(report.CausalChain, layer)

		if exists && (status == evidence.StatusContradicted || status == evidence.StatusMismatch) {
			report.HasTrustBreak = true
			report.EarliestLayer = layer
			report.LayerIndex = idx
			report.Status = status
			report.Reason = fmt.Sprintf("Earliest supply-chain trust break detected at %s layer (%s)", layer, status)

			// Collect all supporting evidence relating to this earliest layer
			for _, c := range res.Contradictions {
				if c.Layer1 == layer || c.Layer2 == layer {
					report.SupportingEvidence = append(report.SupportingEvidence,
						fmt.Sprintf("[%s vs %s] %s: %s", c.Layer1, c.Layer2, c.Subject, c.Description))
				}
			}

			if layer == evidence.LayerFilesystem && len(res.UnexpectedInputs) > 0 {
				for _, unexp := range res.UnexpectedInputs {
					report.SupportingEvidence = append(report.SupportingEvidence,
						fmt.Sprintf("Unexpected build input observed: %s", unexp))
				}
			}

			return report
		}
	}

	// Fallback if contradiction spans unsequenced layer
	if len(res.Contradictions) > 0 {
		first := res.Contradictions[0]
		report.HasTrustBreak = true
		report.EarliestLayer = first.Layer1
		report.Status = evidence.StatusContradicted
		report.Reason = first.Description
		report.SupportingEvidence = append(report.SupportingEvidence, first.Description)
	}

	return report
}
