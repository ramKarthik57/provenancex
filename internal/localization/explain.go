package localization

import (
	"fmt"
	"strings"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// Explanation provides an explainable causal breakdown of a verification decision
type Explanation struct {
	Verdict                string           `json:"verdict"`
	Summary                string           `json:"summary"`
	EarliestTrustBreak     evidence.Layer   `json:"earliestTrustBreak,omitempty"`
	BrokenLayerStatus      evidence.Status  `json:"brokenLayerStatus,omitempty"`
	ContradictionCount     int              `json:"contradictionCount"`
	ContradictionDetails   []string         `json:"contradictionDetails"`
	ImpactedCausalChain    []evidence.Layer `json:"impactedCausalChain"`
	AssociatedEvidenceIDs  []string         `json:"associatedEvidenceIds"`
	ActionableRemediations []string         `json:"actionableRemediations"`
}

// Explain produces an explainable, audit-grade root cause analysis of the correlation result
func Explain(res *correlation.Result, verdict string) *Explanation {
	localizer := NewLocalizer()
	tb := localizer.Localize(res)

	exp := &Explanation{
		Verdict:                verdict,
		ContradictionCount:     len(res.Contradictions),
		ContradictionDetails:   make([]string, 0),
		ImpactedCausalChain:    tb.CausalChain,
		AssociatedEvidenceIDs:  make([]string, 0),
		ActionableRemediations: make([]string, 0),
	}

	if !tb.HasTrustBreak && exp.ContradictionCount == 0 {
		exp.Summary = "Artifact verified trustworthy: All 12 supply-chain planes are mutually consistent and policy-compliant."
		return exp
	}

	exp.EarliestTrustBreak = tb.EarliestLayer
	exp.BrokenLayerStatus = tb.Status
	exp.Summary = fmt.Sprintf("Verification failed: Trust collapsed at the %s layer (%s).", tb.EarliestLayer, tb.Status)

	// Collect contradiction details
	for _, c := range res.Contradictions {
		exp.ContradictionDetails = append(exp.ContradictionDetails,
			fmt.Sprintf("[%s vs %s] %s: %s (Claim: %q, Observed: %q)",
				c.Layer1, c.Layer2, c.Subject, c.Description, c.Claim1, c.Claim2))
	}

	// Collect relevant evidence IDs from the append-only evidence log
	if res.EvidenceLog != nil {
		for _, item := range res.EvidenceLog.Items {
			if item.Layer == tb.EarliestLayer || item.Status == evidence.StatusContradicted || item.Status == evidence.StatusMismatch {
				exp.AssociatedEvidenceIDs = append(exp.AssociatedEvidenceIDs, item.ID)
			}
		}
	}

	// Actionable remediations based on earliest break layer
	switch tb.EarliestLayer {
	case evidence.LayerSource:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Commit or stash all untracked and modified files before building.",
			"Verify git commit SHA matches declared build metadata.")
	case evidence.LayerDependencies:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Regenerate lockfile to resolve version drift.",
			"Ensure all packages are fetched from authorized package registries.")
	case evidence.LayerLockfile:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Commit dependency lockfile (poetry.lock, package-lock.json) to version control.",
			"Pin all package versions with cryptographic SHA-256 hashes.")
	case evidence.LayerEnvironment:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Align compiler and runtime toolchains with declared build specification.",
			"Avoid environment variable drift in CI build containers.")
	case evidence.LayerBuild, evidence.LayerProcess:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Inspect build scripts for unauthorized shell pipes (e.g. curl | bash).",
			"Ensure compiler exit code is 0 and build command is deterministic.")
	case evidence.LayerFilesystem:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Remove untracked or unexpected files from build workspace before compilation.",
			"Declare all dynamic configuration in expected build input manifests.")
	case evidence.LayerNetwork:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Block unauthorized egress connections during build.",
			"Add required remote registries to the network allowlist in policy.yaml.")
	case evidence.LayerArtifact:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Check for post-compilation binary tampering or file replacement on disk.",
			"Re-run build in clean workspace to verify artifact SHA-256 match.")
	case evidence.LayerSBOM:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Regenerate CycloneDX / SPDX SBOM directly from build dependencies.",
			"Ensure all dynamically linked packages are declared in SBOM components.")
	case evidence.LayerProvenance:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Ensure in-toto SLSA attestation subject digest matches output binary hash.",
			"Verify that builder ID in provenance matches trusted runner identity.")
	case evidence.LayerSignature:
		exp.ActionableRemediations = append(exp.ActionableRemediations,
			"Re-sign artifact using active private key.",
			"Verify correct public key is configured in policy.yaml.")
	}

	return exp
}

// FormatTerminal prints a human-readable "Why?" explanation
func (e *Explanation) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                 PROVENANCEX CAUSAL EXPLAINABILITY ENGINE                       \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("FINAL VERDICT:             [%s]\n", e.Verdict))
	sb.WriteString(fmt.Sprintf("SUMMARY:                   %s\n", e.Summary))
	if e.EarliestTrustBreak != "" {
		sb.WriteString(fmt.Sprintf("EARLIEST TRUST BREAK:      %s LAYER (%s)\n", e.EarliestTrustBreak, e.BrokenLayerStatus))
	}
	sb.WriteString(fmt.Sprintf("CONTRADICTIONS DETECTED:   %d\n", e.ContradictionCount))
	sb.WriteString("--------------------------------------------------------------------------------\n")

	if len(e.ContradictionDetails) > 0 {
		sb.WriteString("CONTRADICTION BREAKDOWN:\n")
		for i, c := range e.ContradictionDetails {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, c))
		}
		sb.WriteString("--------------------------------------------------------------------------------\n")
	}

	if len(e.AssociatedEvidenceIDs) > 0 {
		sb.WriteString(fmt.Sprintf("SUPPORTING EVIDENCE IDS:   %s\n", strings.Join(e.AssociatedEvidenceIDs, ", ")))
		sb.WriteString("--------------------------------------------------------------------------------\n")
	}

	if len(e.ActionableRemediations) > 0 {
		sb.WriteString("ACTIONABLE DEVELOPER REMEDIATIONS:\n")
		for i, r := range e.ActionableRemediations {
			sb.WriteString(fmt.Sprintf("  * [Fix %d] %s\n", i+1, r))
		}
	}
	sb.WriteString("================================================================================\n")
	return sb.String()
}
