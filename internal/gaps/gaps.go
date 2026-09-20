package gaps

import (
	"fmt"
	"strings"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// CoverageStatus explicitly models evidence presence, absence, and validity
type CoverageStatus string

const (
	StatusVerified     CoverageStatus = "VERIFIED"
	StatusFailed       CoverageStatus = "FAILED"
	StatusUnverified   CoverageStatus = "UNVERIFIED"
	StatusUnobserved   CoverageStatus = "UNOBSERVED"
	StatusMissing      CoverageStatus = "MISSING"
	StatusContradicted CoverageStatus = "CONTRADICTED"
)

// LayerCoverage provides granular auditing for an individual evidence plane
type LayerCoverage struct {
	Layer       evidence.Layer `json:"layer"`
	Status      CoverageStatus `json:"status"`
	Description string         `json:"description"`
	Required    bool           `json:"required"`
}

// LineageStep documents an unassailable path from security decision to raw observation
type LineageStep struct {
	StepIndex       int            `json:"stepIndex"`
	Layer           evidence.Layer `json:"layer"`
	DecisionVerdict string         `json:"decisionVerdict"`
	RuleViolated    string         `json:"ruleViolated"`
	ContradictionID string         `json:"contradictionId"`
	EvidenceID      string         `json:"evidenceId"`
	Subject         string         `json:"subject"`
	Claimed         string         `json:"claimed"`
	Observed        string         `json:"observed"`
	RawObservation  string         `json:"rawObservation"`
}

// AnalysisReport encapsulates evidence gap and complete lineage analysis
type AnalysisReport struct {
	TotalLayers      int             `json:"totalLayers"`
	ObservedCount    int             `json:"observedCount"`
	MissingCount     int             `json:"missingCount"`
	UnobservedCount  int             `json:"unobservedCount"`
	CoverageRatio    float64         `json:"coverageRatio"`
	CoverageComplete bool            `json:"coverageComplete"`
	Verdict          string          `json:"verdict"`
	Reason           string          `json:"reason"`
	Layers           []LayerCoverage `json:"layers"`
	Lineage          []LineageStep   `json:"lineage,omitempty"`
}

// DefaultRequiredLayers defines planes strictly mandated for high-assurance release
var DefaultRequiredLayers = []evidence.Layer{
	evidence.LayerSource,
	evidence.LayerDependencies,
	evidence.LayerLockfile,
	evidence.LayerEnvironment,
	evidence.LayerProcess,
	evidence.LayerFilesystem,
	evidence.LayerNetwork,
	evidence.LayerArtifact,
	evidence.LayerSBOM,
	evidence.LayerProvenance,
	evidence.LayerSignature,
}

// Analyzer evaluates evidence completeness and lineage
type Analyzer struct {
	requiredLayers []evidence.Layer
}

// NewAnalyzer creates an evidence gap analyzer
func NewAnalyzer(required []evidence.Layer) *Analyzer {
	if len(required) == 0 {
		required = DefaultRequiredLayers
	}
	return &Analyzer{
		requiredLayers: required,
	}
}

// Analyze evaluates the correlation input and result for missing evidence gaps
func (a *Analyzer) Analyze(in *correlation.CorrelationInput, res *correlation.Result) *AnalysisReport {
	allLayers := []evidence.Layer{
		evidence.LayerSource,
		evidence.LayerDependencies,
		evidence.LayerLockfile,
		evidence.LayerEnvironment,
		evidence.LayerProcess,
		evidence.LayerFilesystem,
		evidence.LayerNetwork,
		evidence.LayerBuild,
		evidence.LayerArtifact,
		evidence.LayerSBOM,
		evidence.LayerProvenance,
		evidence.LayerSignature,
	}

	report := &AnalysisReport{
		TotalLayers: len(allLayers),
		Layers:      make([]LayerCoverage, 0),
		Lineage:     make([]LineageStep, 0),
	}

	reqMap := make(map[evidence.Layer]bool)
	for _, req := range a.requiredLayers {
		reqMap[req] = true
	}

	for _, layer := range allLayers {
		cov := LayerCoverage{
			Layer:    layer,
			Required: reqMap[layer],
		}

		// Inspect input directly for physical presence
		observed := isLayerPresent(layer, in)
		if !observed {
			if cov.Required {
				cov.Status = StatusMissing
				cov.Description = fmt.Sprintf("CRITICAL GAP: %s evidence was required by verification policy but was missing from the build evidence", layer)
				report.MissingCount++
			} else {
				cov.Status = StatusUnobserved
				cov.Description = fmt.Sprintf("TELEMETRY UNOBSERVED: %s was not captured during build execution", layer)
				report.UnobservedCount++
			}
		} else {
			report.ObservedCount++
			// Determine if contradicted or verified from result
			if res != nil && res.LayerStatuses != nil {
				st, ok := res.LayerStatuses[layer]
				if ok {
					switch st {
					case evidence.StatusVerified:
						cov.Status = StatusVerified
						cov.Description = "Evidence captured and mutually consistent across layers"
					case evidence.StatusContradicted, evidence.StatusMismatch:
						cov.Status = StatusContradicted
						cov.Description = "Evidence contradicted by other planes"
					case evidence.StatusUnverified:
						cov.Status = StatusUnverified
						cov.Description = "Evidence captured but unverified against policy"
					default:
						cov.Status = StatusVerified
					}
				} else {
					cov.Status = StatusVerified
				}
			} else {
				cov.Status = StatusVerified
			}
		}

		report.Layers = append(report.Layers, cov)
	}

	report.CoverageRatio = float64(report.ObservedCount) / float64(report.TotalLayers) * 100.0
	report.CoverageComplete = report.MissingCount == 0

	// Determine verdict based on gaps and contradictions
	if report.MissingCount > 0 {
		report.Verdict = "WARNING"
		report.Reason = fmt.Sprintf("Verification coverage incomplete: %d required evidence plane(s) missing", report.MissingCount)
	} else if res != nil && (!res.IsConsistent || len(res.Contradictions) > 0) {
		report.Verdict = "REJECTED"
		report.Reason = fmt.Sprintf("Verification failed: %d cross-plane contradiction(s) detected", len(res.Contradictions))
	} else {
		report.Verdict = "TRUSTED"
		report.Reason = "All required supply chain planes present, mutually consistent, and policy-compliant."
	}

	// Build Lineage Trail if contradictions exist
	if res != nil && len(res.Contradictions) > 0 {
		for i, c := range res.Contradictions {
			report.Lineage = append(report.Lineage, LineageStep{
				StepIndex:       i + 1,
				Layer:           c.Layer1,
				DecisionVerdict: "REJECTED",
				RuleViolated:    fmt.Sprintf("CrossLayerConsistencyRule(%s, %s)", c.Layer1, c.Layer2),
				ContradictionID: fmt.Sprintf("C-%02d", i+1),
				EvidenceID:      fmt.Sprintf("EV-%s-OBS", strings.ToUpper(string(c.Layer1))),
				Subject:         c.Subject,
				Claimed:         c.Claim1,
				Observed:        c.Claim2,
				RawObservation:  c.Description,
			})
		}
	}

	return report
}

// isLayerPresent returns true if raw observation data exists for the layer
func isLayerPresent(layer evidence.Layer, in *correlation.CorrelationInput) bool {
	if in == nil {
		return false
	}
	switch layer {
	case evidence.LayerSource:
		return in.Repository != nil && in.Repository.CommitSHA != ""
	case evidence.LayerDependencies:
		return in.Dependencies != nil
	case evidence.LayerLockfile:
		return in.Dependencies != nil && in.Dependencies.HasLockfile
	case evidence.LayerEnvironment:
		return in.Environment != nil && in.Environment.FingerprintHash != ""
	case evidence.LayerProcess:
		return in.ProcessTree != nil && len(in.ProcessTree.Processes) > 0
	case evidence.LayerFilesystem:
		return in.FilesystemDelta != nil || in.InputEvaluation != nil
	case evidence.LayerNetwork:
		return in.NetworkAudit != nil
	case evidence.LayerBuild:
		return in.Execution != nil
	case evidence.LayerArtifact:
		return in.Artifact != nil && in.Artifact.SHA256 != ""
	case evidence.LayerSBOM:
		return in.SBOM != nil
	case evidence.LayerProvenance:
		return in.Provenance != nil
	case evidence.LayerSignature:
		return in.Signature != nil
	}
	return false
}

// FormatTerminal generates human-readable gap analysis
func (r *AnalysisReport) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                     PROVENANCEX EVIDENCE GAP ANALYSIS                          \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("FINAL VERDICT:             [%s]\n", r.Verdict))
	sb.WriteString(fmt.Sprintf("SUMMARY REASON:            %s\n", r.Reason))
	sb.WriteString(fmt.Sprintf("EVIDENCE COVERAGE:         %.1f%% (%d/%d Planes Observed)\n", r.CoverageRatio, r.ObservedCount, r.TotalLayers))
	sb.WriteString(fmt.Sprintf("MISSING REQUIRED LAYERS:   %d\n", r.MissingCount))
	sb.WriteString(fmt.Sprintf("UNOBSERVED OPTIONAL LAYERS:%d\n", r.UnobservedCount))
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("EVIDENCE PLANE STATUS AUDIT:\n")
	for _, l := range r.Layers {
		reqMark := "[OPTIONAL]"
		if l.Required {
			reqMark = "[REQUIRED]"
		}
		statusBadge := fmt.Sprintf("%-14s", l.Status)
		sb.WriteString(fmt.Sprintf("  %-16s %s %s | %s\n", l.Layer, reqMark, statusBadge, l.Description))
	}

	if len(r.Lineage) > 0 {
		sb.WriteString("--------------------------------------------------------------------------------\n")
		sb.WriteString("CAUSAL DECISION LINEAGE (Decision -> Rule -> Contradiction -> Evidence -> Raw):\n")
		for _, step := range r.Lineage {
			sb.WriteString(fmt.Sprintf("  [%d] Verdict: %s\n", step.StepIndex, step.DecisionVerdict))
			sb.WriteString(fmt.Sprintf("      Rule:          %s\n", step.RuleViolated))
			sb.WriteString(fmt.Sprintf("      Contradiction: %s (%s)\n", step.ContradictionID, step.Subject))
			sb.WriteString(fmt.Sprintf("      Evidence ID:   %s [Layer: %s]\n", step.EvidenceID, step.Layer))
			sb.WriteString(fmt.Sprintf("      Claimed:       %q vs Observed: %q\n", step.Claimed, step.Observed))
			sb.WriteString(fmt.Sprintf("      Raw Data:      %s\n", step.RawObservation))
		}
	}
	sb.WriteString("================================================================================\n")
	return sb.String()
}
