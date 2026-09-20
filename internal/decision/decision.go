package decision

import (
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/localization"
	"github.com/ramKarthik57/provenancex/internal/policy"
)

// Verdict defines the deterministic security verdict
type Verdict string

const (
	VerdictTrusted  Verdict = "TRUSTED"
	VerdictWarning  Verdict = "WARNING"
	VerdictRejected Verdict = "REJECTED"
)

// Decision encapsulates the explainable security verdict and full reasoning trail
type Decision struct {
	Timestamp  time.Time                      `json:"timestamp"`
	Verdict    Verdict                        `json:"verdict"`
	Reasons    []string                       `json:"reasons"`
	Warnings   []string                       `json:"warnings"`
	TrustBreak *localization.TrustBreakReport `json:"trustBreak,omitempty"`
}

// Engine evaluates correlation results against policy rules to render deterministic decisions
type Engine struct {
	localizer *localization.Localizer
}

// NewEngine constructs a security decision engine
func NewEngine() *Engine {
	return &Engine{
		localizer: localization.NewLocalizer(),
	}
}

// Decide renders a deterministic security verdict with an explainable audit trail
func (e *Engine) Decide(corr *correlation.Result, pol *policy.Policy) *Decision {
	if pol == nil {
		pol = policy.DefaultPolicy()
	}

	trustBreak := e.localizer.Localize(corr)
	dec := &Decision{
		Timestamp:  time.Now().UTC(),
		Verdict:    VerdictTrusted,
		Reasons:    []string{},
		Warnings:   []string{},
		TrustBreak: trustBreak,
	}

	// 1. Contradictions are fatal -> REJECTED
	if len(corr.Contradictions) > 0 {
		dec.Verdict = VerdictRejected
		for _, c := range corr.Contradictions {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("[%s vs %s] %s: %s", c.Layer1, c.Layer2, c.Subject, c.Description))
		}
	}

	// 2. Unexpected Build Inputs -> REJECTED
	if len(corr.UnexpectedInputs) > 0 {
		dec.Verdict = VerdictRejected
		for _, unexp := range corr.UnexpectedInputs {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("Unexpected uncommitted/injected build input: %s", unexp))
		}
	}

	// 3. Repository clean state policy
	if pol.Repository.RequireCleanState {
		if status, ok := corr.LayerStatuses[evidence.LayerSource]; ok && status == evidence.StatusMismatch {
			dec.Verdict = VerdictRejected
			dec.Reasons = append(dec.Reasons, "Repository working tree is dirty with uncommitted changes (violates require_clean_state policy)")
		}
	} else {
		if status, ok := corr.LayerStatuses[evidence.LayerSource]; ok && status == evidence.StatusMismatch {
			dec.Warnings = append(dec.Warnings, "Repository working tree is dirty with uncommitted changes")
			if dec.Verdict == VerdictTrusted {
				dec.Verdict = VerdictWarning
			}
		}
	}

	// 4. Lockfile policy
	if pol.Dependencies.RequireLockfile {
		if status, ok := corr.LayerStatuses[evidence.LayerLockfile]; ok && (status == evidence.StatusMismatch || status == evidence.StatusUnobserved) {
			dec.Verdict = VerdictRejected
			dec.Reasons = append(dec.Reasons, "Missing or unpinned dependency lockfile (violates require_lockfile policy)")
		}
	}

	// 5. Provenance policy
	if pol.Provenance.Required {
		if status, ok := corr.LayerStatuses[evidence.LayerProvenance]; !ok || status == evidence.StatusUnobserved {
			dec.Verdict = VerdictRejected
			dec.Reasons = append(dec.Reasons, "Mandatory SLSA / in-toto build provenance is missing (violates provenance.required policy)")
		}
	}

	// 6. Signature policy
	if pol.Signature.Required {
		if status, ok := corr.LayerStatuses[evidence.LayerSignature]; !ok || status == evidence.StatusUnobserved {
			dec.Verdict = VerdictRejected
			dec.Reasons = append(dec.Reasons, "Cryptographic digital signature is missing (violates signature.required policy)")
		}
	}

	// 7. Process Telemetry Policy
	if pol.Telemetry.RequireProcessTelemetry {
		if status, ok := corr.LayerStatuses[evidence.LayerProcess]; !ok || status == evidence.StatusUnobserved {
			dec.Verdict = VerdictRejected
			dec.Reasons = append(dec.Reasons, "Mandatory process telemetry is missing (violates telemetry.require_process_telemetry policy)")
		}
	} else {
		if status, ok := corr.LayerStatuses[evidence.LayerProcess]; !ok || status == evidence.StatusUnobserved {
			dec.Warnings = append(dec.Warnings, "Process execution telemetry is unobserved: runtime build processes were not tracked")
		}
	}

	// 8. Network Telemetry Policy
	if pol.Telemetry.RequireNetworkTelemetry {
		if status, ok := corr.LayerStatuses[evidence.LayerNetwork]; !ok || status == evidence.StatusUnobserved {
			dec.Verdict = VerdictRejected
			dec.Reasons = append(dec.Reasons, "Mandatory network telemetry is missing (violates telemetry.require_network_telemetry policy)")
		}
	} else {
		if status, ok := corr.LayerStatuses[evidence.LayerNetwork]; !ok || status == evidence.StatusUnobserved {
			dec.Warnings = append(dec.Warnings, "Network telemetry is unobserved: network egress was not audited during build")
		}
	}

	// 9. Network policy violations
	if status, ok := corr.LayerStatuses[evidence.LayerNetwork]; ok && status == evidence.StatusContradicted {
		dec.Verdict = VerdictRejected
		dec.Reasons = append(dec.Reasons, "Build attempted unauthorized network communication to unapproved destinations")
	}

	// 10. Build execution status
	if status, ok := corr.LayerStatuses[evidence.LayerBuild]; ok && status == evidence.StatusMismatch {
		dec.Verdict = VerdictRejected
		dec.Reasons = append(dec.Reasons, "Build command execution failed or exited with non-zero status")
	}

	// 11. Missing build inputs warning
	if len(corr.MissingInputs) > 0 {
		for _, m := range corr.MissingInputs {
			dec.Warnings = append(dec.Warnings, fmt.Sprintf("Declared build input was missing during build: %s", m))
		}
		if dec.Verdict == VerdictTrusted {
			dec.Verdict = VerdictWarning
		}
	}

	if dec.Verdict == VerdictTrusted {
		dec.Reasons = append(dec.Reasons, "All declared and observed evidence layers are mutually consistent and policy compliant")
	}

	return dec
}
