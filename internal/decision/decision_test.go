package decision

import (
	"testing"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/policy"
)

func TestDecisionEngineTrusted(t *testing.T) {
	engine := NewEngine()
	pol := policy.DefaultPolicy()

	corr := &correlation.Result{
		IsConsistent: true,
		LayerStatuses: map[evidence.Layer]evidence.Status{
			evidence.LayerSource:       evidence.StatusVerified,
			evidence.LayerDependencies: evidence.StatusVerified,
			evidence.LayerLockfile:     evidence.StatusVerified,
			evidence.LayerArtifact:     evidence.StatusVerified,
		},
	}

	dec := engine.Decide(corr, pol)

	if dec.Verdict != VerdictTrusted {
		t.Errorf("expected verdict TRUSTED, got %s (reasons: %v)", dec.Verdict, dec.Reasons)
	}
	if len(dec.Reasons) == 0 {
		t.Errorf("expected explainable reason for TRUSTED verdict")
	}
}

func TestDecisionEngineRejectedOnContradiction(t *testing.T) {
	engine := NewEngine()
	pol := policy.DefaultPolicy()

	corr := &correlation.Result{
		IsConsistent: false,
		LayerStatuses: map[evidence.Layer]evidence.Status{
			evidence.LayerNetwork: evidence.StatusContradicted,
		},
		Contradictions: []*correlation.Contradiction{
			{
				Layer1:      evidence.LayerDependencies,
				Layer2:      evidence.LayerNetwork,
				Subject:     "evil-c2.xyz",
				Description: "Unauthorized network destination contacted during build",
			},
		},
	}

	dec := engine.Decide(corr, pol)

	if dec.Verdict != VerdictRejected {
		t.Errorf("expected verdict REJECTED, got %s", dec.Verdict)
	}

	if dec.TrustBreak == nil || !dec.TrustBreak.HasTrustBreak {
		t.Errorf("expected trust break localization attached to decision")
	}

	if len(dec.Reasons) == 0 {
		t.Errorf("expected explicit reasons for REJECTED verdict")
	}
}
