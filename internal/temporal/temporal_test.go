package temporal

import (
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/evidence"
)

func TestTemporalConsistencyValidSequence(t *testing.T) {
	engine := NewEngine(5 * time.Minute)
	base := time.Now().Add(-10 * time.Minute)

	events := []*TemporalEvent{
		{ID: "EV-1", Sequence: 1, Layer: evidence.LayerSource, Name: "git-commit", CreatedAt: base},
		{ID: "EV-2", Sequence: 2, Layer: evidence.LayerDependencies, Name: "dep-install", CreatedAt: base.Add(1 * time.Minute)},
		{ID: "EV-3", Sequence: 3, Layer: evidence.LayerBuild, Name: "compilation", CreatedAt: base.Add(2 * time.Minute)},
		{ID: "EV-4", Sequence: 4, Layer: evidence.LayerArtifact, Name: "binary-emission", CreatedAt: base.Add(3 * time.Minute)},
		{ID: "EV-5", Sequence: 5, Layer: evidence.LayerSignature, Name: "signing", CreatedAt: base.Add(4 * time.Minute)},
	}

	anomalies, valid := engine.Validate(events)
	if !valid || len(anomalies) > 0 {
		t.Fatalf("expected valid temporal sequence, got %d anomalies", len(anomalies))
	}
}

func TestTemporalImpossibleOrderDetection(t *testing.T) {
	engine := NewEngine(5 * time.Minute)
	base := time.Now().Add(-10 * time.Minute)

	// Artifact claimed created BEFORE compilation
	events := []*TemporalEvent{
		{ID: "EV-1", Sequence: 1, Layer: evidence.LayerBuild, Name: "compilation", CreatedAt: base.Add(5 * time.Minute)},
		{ID: "EV-2", Sequence: 2, Layer: evidence.LayerArtifact, Name: "binary-emission", CreatedAt: base.Add(1 * time.Minute)},
	}

	anomalies, valid := engine.Validate(events)
	if valid || len(anomalies) == 0 {
		t.Fatalf("expected impossible order anomaly detection")
	}

	if anomalies[0].Type != AnomalyImpossibleOrder {
		t.Fatalf("expected AnomalyImpossibleOrder, got %s", anomalies[0].Type)
	}
}

func TestTemporalClockSkewDetection(t *testing.T) {
	engine := NewEngine(5 * time.Minute)
	futureTime := time.Now().Add(24 * time.Hour)

	events := []*TemporalEvent{
		{ID: "EV-1", Sequence: 1, Layer: evidence.LayerSource, Name: "future-commit", CreatedAt: futureTime},
	}

	anomalies, valid := engine.Validate(events)
	if valid || len(anomalies) == 0 {
		t.Fatalf("expected clock skew anomaly detection")
	}

	if anomalies[0].Type != AnomalyClockSkew {
		t.Fatalf("expected AnomalyClockSkew, got %s", anomalies[0].Type)
	}
}
