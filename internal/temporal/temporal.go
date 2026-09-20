package temporal

import (
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// AnomalyType categorizes temporal integrity violations
type AnomalyType string

const (
	AnomalyClockSkew             AnomalyType = "CLOCK_SKEW"
	AnomalyTemporalInconsistency AnomalyType = "TEMPORAL_INCONSISTENCY"
	AnomalyImpossibleOrder       AnomalyType = "IMPOSSIBLE_ORDER"
	AnomalyUntrustedTimestamp    AnomalyType = "UNTRUSTED_TIMESTAMP"
)

// TemporalEvent models a discrete lifecycle event with multi-dimensional timestamps
type TemporalEvent struct {
	ID         string         `json:"id"`
	Layer      evidence.Layer `json:"layer"`
	Name       string         `json:"name"`
	Sequence   int            `json:"sequence"`
	ObservedAt time.Time      `json:"observedAt"`
	CreatedAt  time.Time      `json:"createdAt"`
	VerifiedAt time.Time      `json:"verifiedAt"`
}

// TemporalAnomaly represents a causal timeline contradiction
type TemporalAnomaly struct {
	Type        AnomalyType    `json:"type"`
	Layer       evidence.Layer `json:"layer"`
	Subject     string         `json:"subject"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Delta       time.Duration  `json:"delta"`
}

// Engine performs timeline validation across supply-chain lifecycle events
type Engine struct {
	allowedClockSkew time.Duration
}

// NewEngine creates a temporal consistency validation engine
func NewEngine(allowedSkew time.Duration) *Engine {
	if allowedSkew <= 0 {
		allowedSkew = 5 * time.Minute
	}
	return &Engine{
		allowedClockSkew: allowedSkew,
	}
}

// Validate checks causal sequence and timeline sanity
func (e *Engine) Validate(events []*TemporalEvent) ([]*TemporalAnomaly, bool) {
	anomalies := make([]*TemporalAnomaly, 0)
	now := time.Now().UTC()

	// 1. Future timestamp checks (Clock skew vs Malicious forward dates)
	for _, ev := range events {
		if ev.CreatedAt.After(now.Add(e.allowedClockSkew)) {
			anomalies = append(anomalies, &TemporalAnomaly{
				Type:        AnomalyClockSkew,
				Layer:       ev.Layer,
				Subject:     ev.Name,
				Description: fmt.Sprintf("Event %s timestamp %s is in the future beyond allowed skew (%s)", ev.Name, ev.CreatedAt.Format(time.RFC3339), e.allowedClockSkew),
				Severity:    "WARNING",
				Delta:       ev.CreatedAt.Sub(now),
			})
		}
	}

	// 2. Pairwise chronological causality checks
	for i := 0; i < len(events)-1; i++ {
		first := events[i]
		second := events[i+1]

		// An event higher in causal sequence should not predate a previous essential step
		if first.Sequence < second.Sequence && second.CreatedAt.Before(first.CreatedAt) {
			diff := first.CreatedAt.Sub(second.CreatedAt)

			// Determine if impossible order or general inconsistency
			if first.Layer == evidence.LayerBuild && second.Layer == evidence.LayerArtifact {
				anomalies = append(anomalies, &TemporalAnomaly{
					Type:        AnomalyImpossibleOrder,
					Layer:       second.Layer,
					Subject:     fmt.Sprintf("%s vs %s", first.Name, second.Name),
					Description: fmt.Sprintf("IMPOSSIBLE ORDER: Artifact was created at %s, before compilation began at %s (delta: %s)", second.CreatedAt.Format(time.RFC3339), first.CreatedAt.Format(time.RFC3339), diff),
					Severity:    "CRITICAL",
					Delta:       diff,
				})
			} else if first.Layer == evidence.LayerDependencies && second.Layer == evidence.LayerArtifact {
				anomalies = append(anomalies, &TemporalAnomaly{
					Type:        AnomalyTemporalInconsistency,
					Layer:       second.Layer,
					Subject:     fmt.Sprintf("%s vs %s", first.Name, second.Name),
					Description: fmt.Sprintf("TEMPORAL INCONSISTENCY: Artifact was emitted before dependency resolution occurred (delta: %s)", diff),
					Severity:    "CRITICAL",
					Delta:       diff,
				})
			} else {
				anomalies = append(anomalies, &TemporalAnomaly{
					Type:        AnomalyTemporalInconsistency,
					Layer:       second.Layer,
					Subject:     fmt.Sprintf("%s vs %s", first.Name, second.Name),
					Description: fmt.Sprintf("Sequence anomaly: %s (%s) predates preceding step %s (%s)", second.Name, second.CreatedAt.Format(time.RFC3339), first.Name, first.CreatedAt.Format(time.RFC3339)),
					Severity:    "WARNING",
					Delta:       diff,
				})
			}
		}
	}

	return anomalies, len(anomalies) == 0
}
