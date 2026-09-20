package experiment

import (
	"context"
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// Scenario represents an isolated supply chain attack experiment
type Scenario struct {
	ID                 string
	Name               string
	Category           string
	Description        string
	TargetLayer        evidence.Layer
	ExpectedVerdict    string
	ExpectedBreakLayer evidence.Layer
	Simulate           func(ctx context.Context) (*correlation.CorrelationInput, error)
}

// ScenarioResult records the outcome of a single simulated attack
type ScenarioResult struct {
	ScenarioID          string         `json:"scenarioId"`
	ScenarioName        string         `json:"scenarioName"`
	Category            string         `json:"category"`
	TargetLayer         evidence.Layer `json:"targetLayer"`
	Detected            bool           `json:"detected"`
	Verdict             string         `json:"verdict"`
	ExpectedVerdict     string         `json:"expectedVerdict"`
	VerdictMatched      bool           `json:"verdictMatched"`
	LocalizedLayer      evidence.Layer `json:"localizedLayer"`
	ExpectedBreakLayer  evidence.Layer `json:"expectedBreakLayer"`
	LocalizationMatched bool           `json:"localizationMatched"`
	Reason              string         `json:"reason"`
	DurationMs          int64          `json:"durationMs"`
}

// BenchmarkReport summarizes the empirical evaluation across all attack scenarios
type BenchmarkReport struct {
	TotalScenarios         int              `json:"totalScenarios"`
	DetectedAttacks        int              `json:"detectedAttacks"`
	DetectionRatePercent   float64          `json:"detectionRatePercent"`
	LocalizationAccPercent float64          `json:"localizationAccPercent"`
	AverageLatencyMs       float64          `json:"averageLatencyMs"`
	TotalDurationMs        int64            `json:"totalDurationMs"`
	ExecutedAt             time.Time        `json:"executedAt"`
	Results                []ScenarioResult `json:"results"`
}
