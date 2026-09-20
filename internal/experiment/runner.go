package experiment

import (
	"context"
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/localization"
	"github.com/ramKarthik57/provenancex/internal/policy"
)

// Runner executes supply chain attack experiments and tabulates empirical metrics
type Runner struct {
	correlator *correlation.Correlator
	localizer  *localization.Localizer
	engine     *decision.Engine
	policy     *policy.Policy
}

// NewRunner constructs an experiment runner
func NewRunner(pol *policy.Policy) *Runner {
	if pol == nil {
		pol = policy.DefaultPolicy()
	}
	return &Runner{
		correlator: correlation.NewCorrelator(),
		localizer:  localization.NewLocalizer(),
		engine:     decision.NewEngine(),
		policy:     pol,
	}
}

// RunScenario executes a single simulated supply chain attack and evaluates verification performance
func (r *Runner) RunScenario(ctx context.Context, s Scenario) (*ScenarioResult, error) {
	start := time.Now()

	input, err := s.Simulate(ctx)
	if err != nil {
		return nil, fmt.Errorf("scenario simulation failed: %w", err)
	}

	corrRes := r.correlator.Correlate(input)
	trustBreak := r.localizer.Localize(corrRes)
	dec := r.engine.Decide(corrRes, r.policy)

	duration := time.Since(start).Milliseconds()

	res := &ScenarioResult{
		ScenarioID:         s.ID,
		ScenarioName:       s.Name,
		Category:           s.Category,
		TargetLayer:        s.TargetLayer,
		Verdict:            string(dec.Verdict),
		ExpectedVerdict:    s.ExpectedVerdict,
		ExpectedBreakLayer: s.ExpectedBreakLayer,
		DurationMs:         duration,
	}

	// Detection logic: Was the attack flagged?
	if dec.Verdict != decision.VerdictTrusted || trustBreak.HasTrustBreak {
		res.Detected = true
	}

	res.VerdictMatched = (res.Verdict == s.ExpectedVerdict)

	if trustBreak.HasTrustBreak {
		res.LocalizedLayer = trustBreak.EarliestLayer
		res.LocalizationMatched = (trustBreak.EarliestLayer == s.ExpectedBreakLayer)
		res.Reason = trustBreak.Reason
	} else {
		if len(dec.Warnings) > 0 {
			res.Reason = dec.Warnings[0]
		}
	}

	return res, nil
}

// RunAll executes all provided scenarios and aggregates benchmark metrics
func (r *Runner) RunAll(ctx context.Context, scenarios []Scenario) (*BenchmarkReport, error) {
	if len(scenarios) == 0 {
		scenarios = DefaultScenarios()
	}

	startTime := time.Now()
	report := &BenchmarkReport{
		TotalScenarios: len(scenarios),
		Results:        make([]ScenarioResult, 0, len(scenarios)),
		ExecutedAt:     startTime,
	}

	var totalLatency int64
	correctLocalizations := 0

	for _, s := range scenarios {
		res, err := r.RunScenario(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("error running scenario %s: %w", s.ID, err)
		}

		if res.Detected {
			report.DetectedAttacks++
		}
		if res.LocalizationMatched {
			correctLocalizations++
		}
		totalLatency += res.DurationMs
		report.Results = append(report.Results, *res)
	}

	if report.TotalScenarios > 0 {
		report.DetectionRatePercent = (float64(report.DetectedAttacks) / float64(report.TotalScenarios)) * 100.0
		report.LocalizationAccPercent = (float64(correctLocalizations) / float64(report.TotalScenarios)) * 100.0
		report.AverageLatencyMs = float64(totalLatency) / float64(report.TotalScenarios)
	}
	report.TotalDurationMs = time.Since(startTime).Milliseconds()

	return report, nil
}
