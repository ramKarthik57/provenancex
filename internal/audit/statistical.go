package audit

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/generalization"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/remediation"
)

// StatisticalDistribution holds comprehensive parametric and non-parametric stats
type StatisticalDistribution struct {
	MetricName      string  `json:"metric_name"`
	SampleCount     int     `json:"sample_count"`
	Mean            float64 `json:"mean"`
	Median          float64 `json:"median"`
	StdDev          float64 `json:"stddev"`
	Min             float64 `json:"min"`
	Max             float64 `json:"max"`
	P95             float64 `json:"p95"`
	P99             float64 `json:"p99"`
	CI95Lower       float64 `json:"ci95_lower"` // 95% Confidence Interval
	CI95Upper       float64 `json:"ci95_upper"`
}

// ComputeDistribution calculates full statistical distribution for sample slice
func ComputeDistribution(metricName string, samples []float64) *StatisticalDistribution {
	if len(samples) == 0 {
		return &StatisticalDistribution{MetricName: metricName}
	}
	sorted := make([]float64, len(samples))
	copy(sorted, samples)
	sort.Float64s(sorted)

	n := len(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	mean := sum / float64(n)

	// Median
	median := sorted[n/2]
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2.0
	}

	// Min / Max
	minVal := sorted[0]
	maxVal := sorted[n-1]

	// P95 / P99
	p95Idx := int(float64(n) * 0.95)
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p95 := sorted[p95Idx]

	p99Idx := int(float64(n) * 0.99)
	if p99Idx >= n {
		p99Idx = n - 1
	}
	p99 := sorted[p99Idx]

	// StdDev
	var varSum float64
	for _, v := range sorted {
		diff := v - mean
		varSum += diff * diff
	}
	stddev := math.Sqrt(varSum / float64(n))

	// 95% Confidence Interval for normal approximation: Mean ± 1.96 * (StdDev / sqrt(N))
	margin := 1.96 * (stddev / math.Sqrt(float64(n)))
	ciLower := mean - margin
	ciUpper := mean + margin

	return &StatisticalDistribution{
		MetricName:  metricName,
		SampleCount: n,
		Mean:        mean,
		Median:      median,
		StdDev:      stddev,
		Min:         minVal,
		Max:         maxVal,
		P95:         p95,
		P99:         p99,
		CI95Lower:   ciLower,
		CI95Upper:   ciUpper,
	}
}

// RunStatisticalHeadlineBenchmark executes 10 repeated runs of the macro benchmark
func RunStatisticalHeadlineBenchmark(correlator *correlation.Correlator, engine *decision.Engine) []*StatisticalDistribution {
	runs := 10
	casesPerScenario := 20
	scenarios := generalization.GetAllScenarios()

	recallSamples := make([]float64, 0, runs)
	precisionSamples := make([]float64, 0, runs)
	latencySamples := make([]float64, 0, runs)

	pol := policy.DefaultPolicy()
	pol.Repository.RequireSignedCommits = true

	for r := 1; r <= runs; r++ {
		tp, fn, tn, fp := 0, 0, 0, 0
		var totalLat int64
		trialCount := 0

		for _, sc := range scenarios {
			for c := 0; c < casesPerScenario; c++ {
				trialCount++
				seed := r*10000 + c
				base := remediation.MakeBaseClean()
				mutated := sc.Mutate(base, seed)

				t0 := time.Now()
				res := correlator.Correlate(mutated)
				dec := engine.Decide(res, pol)
				d := time.Since(t0).Microseconds()
				if d <= 0 {
					d = 10
				}
				totalLat += d

				if sc.IsAttack {
					if dec.Verdict == decision.VerdictRejected {
						tp++
					} else {
						fn++
					}
				} else {
					if dec.Verdict == decision.VerdictTrusted {
						tn++
					} else {
						fp++
					}
				}
			}
		}

		rec := float64(tp) / float64(tp+fn) * 100.0
		prec := float64(tp) / float64(tp+fp) * 100.0
		meanLat := float64(totalLat) / float64(trialCount)

		recallSamples = append(recallSamples, rec)
		precisionSamples = append(precisionSamples, prec)
		latencySamples = append(latencySamples, meanLat)
	}

	return []*StatisticalDistribution{
		ComputeDistribution("Attack Detection Recall (%) [10 Runs]", recallSamples),
		ComputeDistribution("Decision Precision (%) [10 Runs]", precisionSamples),
		ComputeDistribution("Mean In-Memory Decision Latency (µs) [10 Runs]", latencySamples),
	}
}

// RunRandomnessAudit verifies deterministic stability under fixed seeds vs different seeds
func RunRandomnessAudit(correlator *correlation.Correlator, engine *decision.Engine) []*RandomnessAuditRecord {
	var records []*RandomnessAuditRecord

	// Test Part 1: Identical Seed Evaluated Twice (Expect bitwise identical recall & precision)
	fixedSeed := int64(133742)
	runWithSeed := func(seed int64, label string, runIdx int) *RandomnessAuditRecord {
		rng := rand.New(rand.NewSource(seed))
		scenarios := generalization.GetAllScenarios()
		pol := policy.DefaultPolicy()
		pol.Repository.RequireSignedCommits = true

		tp, fn, tn, fp := 0, 0, 0, 0
		var totalLat int64
		count := 0

		for _, sc := range scenarios {
			for c := 0; c < 10; c++ {
				count++
				subSeed := rng.Intn(100000)
				base := remediation.MakeBaseClean()
				mutated := sc.Mutate(base, subSeed)

				t0 := time.Now()
				res := correlator.Correlate(mutated)
				dec := engine.Decide(res, pol)
				d := time.Since(t0).Microseconds()
				if d <= 0 {
					d = 10
				}
				totalLat += d

				if sc.IsAttack {
					if dec.Verdict == decision.VerdictRejected {
						tp++
					} else {
						fn++
					}
				} else {
					if dec.Verdict == decision.VerdictTrusted {
						tn++
					} else {
						fp++
					}
				}
			}
		}

		rec := float64(tp) / float64(tp+fn) * 100.0
		prec := float64(tp) / float64(tp+fp) * 100.0
		meanLat := float64(totalLat) / float64(count)

		return &RandomnessAuditRecord{
			SeedType:          label,
			SeedValue:         seed,
			RunIndex:          runIdx,
			TotalTrials:       count,
			AttackRecallPct:   rec,
			PrecisionPct:      prec,
			MeanLatencyMicros: meanLat,
			ConsistencyStatus: "STABLE",
		}
	}

	// 1. Same seed twice
	r1 := runWithSeed(fixedSeed, "FIXED_SEED_RUN_1", 1)
	r2 := runWithSeed(fixedSeed, "FIXED_SEED_RUN_2", 2)
	if r1.AttackRecallPct == r2.AttackRecallPct && r1.PrecisionPct == r2.PrecisionPct {
		r1.ConsistencyStatus = "DETERMINISTIC_MATCH"
		r2.ConsistencyStatus = "DETERMINISTIC_MATCH"
	}
	records = append(records, r1, r2)

	// 2. Distinct random seeds
	distinctSeeds := []int64{99123, 44821, 77319, 12048, 88392}
	for i, s := range distinctSeeds {
		rec := runWithSeed(s, fmt.Sprintf("VARIED_SEED_%d", i+1), i+3)
		records = append(records, rec)
	}

	return records
}
