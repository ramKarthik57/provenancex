package generalization

import (
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
)

// ScenarioCategory distinguishes between unseen attack variants, composed attacks, and benign variations
type ScenarioCategory string

const (
	CategoryUnseenAttack      ScenarioCategory = "UNSEEN_ATTACK"
	CategoryComposedAttack    ScenarioCategory = "COMPOSED_ATTACK"
	CategoryBenignVariability ScenarioCategory = "BENIGN_VARIABILITY"
)

// DetectionResult indicates detection outcome
type DetectionResult string

const (
	Detected      DetectionResult = "DETECTED"
	Missed        DetectionResult = "MISSED"
	TrueNegative  DetectionResult = "TRUE_NEGATIVE"
	FalsePositive DetectionResult = "FALSE_POSITIVE"
)

// Scenario defines an evaluation case in the generalization benchmark
type Scenario struct {
	ID              string
	Category        ScenarioCategory
	SubCategory     string
	Description     string
	IsAttack        bool
	ExpectedVerdict string
	ExpectedLayer   evidence.Layer
	Mutate          func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput
}

// TrialResult records the outcome of a single trial
type TrialResult struct {
	RunIndex         int              `json:"run_index"`
	TrialIndex       int              `json:"trial_index"`
	ScenarioID       string           `json:"scenario_id"`
	Category         ScenarioCategory `json:"category"`
	SubCategory      string           `json:"sub_category"`
	IsAttack         bool             `json:"is_attack"`
	TrueLabel        string           `json:"true_label"`
	PredictedVerdict string           `json:"predicted_verdict"`
	Detection        DetectionResult  `json:"detection"`
	ExpectedLayer    evidence.Layer   `json:"expected_layer"`
	IdentifiedLayer  evidence.Layer   `json:"identified_layer"`
	VerdictCorrect   bool             `json:"verdict_correct"`
	LayerCorrect     bool             `json:"layer_correct"`
	LatencyMicros    int64            `json:"latency_micros"`
	ContradictionMsg string           `json:"contradiction_msg,omitempty"`
}

// GeneralizationSummary holds aggregated metrics for a scenario
type GeneralizationSummary struct {
	ScenarioID           string           `json:"scenario_id"`
	Category             ScenarioCategory `json:"category"`
	SubCategory          string           `json:"sub_category"`
	IsAttack             bool             `json:"is_attack"`
	TotalTrials          int              `json:"total_trials"`
	TruePositives        int              `json:"true_positives"`
	FalseNegatives       int              `json:"false_negatives"`
	TrueNegatives        int              `json:"true_negatives"`
	FalsePositives       int              `json:"false_positives"`
	RecallPct            float64          `json:"recall_pct"`
	PrecisionPct         float64          `json:"precision_pct"`
	F1Score              float64          `json:"f1_score"`
	LocalizationAccuracy float64          `json:"localization_accuracy"`
	MeanLatencyMicros    float64          `json:"mean_latency_micros"`
}

// ArtifactScalingResult measures scaling across artifact sizes
type ArtifactScalingResult struct {
	SizeBytes              int64   `json:"size_bytes"`
	SizeLabel              string  `json:"size_label"`
	HashLatencyMicros      int64   `json:"hash_latency_micros"`
	StreamingThroughputMBs float64 `json:"streaming_throughput_mbs"`
	MerkleBuildMicros      int64   `json:"merkle_build_micros"`
}

// DependencyScalingResult measures scaling across dependency graph size
type DependencyScalingResult struct {
	DependencyCount         int   `json:"dependency_count"`
	ParseLatencyMicros      int64 `json:"parse_latency_micros"`
	TraversalLatencyMicros  int64 `json:"traversal_latency_micros"`
	CycleCheckLatencyMicros int64 `json:"cycle_check_latency_micros"`
	TotalResolutionMicros   int64 `json:"total_resolution_micros"`
}

// EvidenceScalingResult measures scaling across evidence telemetry volumes
type EvidenceScalingResult struct {
	EventCount                int     `json:"event_count"`
	ProcessEvents             int     `json:"process_events"`
	FilesystemEvents          int     `json:"filesystem_events"`
	NetworkEvents             int     `json:"network_events"`
	IngestionLatencyMicros    int64   `json:"ingestion_latency_micros"`
	CorrelationLatencyMicros  int64   `json:"correlation_latency_micros"`
	ThroughputEventsPerSecond float64 `json:"throughput_events_per_sec"`
	AllocatedMemoryKB         int64   `json:"allocated_memory_kb"`
}

// GraphScalingResult measures scaling on the Trust Graph 2.0 DAG
type GraphScalingResult struct {
	NodeCount               int   `json:"node_count"`
	EdgeCount               int   `json:"edge_count"`
	BuildLatencyMicros      int64 `json:"build_latency_micros"`
	RootCauseQueryMicros    int64 `json:"root_cause_query_micros"`
	ReachabilityCheckMicros int64 `json:"reachability_check_micros"`
	SubtreeExtractMicros    int64 `json:"subtree_extract_micros"`
}

// ConcurrencyResult measures thread safety and throughput across parallel builds
type ConcurrencyResult struct {
	ConcurrentWorkers          int     `json:"concurrent_workers"`
	CompletedBuilds            int     `json:"completed_builds"`
	TotalDurationMs            int64   `json:"total_duration_ms"`
	ThroughputBuildsPerSec     float64 `json:"throughput_builds_per_sec"`
	MeanLatencyMicros          float64 `json:"mean_latency_micros"`
	P99LatencyMicros           float64 `json:"p99_latency_micros"`
	CrossContaminationDetected bool    `json:"cross_contamination_detected"`
}

// BaselineComparisonRecord compares Day 12, Day 13, and Day 14 metrics
type BaselineComparisonRecord struct {
	Milestone               string  `json:"milestone"`
	EvaluatedTrials         int     `json:"evaluated_trials"`
	AttackFamilies          int     `json:"attack_families"`
	BenignFamilies          int     `json:"benign_families"`
	OverallRecallPct        float64 `json:"overall_recall_pct"`
	PrecisionPct            float64 `json:"precision_pct"`
	F1Score                 float64 `json:"f1_score"`
	MeanLatencyMicros       float64 `json:"mean_latency_micros"`
	DemonstratedBlindSpots  int     `json:"demonstrated_blind_spots"`
	KeyArchitecturalAdvance string  `json:"key_advance"`
}

// Day14Manifest records complete experimental metadata
type Day14Manifest struct {
	Timestamp            time.Time `json:"timestamp"`
	GitCommit            string    `json:"git_commit"`
	OS                   string    `json:"os"`
	Architecture         string    `json:"architecture"`
	GoVersion            string    `json:"go_version"`
	Runs                 int       `json:"runs"`
	CasesPerScenario     int       `json:"cases_per_scenario"`
	TotalScenarios       int       `json:"total_scenarios"`
	TotalEvaluatedTrials int       `json:"total_evaluated_trials"`
	ConfigurationHash    string    `json:"configuration_hash"`
	ExperimentNotice     string    `json:"experiment_notice"`
}
