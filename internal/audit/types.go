package audit

import (
	"time"
)

// RecomputedMetricRecord holds independently calculated classification metrics
type RecomputedMetricRecord struct {
	Partition            string  `json:"partition"`
	ScenarioID           string  `json:"scenario_id"`
	Category             string  `json:"category"`
	SubCategory          string  `json:"sub_category"`
	TotalTrials          int     `json:"total_trials"`
	TruePositives        int     `json:"true_positives"`
	FalseNegatives       int     `json:"false_negatives"`
	TrueNegatives        int     `json:"true_negatives"`
	FalsePositives       int     `json:"false_positives"`
	SumCheck             int     `json:"sum_check"` // TP + FN + TN + FP
	IsSumValid           bool    `json:"is_sum_valid"`
	RecallPct            float64 `json:"recall_pct"`
	PrecisionPct         float64 `json:"precision_pct"`
	F1Score              float64 `json:"f1_score"`
	FalseAcceptanceRate  float64 `json:"false_acceptance_rate_pct"` // FP / (FP + TN)
	FalseRejectionRate   float64 `json:"false_rejection_rate_pct"`  // FN / (TP + FN)
	SpecificityPct       float64 `json:"specificity_pct"`           // TN / (TN + FP)
	AccuracyPct          float64 `json:"accuracy_pct"`              // (TP + TN) / Total
	MeanLatencyMicros    float64 `json:"mean_latency_micros"`
}

// PerfStageRecord represents latency and throughput across pipeline stages
type PerfStageRecord struct {
	Benchmark          string  `json:"benchmark"`
	InputScale         int     `json:"input_scale"`
	ScaleLabel         string  `json:"scale_label"`
	Stage              string  `json:"stage"`
	MeasurementScope   string  `json:"measurement_scope"`
	MeanMicros         float64 `json:"mean_micros"`
	MedianMicros       float64 `json:"median_micros"`
	P95Micros          float64 `json:"p95_micros"`
	P99Micros          float64 `json:"p99_micros"`
	StdDevMicros       float64 `json:"stddev_micros"`
	ThroughputPerSec   float64 `json:"throughput_per_sec"`
	MemoryAllocatedKB  int64   `json:"memory_allocated_kb"`
	IsEndToEnd         bool    `json:"is_end_to_end"`
}

// DiskHashRecord compares memory-buffer vs disk-backed artifact hashing
type DiskHashRecord struct {
	SizeLabel          string  `json:"size_label"`
	SizeBytes          int64   `json:"size_bytes"`
	DiskCreationMicros int64   `json:"disk_creation_micros"`
	DiskReadMicros     int64   `json:"disk_read_micros"`
	MemoryHashMicros   int64   `json:"memory_hash_micros"`
	DiskStreamMicros   int64   `json:"disk_stream_micros"`
	TotalWallClockMs   float64 `json:"total_wall_clock_ms"`
	ThroughputDiskMBs  float64 `json:"throughput_disk_mbs"`
	ThroughputMemMBs   float64 `json:"throughput_mem_mbs"`
}

// EndToEndBuildRecord measures realistic build pipeline overhead
type EndToEndBuildRecord struct {
	BuildIteration       int     `json:"build_iteration"`
	ProjectName          string  `json:"project_name"`
	BaselineDurationMs   float64 `json:"baseline_duration_ms"`
	InstrumentedDurationMs float64 `json:"instrumented_duration_ms"`
	CollectionTimeMs     float64 `json:"collection_time_ms"`
	AnalysisTimeMs       float64 `json:"analysis_time_ms"`
	OverheadMs           float64 `json:"overhead_ms"`
	OverheadPercent      float64 `json:"overhead_percent"`
	Verdict              string  `json:"verdict"`
}

// AdversarialHuntRecord documents newly discovered adversarial edge cases or blind spots
type AdversarialHuntRecord struct {
	AttackID            string `json:"attack_id"`
	TargetLayer         string `json:"target_layer"`
	AttackVector        string `json:"attack_vector"`
	EvasionTechnique    string `json:"evasion_technique"`
	ObservedVerdict     string `json:"observed_verdict"`
	ExpectedVerdict     string `json:"expected_verdict"`
	IsDetected          bool   `json:"is_detected"`
	EarliestLayerCaught string `json:"earliest_layer_caught"`
	RootCauseLimitation string `json:"root_cause_limitation"`
}

// BenignHuntRecord documents benign operational variations and any false alarms
type BenignHuntRecord struct {
	VariationID         string `json:"variation_id"`
	Category            string `json:"category"`
	OperationalScenario string `json:"operational_scenario"`
	ObservedVerdict     string `json:"observed_verdict"`
	ExpectedVerdict     string `json:"expected_verdict"`
	IsFalsePositive     bool   `json:"is_false_positive"`
	TriggeredRule       string `json:"triggered_rule,omitempty"`
	Analysis            string `json:"analysis"`
}

// HoldoutRecord evaluates frozen detector on blinded 70/15/15 partitions
type HoldoutRecord struct {
	Partition       string  `json:"partition"`
	TotalCases      int     `json:"total_cases"`
	AttackCases     int     `json:"attack_cases"`
	BenignCases     int     `json:"benign_cases"`
	TruePositives   int     `json:"true_positives"`
	FalseNegatives  int     `json:"false_negatives"`
	TrueNegatives   int     `json:"true_negatives"`
	FalsePositives  int     `json:"false_positives"`
	RecallPct       float64 `json:"recall_pct"`
	PrecisionPct    float64 `json:"precision_pct"`
	F1Score         float64 `json:"f1_score"`
}

// RandomnessAuditRecord documents stability under fixed vs varying seeds
type RandomnessAuditRecord struct {
	SeedType            string  `json:"seed_type"`
	SeedValue           int64   `json:"seed_value"`
	RunIndex            int     `json:"run_index"`
	TotalTrials         int     `json:"total_trials"`
	AttackRecallPct     float64 `json:"attack_recall_pct"`
	PrecisionPct        float64 `json:"precision_pct"`
	MeanLatencyMicros   float64 `json:"mean_latency_micros"`
	ConsistencyStatus   string  `json:"consistency_status"`
}

// Day15Manifest encapsulates audit metadata and provenance hashes
type Day15Manifest struct {
	Timestamp           time.Time `json:"timestamp"`
	GitCommit           string    `json:"git_commit"`
	OS                  string    `json:"os"`
	Architecture        string    `json:"architecture"`
	GoVersion           string    `json:"go_version"`
	AuditScope          string    `json:"audit_scope"`
	TotalAuditedTrials  int       `json:"total_audited_trials"`
	ConfigurationHash   string    `json:"configuration_hash"`
	ResearchIntegrityNotice string `json:"research_integrity_notice"`
}
