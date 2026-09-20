package day17

import "time"

// ConfusionMatrixAuditRow stores recomputed metrics for an evaluated dataset
type ConfusionMatrixAuditRow struct {
	DatasetName    string  `json:"dataset_name"`
	Category       string  `json:"category"`
	TotalTrials    int     `json:"total_trials"`
	TruePositives  int     `json:"true_positives"`
	FalseNegatives int     `json:"false_negatives"`
	TrueNegatives  int     `json:"true_negatives"`
	FalsePositives int     `json:"false_positives"`
	SumCheck       int     `json:"sum_check"` // TP + FN + TN + FP
	SumCheckValid  bool    `json:"sum_check_valid"`
	PrecisionPct   float64 `json:"precision_pct"`
	RecallPct      float64 `json:"recall_pct"`
	SpecificityPct float64 `json:"specificity_pct"`
	F1Score        float64 `json:"f1_score"`
	FAR            float64 `json:"far_pct"` // False Acceptance Rate: FP / (FP + TN)
	FRR            float64 `json:"frr_pct"` // False Rejection Rate: FN / (TP + FN)
	AuditStatus    string  `json:"audit_status"`
}

// ClaimInventoryRow represents an audited research claim with bounded classification
type ClaimInventoryRow struct {
	ClaimID                string `json:"claim_id"`
	ClaimShortName         string `json:"claim_short_name"`
	TargetLayer            string `json:"target_layer"`
	OriginalClaimStatement string `json:"original_claim_statement"`
	AuditedClassification  string `json:"audited_classification"` // VALIDATED, PARTIALLY_VALIDATED, BOUNDED, UNSUPPORTED, CONTRADICTED
	OperationalBoundary    string `json:"operational_boundary"`
	DemonstratedFailure    string `json:"demonstrated_failure_condition"`
	EmpiricalEvidenceRef   string `json:"empirical_evidence_ref"`
}

// BenchmarkScopeRow disentangles algorithmic micro-benchmarks from physical builds
type BenchmarkScopeRow struct {
	BenchmarkID                string `json:"benchmark_id"`
	BenchmarkName              string `json:"benchmark_name"`
	SubsystemMeasured          string `json:"subsystem_measured"`
	ExecutionEnvironment      string `json:"execution_environment"`
	HardwareOrSynthetic        string `json:"hardware_or_synthetic"`
	PureAlgorithmicVsEndToEnd  string `json:"pure_algorithmic_vs_end_to_end"`
	MetricReported             string `json:"metric_reported"`
	DisentangledInterpretation string `json:"disentangled_interpretation"`
}

// ObservabilityAuditRow logs telemetry capabilities across privilege tiers
type ObservabilityAuditRow struct {
	TelemetrySubsystem          string  `json:"telemetry_subsystem"`
	Mechanism                   string  `json:"mechanism"`
	ExecutionPrivilege          string  `json:"execution_privilege"`
	EphemeralThresholdMs        float64 `json:"ephemeral_threshold_ms"`
	CatchRateTestedPct          float64 `json:"catch_rate_tested_pct"`
	LimitationDiscovered        string  `json:"limitation_discovered"`
	RemediationOrResidualStatus string  `json:"remediation_or_residual_status"`
}

// OfflineVerifierAuditRow validates air-gapped standalone verification under tampering
type OfflineVerifierAuditRow struct {
	TestCaseID             string `json:"test_case_id"`
	TestDescription        string `json:"test_description"`
	BundleState            string `json:"bundle_state"`
	ExpectedVerdict        string `json:"expected_verdict"`
	ObservedVerdict        string `json:"observed_verdict"`
	NetworkEgressAttempted bool   `json:"network_egress_attempted"`
	TamperDetected         bool   `json:"tamper_detected"`
	AuditStatus            string `json:"audit_status"`
}

// ScorecardRow evaluates a research dimension for publication readiness
type ScorecardRow struct {
	Category                  string `json:"category"`
	TargetSubsystem           string `json:"target_subsystem"`
	AuditResult               string `json:"audit_result"` // PASS, PASS_WITH_LIMITATION, REQUIRES_REVISION, FAIL
	KeyLimitationIdentified   string `json:"key_limitation_identified"`
	PublicationRecommendation string `json:"publication_recommendation"`
}

// EnvironmentMetadata records complete execution environment details
type EnvironmentMetadata struct {
	HostArchitecture               string    `json:"host_architecture"`
	OperatingSystem                string    `json:"operating_system"`
	KernelVersion                  string    `json:"kernel_version"`
	CPUModel                       string    `json:"cpu_model"`
	LogicalCores                   int       `json:"logical_cores"`
	GoVersion                      string    `json:"go_version"`
	GitCommit                      string    `json:"git_commit"`
	GitBranch                      string    `json:"git_branch"`
	WorkingTreeClean               bool      `json:"working_tree_clean"`
	AuditExecutionTimestamp        time.Time `json:"audit_execution_timestamp"`
	HistoricalBaselinesFrozenCount int       `json:"historical_baselines_frozen_count"`
}

// Day17AuditReport aggregates all Day 17 audit outcomes
type Day17AuditReport struct {
	ConfusionMatrixAudit []*ConfusionMatrixAuditRow `json:"confusion_matrix_audit"`
	ClaimInventory       []*ClaimInventoryRow       `json:"claim_inventory"`
	BenchmarkScopes      []*BenchmarkScopeRow       `json:"benchmark_scopes"`
	ObservabilityAudit   []*ObservabilityAuditRow   `json:"observability_audit"`
	OfflineVerifierAudit []*OfflineVerifierAuditRow `json:"offline_verifier_audit"`
	Scorecard            []*ScorecardRow            `json:"scorecard"`
	Environment          *EnvironmentMetadata       `json:"environment"`
	DataLeakageSummary   string                     `json:"data_leakage_summary"`
	ReproductionSummary  string                     `json:"reproduction_summary"`
}
