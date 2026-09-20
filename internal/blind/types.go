package blind

import (
	"time"

	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/policy"
)

// DatasetSplit identifies the empirical partition for anti-leakage evaluation
type DatasetSplit string

const (
	SplitDevelopment DatasetSplit = "DEVELOPMENT (70%)"
	SplitValidation  DatasetSplit = "VALIDATION (15%)"
	SplitHoldout     DatasetSplit = "HOLDOUT (15%)"
)

// GroundTruthLabel defines the true security reality known only to the harness
type GroundTruthLabel string

const (
	LabelAttack GroundTruthLabel = "ATTACK"
	LabelBenign GroundTruthLabel = "BENIGN"
)

// BlindPayload contains pure, anonymized evidence stripped of all experiment metadata
type BlindPayload struct {
	Input  *correlation.CorrelationInput `json:"input"`
	Policy *policy.Policy                `json:"policy"`
}

// BlindVerdict encapsulates the detector's independent judgment
type BlindVerdict struct {
	Verdict            string           `json:"verdict"` // TRUSTED, WARNING, REJECTED
	EarliestTrustBreak evidence.Layer   `json:"earliestTrustBreak,omitempty"`
	ContradictionCount int              `json:"contradictionCount"`
	Reasons            []string         `json:"reasons"`
	DurationMicros     int64            `json:"durationMicros"`
	EvaluatedAt        time.Time        `json:"evaluatedAt"`
}

// GroundTruthRecord is held privately by the experiment harness
type GroundTruthRecord struct {
	PayloadID     int              `json:"payloadId"`
	Split         DatasetSplit     `json:"split"`
	TrueLabel     GroundTruthLabel `json:"trueLabel"`
	ExpectedLayer evidence.Layer   `json:"expectedLayer,omitempty"`
	AttackFamily  string           `json:"attackFamily"`
	Description   string           `json:"description"`
}

// ScoredTrial records the comparison between blind judgment and secret ground truth
type ScoredTrial struct {
	PayloadID          int              `json:"payloadId"`
	Split              DatasetSplit     `json:"split"`
	TrueLabel          GroundTruthLabel `json:"trueLabel"`
	PredictedVerdict   string           `json:"predictedVerdict"`
	PredictedBreak     evidence.Layer   `json:"predictedBreak"`
	ExpectedBreak      evidence.Layer   `json:"expectedBreak"`
	IsCorrect          bool             `json:"isCorrect"`
	LocalizationMatch  bool             `json:"localizationMatch"`
	LatencyMicros      int64            `json:"latencyMicros"`
}

// SplitMetrics records empirical statistics for a specific dataset partition
type SplitMetrics struct {
	Split                DatasetSplit `json:"split"`
	Total                int          `json:"total"`
	TruePositives        int          `json:"truePositives"`
	TrueNegatives        int          `json:"trueNegatives"`
	FalsePositives       int          `json:"falsePositives"`
	FalseNegatives       int          `json:"falseNegatives"`
	Precision            float64      `json:"precision"`
	Recall               float64      `json:"recall"`
	F1Score              float64      `json:"f1Score"`
	FalseAcceptanceRate  float64      `json:"falseAcceptanceRate"`
	FalseRejectionRate   float64      `json:"falseRejectionRate"`
	LocalizationAccuracy float64      `json:"localizationAccuracy"`
	MeanLatencyMicros    float64      `json:"meanLatencyMicros"`
}

// BlindEvaluationReport aggregates results across Dev, Validation, and Holdout partitions
type BlindEvaluationReport struct {
	TotalTrials     int                     `json:"totalTrials"`
	DevMetrics      *SplitMetrics           `json:"devMetrics"`
	ValMetrics      *SplitMetrics           `json:"valMetrics"`
	HoldoutMetrics  *SplitMetrics           `json:"holdoutMetrics"`
	OverallMetrics  *SplitMetrics           `json:"overallMetrics"`
	Trials          []*ScoredTrial          `json:"trials"`
}
