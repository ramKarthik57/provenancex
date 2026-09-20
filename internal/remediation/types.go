package remediation

import (
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/blind"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/execution"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/sbom"
	"github.com/ramKarthik57/provenancex/internal/signature"
)

// MakeBaseClean generates a verified baseline evidence bundle
func MakeBaseClean() *correlation.CorrelationInput {
	artHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	return &correlation.CorrelationInput{
		Repository: &repository.State{
			Branch:         "main",
			CommitSHA:      "c0ffee1234567890abcdef1234567890abcdef12",
			Author:         "Release Bot <release@provenancex.dev>",
			AuthorEmail:    "release@provenancex.dev",
			IsClean:        true,
			UntrackedFiles: []string{},
			ModifiedFiles:  []string{},
			SignatureInfo: &repository.CommitSignatureInfo{
				Status:         repository.CommitSignatureSignedAndValid,
				SignerKeyID:    "4A8B9C0D1E2F3A4B",
				SignerIdentity: "Release Bot <release@provenancex.dev>",
				Committer:      "Release Bot <release@provenancex.dev>",
				CommitterEmail: "release@provenancex.dev",
			},
		},
		Dependencies: &dependency.Report{
			DirectCount:  1,
			HasLockfile:  true,
			IsConsistent: true,
			Dependencies: []*dependency.Dependency{
				{Name: "cryptography", Version: "42.0.5", Ecosystem: dependency.EcosystemPython},
			},
			Mismatches: []*dependency.Mismatch{},
		},
		Environment: &environment.Fingerprint{
			OS:              "linux",
			Architecture:    "amd64",
			EnvironmentVars: map[string]string{"WORKSPACE": "/build/workspace"},
			FingerprintHash: "f107e32400000000000000000000000000000000000000000000000000000000",
		},
		Execution: &execution.StageExecution{
			Name:     "build",
			Success:  true,
			ExitCode: 0,
			Duration: 2 * time.Second,
		},
		ProcessTree: &process.Tree{
			SuspiciousCount: 0,
			Processes: []*process.ProcessNode{
				{PID: 1001, Name: "go", CommandLine: "go build -o app", IsSuspicious: false},
			},
		},
		InputEvaluation: &filesystem.InputEvaluation{
			UnexpectedInputs:    []string{},
			MissingInputs:       []string{},
			OutOfBoundaryWrites: []string{},
		},
		NetworkAudit: &network.Evaluation{
			TotalConnections:  1,
			ViolationCount:    0,
			IsPolicyCompliant: true,
			Violations:        []*network.ConnectionRecord{},
			DNSQueries:        []*network.DNSQueryRecord{},
		},
		Artifact: &artifact.Metadata{
			Name:   "production-app",
			SHA256: artHash,
			Size:   2048,
		},
		SBOM: &sbom.Document{
			Format:  sbom.FormatCycloneDX,
			Version: "1.5",
			Components: []*sbom.Component{
				{Name: "cryptography", Version: "42.0.5"},
			},
		},
		Provenance: &provenance.InTotoStatement{
			Type:          provenance.InTotoStatementV1,
			PredicateType: provenance.SLSAProvenanceV1,
			Subject: []provenance.Subject{
				{
					Name:   "production-app",
					Digest: map[string]string{"sha256": artHash},
				},
			},
			Predicate: provenance.SLSAv1Predicate{
				RunDetails: provenance.RunDetails{
					Builder: provenance.BuilderMetadata{ID: "https://provenancex.dev/builder/isolated-runner@v1"},
				},
			},
		},
		Signature: &signature.VerificationResult{
			Valid:     true,
			Algorithm: signature.AlgoECDSAP256,
		},
	}
}

// RemediationMode defines whether evaluation is baseline (Day 12) or remediated (Day 13)
type RemediationMode string

const (
	ModePreRemediation  RemediationMode = "PRE_REMEDIATION"
	ModePostRemediation RemediationMode = "POST_REMEDIATION"
)

// ObservationStatus tracks evidence visibility
type ObservationStatus string

const (
	Observed          ObservationStatus = "OBSERVED"
	Unobserved        ObservationStatus = "UNOBSERVED"
	PartiallyObserved ObservationStatus = "PARTIALLY_OBSERVED"
)

// DetectionStatus tracks detector verdict
type DetectionStatus string

const (
	Detected DetectionStatus = "DETECTED"
	Missed   DetectionStatus = "MISSED"
)

// TrialRecord stores granular trial-level data for Day 13 experiments
type TrialRecord struct {
	RunIndex         int                    `json:"runIndex"`
	TrialIndex       int                    `json:"trialIndex"`
	Mode             RemediationMode        `json:"mode"`
	Family           string                 `json:"family"`
	SubCase          string                 `json:"subCase"`
	TrueLabel        blind.GroundTruthLabel `json:"trueLabel"`
	Observation      ObservationStatus      `json:"observation"`
	PredictedVerdict string                 `json:"predictedVerdict"`
	PredictedBreak   evidence.Layer         `json:"predictedBreak"`
	ExpectedBreak    evidence.Layer         `json:"expectedBreak"`
	Detection        DetectionStatus        `json:"detection"`
	IsCorrect        bool                   `json:"isCorrect"`
	LatencyMicros    int64                  `json:"latencyMicros"`
}

// FamilyComparison summarizes pre vs post remediation metrics for a family
type FamilyComparison struct {
	Family            string  `json:"family"`
	PreN              int     `json:"preN"`
	PreTP             int     `json:"preTP"`
	PreFN             int     `json:"preFN"`
	PreRecall         float64 `json:"preRecall"`
	PostN             int     `json:"postN"`
	PostTP            int     `json:"postTP"`
	PostFN            int     `json:"postFN"`
	PostRecall        float64 `json:"postRecall"`
	DeltaRecall       float64 `json:"deltaRecall"`
	ObservationStatus string  `json:"observationStatus"`
	Limitation        string  `json:"limitation"`
}

// LifetimeEvaluationRecord stores data for process lifetime benchmark
type LifetimeEvaluationRecord struct {
	LifetimeRange    string  `json:"lifetimeRange"`
	PollingObserved  string  `json:"pollingObserved"`
	ETWObserved      string  `json:"etwObserved"`
	PollingDetection string  `json:"pollingDetection"`
	ETWDetection     string  `json:"etwDetection"`
	PollingLatencyUs float64 `json:"pollingLatencyUs"`
	ETWLatencyUs     float64 `json:"etwLatencyUs"`
}

// FilesystemLocationRecord stores data for filesystem boundary evaluation
type FilesystemLocationRecord struct {
	LocationClass     string `json:"locationClass"`
	PathExample       string `json:"pathExample"`
	ObservedWorkspace string `json:"observedWorkspace"`
	ObservedExpanded  string `json:"observedExpanded"`
	Attributed        string `json:"attributed"`
	Detected          string `json:"detected"`
	Limitation        string `json:"limitation"`
}

// NetworkTrafficRecord stores data for UDP/DNS telemetry evaluation
type NetworkTrafficRecord struct {
	TrafficType      string `json:"trafficType"`
	PollingVisible   string `json:"pollingVisible"`
	DNSTelemetry     string `json:"dnsTelemetry"`
	NetworkIsolation string `json:"networkIsolation"`
	Detected         string `json:"detected"`
	Limitation       string `json:"limitation"`
}

// AblationRecord records accuracy under specific capability omissions
type AblationRecord struct {
	Configuration  string  `json:"configuration"`
	Recall         float64 `json:"recall"`
	Precision      float64 `json:"precision"`
	F1Score        float64 `json:"f1Score"`
	IdentifiedGaps int     `json:"identifiedGaps"`
	Note           string  `json:"note"`
}

// Manifest captures experiment metadata for scientific reproducibility
type Manifest struct {
	Timestamp          time.Time `json:"timestamp"`
	GitCommit          string    `json:"gitCommit"`
	OSVersion          string    `json:"osVersion"`
	GoVersion          string    `json:"goVersion"`
	Architecture       string    `json:"architecture"`
	IsElevated         bool      `json:"isElevated"`
	Runs               int       `json:"runs"`
	CasesPerFamily     int       `json:"casesPerFamily"`
	TelemetryActive    string    `json:"telemetryActive"`
	ConfigurationHash  string    `json:"configurationHash"`
	ExperimentNotice   string    `json:"experimentNotice"`
}
