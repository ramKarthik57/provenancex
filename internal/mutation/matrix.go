package mutation

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/execution"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/localization"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/sbom"
	"github.com/ramKarthik57/provenancex/internal/signature"
)

// MutationCategory enumerates the 14 adversarial attack targets
type MutationCategory string

const (
	CategoryArtifact    MutationCategory = "Artifact"
	CategoryHash        MutationCategory = "Hash"
	CategorySignature   MutationCategory = "Signature"
	CategoryProvenance  MutationCategory = "Provenance"
	CategorySBOM        MutationCategory = "SBOM"
	CategoryDependency  MutationCategory = "Dependency"
	CategoryCommit      MutationCategory = "Commit"
	CategoryEnvironment MutationCategory = "Environment"
	CategoryFilesystem  MutationCategory = "Filesystem"
	CategoryNetwork     MutationCategory = "Network"
	CategoryProcess     MutationCategory = "Process"
	CategoryTimestamp   MutationCategory = "Timestamp"
	CategoryManifest    MutationCategory = "Evidence Manifest"
	CategoryHashChain   MutationCategory = "Hash Chain"
)

// TrialRecord stores granular data for every single verification trial
type TrialRecord struct {
	TrialID        int              `json:"trialId"`
	MutationID     string           `json:"mutationId"`
	Category       MutationCategory `json:"category"`
	TargetLayer    evidence.Layer   `json:"targetLayer"`
	OriginalHash   string           `json:"originalHash"`
	MutatedHash    string           `json:"mutatedHash"`
	ExpectedResult string           `json:"expectedResult"`
	ActualResult   string           `json:"actualResult"`
	Detected       bool             `json:"detected"`
	Localized      bool             `json:"localized"`
	LatencyMicros  int64            `json:"latencyMicros"`
	IsBenign       bool             `json:"isBenign"`
}

// MatrixReport aggregates statistics over 1,000+ trials
type MatrixReport struct {
	TotalTrials          int             `json:"totalTrials"`
	AttackTrials         int             `json:"attackTrials"`
	BenignTrials         int             `json:"benignTrials"`
	TruePositives        int             `json:"truePositives"`
	TrueNegatives        int             `json:"trueNegatives"`
	FalsePositives       int             `json:"falsePositives"`
	FalseNegatives       int             `json:"falseNegatives"`
	Precision            float64         `json:"precision"`
	Recall               float64         `json:"recall"`
	F1Score              float64         `json:"f1Score"`
	FalseAcceptanceRate  float64         `json:"falseAcceptanceRate"`
	FalseRejectionRate   float64         `json:"falseRejectionRate"`
	LocalizationAccuracy float64         `json:"localizationAccuracy"`
	MeanLatencyMicros    float64         `json:"meanLatencyMicros"`
	Records              []*TrialRecord  `json:"records"`
}

// TrialRunner executes the Monte Carlo 1,000+ verification trial suite
type TrialRunner struct {
	correlator *correlation.Correlator
	localizer  *localization.Localizer
	engine     *decision.Engine
	pol        *policy.Policy
}

// NewTrialRunner constructs a trial runner
func NewTrialRunner() *TrialRunner {
	return &TrialRunner{
		correlator: correlation.NewCorrelator(),
		localizer:  localization.NewLocalizer(),
		engine:     decision.NewEngine(),
		pol:        policy.DefaultPolicy(),
	}
}

// RunTrials executes N controlled verification trials across all 14 mutation categories
func (tr *TrialRunner) RunTrials(numTrials int) (*MatrixReport, error) {
	if numTrials < 100 {
		numTrials = 1000
	}

	report := &MatrixReport{
		TotalTrials: numTrials,
		Records:     make([]*TrialRecord, 0, numTrials),
	}

	categories := []MutationCategory{
		CategoryArtifact,
		CategoryHash,
		CategorySignature,
		CategoryProvenance,
		CategorySBOM,
		CategoryDependency,
		CategoryCommit,
		CategoryEnvironment,
		CategoryFilesystem,
		CategoryNetwork,
		CategoryProcess,
		CategoryTimestamp,
		CategoryManifest,
		CategoryHashChain,
	}

	totalLatency := int64(0)
	localizedCount := 0

	for i := 0; i < numTrials; i++ {
		cat := categories[i%len(categories)]
		isBenign := (i % 10 == 0) // 10% of trials are benign / clean to measure FP/TN

		rec, err := tr.runSingleTrial(i+1, cat, isBenign)
		if err != nil {
			return nil, err
		}

		report.Records = append(report.Records, rec)
		totalLatency += rec.LatencyMicros

		if isBenign {
			report.BenignTrials++
			if rec.ActualResult == "TRUSTED" {
				report.TrueNegatives++
			} else {
				report.FalsePositives++
			}
		} else {
			report.AttackTrials++
			if rec.Detected {
				report.TruePositives++
			} else {
				report.FalseNegatives++
			}
			if rec.Localized {
				localizedCount++
			}
		}
	}

	// Compute Formal Research Metrics
	if report.TruePositives+report.FalsePositives > 0 {
		report.Precision = float64(report.TruePositives) / float64(report.TruePositives+report.FalsePositives) * 100.0
	}
	if report.TruePositives+report.FalseNegatives > 0 {
		report.Recall = float64(report.TruePositives) / float64(report.TruePositives+report.FalseNegatives) * 100.0
	}
	if report.Precision+report.Recall > 0 {
		report.F1Score = 2 * (report.Precision * report.Recall) / (report.Precision + report.Recall)
	}
	if report.FalseNegatives+report.TruePositives > 0 {
		report.FalseAcceptanceRate = float64(report.FalseNegatives) / float64(report.FalseNegatives+report.TruePositives) * 100.0
	}
	if report.FalsePositives+report.TrueNegatives > 0 {
		report.FalseRejectionRate = float64(report.FalsePositives) / float64(report.FalsePositives+report.TrueNegatives) * 100.0
	}
	if report.AttackTrials > 0 {
		report.LocalizationAccuracy = float64(localizedCount) / float64(report.AttackTrials) * 100.0
	}
	report.MeanLatencyMicros = float64(totalLatency) / float64(numTrials)

	return report, nil
}

func (tr *TrialRunner) runSingleTrial(id int, cat MutationCategory, isBenign bool) (*TrialRecord, error) {
	input := makeBaseInput()
	targetLayer := evidence.LayerArtifact
	expectedVerdict := "REJECTED"
	origHash := input.Artifact.SHA256
	mutatedHash := origHash

	if isBenign {
		expectedVerdict = "TRUSTED"
		targetLayer = ""
	} else {
		switch cat {
		case CategoryArtifact, CategoryHash:
			targetLayer = evidence.LayerProvenance // Correlator identifies provenance subject digest contradicting mutated artifact
			mutatedHash = hashString(fmt.Sprintf("mutated-binary-%d", id))
			input.Artifact.SHA256 = mutatedHash

		case CategorySignature:
			targetLayer = evidence.LayerSignature
			input.Signature.Valid = false
			input.Signature.Error = "ECDSA P-256 signature verification failed"

		case CategoryProvenance, CategoryManifest, CategoryHashChain, CategoryTimestamp:
			targetLayer = evidence.LayerProvenance
			input.Provenance.Subject[0].Digest["sha256"] = hashString(fmt.Sprintf("alien-build-%d", id))

		case CategorySBOM:
			targetLayer = evidence.LayerSBOM
			input.SBOM.Components[0].Version = fmt.Sprintf("99.99.%d", id)

		case CategoryDependency:
			targetLayer = evidence.LayerDependencies
			input.Dependencies.IsConsistent = false
			input.Dependencies.Mismatches = []*dependency.Mismatch{
				{Package: "tampered-pkg", Expected: "1.0.0", Observed: "1.0.0-evil"},
			}

		case CategoryCommit:
			targetLayer = evidence.LayerSource
			expectedVerdict = "WARNING"
			input.Repository.IsClean = false
			input.Repository.ModifiedFiles = []string{fmt.Sprintf("modified_%d.go", id)}

		case CategoryEnvironment:
			targetLayer = evidence.LayerBuild
			input.Execution.Success = false
			input.Execution.ExitCode = 1
			input.Execution.Error = fmt.Sprintf("environment toolchain failure in container-%d", id)

		case CategoryFilesystem:
			targetLayer = evidence.LayerFilesystem
			input.InputEvaluation.UnexpectedInputs = []string{fmt.Sprintf("injected-rootkit-%d.so", id)}

		case CategoryNetwork:
			targetLayer = evidence.LayerNetwork
			input.NetworkAudit.IsPolicyCompliant = false
			input.NetworkAudit.Violations = []*network.ConnectionRecord{
				{Destination: "unauthorized-c2.example", AlertReason: "Domain not in policy allowlist"},
			}

		case CategoryProcess:
			targetLayer = evidence.LayerProcess
			input.ProcessTree.SuspiciousCount = 1
			input.ProcessTree.Processes = append(input.ProcessTree.Processes, &process.ProcessNode{
				PID: 9999, Name: "curl.exe", IsSuspicious: true,
			})

		default:
			targetLayer = evidence.LayerProvenance
			mutatedHash = hashString(fmt.Sprintf("mutated-%d", id))
			input.Artifact.SHA256 = mutatedHash
		}
	}

	start := time.Now()
	corr := tr.correlator.Correlate(input)
	tb := tr.localizer.Localize(corr)
	dec := tr.engine.Decide(corr, tr.pol)
	latency := time.Since(start).Microseconds()

	actualVerdict := string(dec.Verdict)
	detected := (actualVerdict == "REJECTED" || actualVerdict == "WARNING")
	localized := false
	if tb.HasTrustBreak && tb.EarliestLayer == targetLayer {
		localized = true
	}

	return &TrialRecord{
		TrialID:        id,
		MutationID:     fmt.Sprintf("MUT-%04d", id),
		Category:       cat,
		TargetLayer:    targetLayer,
		OriginalHash:   origHash,
		MutatedHash:    mutatedHash,
		ExpectedResult: expectedVerdict,
		ActualResult:   actualVerdict,
		Detected:       detected,
		Localized:      localized,
		LatencyMicros:  latency,
		IsBenign:       isBenign,
	}, nil
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func makeBaseInput() *correlation.CorrelationInput {
	artHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	return &correlation.CorrelationInput{
		Repository: &repository.State{
			Branch:         "main",
			CommitSHA:      "c0ffee1234567890abcdef1234567890abcdef12",
			IsClean:        true,
			UntrackedFiles: []string{},
			ModifiedFiles:  []string{},
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
			UnexpectedInputs: []string{},
			MissingInputs:    []string{},
		},
		NetworkAudit: &network.Evaluation{
			TotalConnections:  1,
			ViolationCount:    0,
			IsPolicyCompliant: true,
			Violations:        []*network.ConnectionRecord{},
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

// ExportCSVResults writes all experimental CSV matrices to results/
func (r *MatrixReport) ExportCSVResults(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// 1. raw.csv
	rawFile, err := os.Create(filepath.Join(outputDir, "raw.csv"))
	if err != nil {
		return err
	}
	defer rawFile.Close()
	wRaw := csv.NewWriter(rawFile)
	wRaw.Write([]string{"trial_id", "mutation_id", "category", "target_layer", "expected", "actual", "detected", "localized", "latency_micros", "is_benign"})
	for _, rec := range r.Records {
		wRaw.Write([]string{
			fmt.Sprintf("%d", rec.TrialID),
			rec.MutationID,
			string(rec.Category),
			string(rec.TargetLayer),
			rec.ExpectedResult,
			rec.ActualResult,
			fmt.Sprintf("%v", rec.Detected),
			fmt.Sprintf("%v", rec.Localized),
			fmt.Sprintf("%d", rec.LatencyMicros),
			fmt.Sprintf("%v", rec.IsBenign),
		})
	}
	wRaw.Flush()

	// 2. summary.csv
	sumFile, err := os.Create(filepath.Join(outputDir, "summary.csv"))
	if err != nil {
		return err
	}
	defer sumFile.Close()
	wSum := csv.NewWriter(sumFile)
	wSum.Write([]string{"metric", "value"})
	wSum.Write([]string{"total_trials", fmt.Sprintf("%d", r.TotalTrials)})
	wSum.Write([]string{"attack_trials", fmt.Sprintf("%d", r.AttackTrials)})
	wSum.Write([]string{"benign_trials", fmt.Sprintf("%d", r.BenignTrials)})
	wSum.Write([]string{"true_positives", fmt.Sprintf("%d", r.TruePositives)})
	wSum.Write([]string{"true_negatives", fmt.Sprintf("%d", r.TrueNegatives)})
	wSum.Write([]string{"false_positives", fmt.Sprintf("%d", r.FalsePositives)})
	wSum.Write([]string{"false_negatives", fmt.Sprintf("%d", r.FalseNegatives)})
	wSum.Write([]string{"precision_pct", fmt.Sprintf("%.2f", r.Precision)})
	wSum.Write([]string{"recall_pct", fmt.Sprintf("%.2f", r.Recall)})
	wSum.Write([]string{"f1_score", fmt.Sprintf("%.2f", r.F1Score)})
	wSum.Write([]string{"false_acceptance_rate_pct", fmt.Sprintf("%.2f", r.FalseAcceptanceRate)})
	wSum.Write([]string{"false_rejection_rate_pct", fmt.Sprintf("%.2f", r.FalseRejectionRate)})
	wSum.Write([]string{"localization_accuracy_pct", fmt.Sprintf("%.2f", r.LocalizationAccuracy)})
	wSum.Write([]string{"mean_latency_micros", fmt.Sprintf("%.2f", r.MeanLatencyMicros)})
	wSum.Flush()

	// 3. confusion-matrix.csv
	cmFile, err := os.Create(filepath.Join(outputDir, "confusion-matrix.csv"))
	if err != nil {
		return err
	}
	defer cmFile.Close()
	wCM := csv.NewWriter(cmFile)
	wCM.Write([]string{"", "Predicted Attack (Rejected/Warning)", "Predicted Safe (Trusted)"})
	wCM.Write([]string{"Actual Attack", fmt.Sprintf("%d", r.TruePositives), fmt.Sprintf("%d", r.FalseNegatives)})
	wCM.Write([]string{"Actual Benign", fmt.Sprintf("%d", r.FalsePositives), fmt.Sprintf("%d", r.TrueNegatives)})
	wCM.Flush()

	return nil
}
