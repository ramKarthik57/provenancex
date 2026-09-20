package correlation

import (
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
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

// CorrelationInput aggregates all evidence collected across layers for a build
type CorrelationInput struct {
	Repository         *repository.State
	Dependencies       *dependency.Report
	Environment        *environment.Fingerprint
	Execution          *execution.StageExecution
	ProcessTree        *process.Tree
	FilesystemDelta    *filesystem.Delta
	InputEvaluation    *filesystem.InputEvaluation
	NetworkAudit       *network.Evaluation
	Artifact           *artifact.Metadata
	ArtifactCollection *artifact.Collection
	SBOM               *sbom.Document
	Provenance         *provenance.InTotoStatement
	Signature          *signature.VerificationResult
}

// Contradiction models an irreconcilable conflict between two or more evidence layers
type Contradiction struct {
	Layer1      evidence.Layer `json:"layer1"`
	Layer2      evidence.Layer `json:"layer2"`
	Subject     string         `json:"subject"`
	Claim1      string         `json:"claim1"`
	Claim2      string         `json:"claim2"`
	Description string         `json:"description"`
}

// Result summarizes cross-layer evidence correlation
type Result struct {
	Timestamp        time.Time                          `json:"timestamp"`
	Input            *CorrelationInput                  `json:"input,omitempty"`
	IsConsistent     bool                               `json:"isConsistent"`
	LayerStatuses    map[evidence.Layer]evidence.Status `json:"layerStatuses"`
	Contradictions   []*Contradiction                   `json:"contradictions"`
	UnexpectedInputs []string                           `json:"unexpectedInputs"`
	MissingInputs    []string                           `json:"missingInputs"`
	EvidenceLog      *evidence.Log                      `json:"evidenceLog"`
}

// Correlator executes the cross-layer consistency rules
type Correlator struct{}

// NewCorrelator constructs an evidence correlator
func NewCorrelator() *Correlator {
	return &Correlator{}
}

// Correlate evaluates cross-layer evidence and identifies inconsistencies and contradictions
func (c *Correlator) Correlate(input *CorrelationInput) *Result {
	log := evidence.NewLog()
	layerStatuses := make(map[evidence.Layer]evidence.Status)
	var contradictions []*Contradiction
	var unexpectedInputs []string
	var missingInputs []string

	isConsistent := true

	// 1. SOURCE LAYER
	if input.Repository != nil {
		if input.Repository.IsClean {
			layerStatuses[evidence.LayerSource] = evidence.StatusVerified
			log.Append(evidence.LayerSource, evidence.CategoryDirect, evidence.StatusVerified,
				"git.workingTree", "clean", "clean",
				fmt.Sprintf("Repository on branch %s at commit %s", input.Repository.Branch, input.Repository.CommitSHA),
				"internal/repository")
		} else {
			layerStatuses[evidence.LayerSource] = evidence.StatusMismatch
			isConsistent = false
			log.Append(evidence.LayerSource, evidence.CategoryDirect, evidence.StatusMismatch,
				"git.workingTree", "clean", "dirty",
				fmt.Sprintf("Uncommitted or modified files: %v", append(input.Repository.ModifiedFiles, input.Repository.UntrackedFiles...)),
				"internal/repository")
		}

		if input.Repository.SignatureInfo != nil {
			switch input.Repository.SignatureInfo.Status {
			case repository.CommitSignatureInvalid:
				layerStatuses[evidence.LayerSource] = evidence.StatusContradicted
				isConsistent = false
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerSource,
					Layer2:      evidence.LayerSignature,
					Subject:     "git.commitSignature",
					Claim1:      "valid cryptographic signature",
					Claim2:      "signature verification failed",
					Description: "Git commit signature is cryptographically invalid or corrupted",
				})
			case repository.CommitSignatureIdentityMismatch:
				layerStatuses[evidence.LayerSource] = evidence.StatusContradicted
				isConsistent = false
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerSource,
					Layer2:      evidence.LayerSignature,
					Subject:     "git.commitIdentity",
					Claim1:      input.Repository.Author,
					Claim2:      input.Repository.SignatureInfo.SignerIdentity,
					Description: fmt.Sprintf("Commit author '%s' does not match signer identity '%s'", input.Repository.Author, input.Repository.SignatureInfo.SignerIdentity),
				})
			}
			log.Append(evidence.LayerSource, evidence.CategoryDirect, layerStatuses[evidence.LayerSource],
				"git.signature", string(input.Repository.SignatureInfo.Status), string(input.Repository.SignatureInfo.Status),
				fmt.Sprintf("Signer: %s, Key: %s", input.Repository.SignatureInfo.SignerIdentity, input.Repository.SignatureInfo.SignerKeyID),
				"internal/repository")
		}
	} else {
		layerStatuses[evidence.LayerSource] = evidence.StatusUnobserved
	}

	// 2. DEPENDENCIES & LOCKFILE
	if input.Dependencies != nil {
		if input.Dependencies.HasLockfile && input.Dependencies.IsConsistent {
			layerStatuses[evidence.LayerDependencies] = evidence.StatusVerified
			layerStatuses[evidence.LayerLockfile] = evidence.StatusVerified
			log.Append(evidence.LayerDependencies, evidence.CategoryDirect, evidence.StatusVerified,
				"dependencies.count", fmt.Sprintf("%d", input.Dependencies.DirectCount), fmt.Sprintf("%d", input.Dependencies.DirectCount),
				"All dependencies resolved and lockfile present", "internal/dependency")
		} else if !input.Dependencies.HasLockfile {
			layerStatuses[evidence.LayerDependencies] = evidence.StatusMismatch
			layerStatuses[evidence.LayerLockfile] = evidence.StatusMismatch
			isConsistent = false
			log.Append(evidence.LayerLockfile, evidence.CategoryDirect, evidence.StatusMismatch,
				"lockfile.presence", "present", "missing",
				"Manifest is missing lockfile or has unpinned dependencies", "internal/dependency")
		} else {
			layerStatuses[evidence.LayerDependencies] = evidence.StatusContradicted
			layerStatuses[evidence.LayerLockfile] = evidence.StatusContradicted
			isConsistent = false
			for _, m := range input.Dependencies.Mismatches {
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerDependencies,
					Layer2:      evidence.LayerLockfile,
					Subject:     m.Package,
					Claim1:      m.Expected,
					Claim2:      m.Observed,
					Description: m.Description,
				})
			}
		}
	} else {
		layerStatuses[evidence.LayerDependencies] = evidence.StatusUnobserved
		layerStatuses[evidence.LayerLockfile] = evidence.StatusUnobserved
	}

	// 3. SBOM vs DEPENDENCIES
	if input.SBOM != nil && input.Dependencies != nil {
		validator := sbom.NewValidator()
		valRes := validator.Validate(input.SBOM, input.Dependencies)
		if valRes.Valid {
			layerStatuses[evidence.LayerSBOM] = evidence.StatusVerified
			log.Append(evidence.LayerSBOM, evidence.CategoryExternal, evidence.StatusVerified,
				"sbom.components", fmt.Sprintf("%d", len(input.SBOM.Components)), fmt.Sprintf("%d", len(input.SBOM.Components)),
				"All observed dependencies match SBOM declarations", "internal/sbom")
		} else {
			layerStatuses[evidence.LayerSBOM] = evidence.StatusContradicted
			isConsistent = false
			for _, d := range valRes.Discrepancies {
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerDependencies,
					Layer2:      evidence.LayerSBOM,
					Subject:     d.Component,
					Claim1:      d.SBOMValue,
					Claim2:      d.ActualValue,
					Description: d.Description,
				})
			}
		}
	} else if input.SBOM != nil {
		layerStatuses[evidence.LayerSBOM] = evidence.StatusUnverified
	} else {
		layerStatuses[evidence.LayerSBOM] = evidence.StatusUnobserved
	}

	// 4. ENVIRONMENT LAYER
	if input.Environment != nil {
		layerStatuses[evidence.LayerEnvironment] = evidence.StatusVerified
		log.Append(evidence.LayerEnvironment, evidence.CategoryDirect, evidence.StatusVerified,
			"env.fingerprint", input.Environment.FingerprintHash, input.Environment.FingerprintHash,
			fmt.Sprintf("OS: %s, Arch: %s, Tools: %d", input.Environment.OS, input.Environment.Architecture, len(input.Environment.Tools)),
			"internal/environment")
	} else {
		layerStatuses[evidence.LayerEnvironment] = evidence.StatusUnobserved
	}

	// 5. BUILD EXECUTION & PROCESSES
	if input.Execution != nil {
		if input.Execution.Success {
			layerStatuses[evidence.LayerBuild] = evidence.StatusVerified
			log.Append(evidence.LayerBuild, evidence.CategoryDirect, evidence.StatusVerified,
				"build.exitCode", "0", "0",
				fmt.Sprintf("Duration: %s", input.Execution.Duration), "internal/execution")
		} else {
			layerStatuses[evidence.LayerBuild] = evidence.StatusMismatch
			isConsistent = false
			log.Append(evidence.LayerBuild, evidence.CategoryDirect, evidence.StatusMismatch,
				"build.exitCode", "0", fmt.Sprintf("%d", input.Execution.ExitCode),
				input.Execution.Error, "internal/execution")
		}
	} else {
		layerStatuses[evidence.LayerBuild] = evidence.StatusUnobserved
	}

	if input.ProcessTree != nil {
		if input.ProcessTree.SuspiciousCount == 0 {
			layerStatuses[evidence.LayerProcess] = evidence.StatusVerified
		} else {
			layerStatuses[evidence.LayerProcess] = evidence.StatusContradicted
			isConsistent = false
			for _, p := range input.ProcessTree.Processes {
				if p.IsSuspicious {
					contradictions = append(contradictions, &Contradiction{
						Layer1:      evidence.LayerBuild,
						Layer2:      evidence.LayerProcess,
						Subject:     p.Name,
						Claim1:      "authorized-build-process",
						Claim2:      p.CommandLine,
						Description: p.AlertReason,
					})
				}
			}
		}
	} else {
		layerStatuses[evidence.LayerProcess] = evidence.StatusUnobserved
	}

	// 6. FILESYSTEM & UNKNOWN INPUTS
	if input.InputEvaluation != nil {
		unexpectedInputs = input.InputEvaluation.UnexpectedInputs
		missingInputs = input.InputEvaluation.MissingInputs

		if len(input.InputEvaluation.OutOfBoundaryWrites) > 0 {
			for _, oob := range input.InputEvaluation.OutOfBoundaryWrites {
				unexpectedInputs = append(unexpectedInputs, oob)
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerSource,
					Layer2:      evidence.LayerFilesystem,
					Subject:     oob,
					Claim1:      "confined within build workspace boundary",
					Claim2:      "unauthorized out-of-boundary filesystem mutation",
					Description: fmt.Sprintf("FILESYSTEM BOUNDARY ESCAPE: Out-of-workspace file modification: %s", oob),
				})
			}
			layerStatuses[evidence.LayerFilesystem] = evidence.StatusContradicted
			isConsistent = false
		}

		if len(unexpectedInputs) > 0 {
			layerStatuses[evidence.LayerFilesystem] = evidence.StatusContradicted
			isConsistent = false
			for _, unexp := range unexpectedInputs {
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerSource,
					Layer2:      evidence.LayerFilesystem,
					Subject:     unexp,
					Claim1:      "declared in expected build inputs",
					Claim2:      "untracked/unexpected build input observed",
					Description: fmt.Sprintf("UNEXPECTED BUILD INPUT: %s", unexp),
				})
			}
		} else if len(missingInputs) > 0 {
			layerStatuses[evidence.LayerFilesystem] = evidence.StatusMismatch
		} else if len(input.InputEvaluation.OutOfBoundaryWrites) == 0 {
			layerStatuses[evidence.LayerFilesystem] = evidence.StatusVerified
		}
	} else {
		layerStatuses[evidence.LayerFilesystem] = evidence.StatusUnobserved
	}

	// 7. NETWORK LAYER
	if input.NetworkAudit != nil {
		hasDNSViolation := false
		if len(input.NetworkAudit.DNSQueries) > 0 {
			for _, q := range input.NetworkAudit.DNSQueries {
				if !q.IsAllowed {
					hasDNSViolation = true
					contradictions = append(contradictions, &Contradiction{
						Layer1:      evidence.LayerDependencies,
						Layer2:      evidence.LayerNetwork,
						Subject:     q.QueryDomain,
						Claim1:      "authorized DNS resolver / domain allowlist",
						Claim2:      q.QueryDomain,
						Description: fmt.Sprintf("UNAUTHORIZED DNS EXFILTRATION: Query for %s (%s)", q.QueryDomain, q.AlertReason),
					})
				}
			}
		}

		if input.NetworkAudit.IsPolicyCompliant && !hasDNSViolation {
			layerStatuses[evidence.LayerNetwork] = evidence.StatusVerified
		} else {
			layerStatuses[evidence.LayerNetwork] = evidence.StatusContradicted
			isConsistent = false
			for _, v := range input.NetworkAudit.Violations {
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerDependencies,
					Layer2:      evidence.LayerNetwork,
					Subject:     v.Destination,
					Claim1:      "authorized package registry",
					Claim2:      v.Destination,
					Description: v.AlertReason,
				})
			}
		}
	} else {
		layerStatuses[evidence.LayerNetwork] = evidence.StatusUnobserved
	}

	// 8. ARTIFACT INTEGRITY
	if input.Artifact != nil {
		layerStatuses[evidence.LayerArtifact] = evidence.StatusVerified
		log.Append(evidence.LayerArtifact, evidence.CategoryDerived, evidence.StatusVerified,
			input.Artifact.Name, input.Artifact.SHA256, input.Artifact.SHA256,
			fmt.Sprintf("Size: %d bytes, MIME: %s", input.Artifact.Size, input.Artifact.MIMEType),
			"internal/artifact")
	} else {
		layerStatuses[evidence.LayerArtifact] = evidence.StatusUnobserved
	}

	// 9. PROVENANCE CORRELATION
	if input.Provenance != nil {
		provVerifier := provenance.NewVerifier(nil)
		provRes := provVerifier.Verify(input.Provenance, input.Artifact, input.Repository)
		if provRes.Valid {
			layerStatuses[evidence.LayerProvenance] = evidence.StatusVerified
		} else {
			layerStatuses[evidence.LayerProvenance] = evidence.StatusContradicted
			isConsistent = false
			for _, ctd := range provRes.Contradictions {
				contradictions = append(contradictions, &Contradiction{
					Layer1:      evidence.LayerProvenance,
					Layer2:      evidence.LayerArtifact,
					Subject:     ctd.Field,
					Claim1:      ctd.Claimed,
					Claim2:      ctd.Observed,
					Description: ctd.Description,
				})
			}
		}
	} else {
		layerStatuses[evidence.LayerProvenance] = evidence.StatusUnobserved
	}

	// 10. DIGITAL SIGNATURE
	if input.Signature != nil {
		if input.Signature.Valid {
			layerStatuses[evidence.LayerSignature] = evidence.StatusVerified
		} else {
			layerStatuses[evidence.LayerSignature] = evidence.StatusContradicted
			isConsistent = false
			contradictions = append(contradictions, &Contradiction{
				Layer1:      evidence.LayerArtifact,
				Layer2:      evidence.LayerSignature,
				Subject:     string(input.Signature.Algorithm),
				Claim1:      "valid digital signature",
				Claim2:      "invalid or corrupted signature",
				Description: input.Signature.Error,
			})
		}
	} else {
		layerStatuses[evidence.LayerSignature] = evidence.StatusUnobserved
	}

	if len(contradictions) > 0 {
		isConsistent = false
	}

	return &Result{
		Timestamp:        time.Now().UTC(),
		Input:            input,
		IsConsistent:     isConsistent,
		LayerStatuses:    layerStatuses,
		Contradictions:   contradictions,
		UnexpectedInputs: unexpectedInputs,
		MissingInputs:    missingInputs,
		EvidenceLog:      log,
	}
}
