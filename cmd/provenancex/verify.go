package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/signature"
	"github.com/spf13/cobra"
)

var (
	verifyPolicyFile     string
	verifyProvenanceFile string
	verifySBOMFile       string
	verifySignatureFile  string
	verifyPublicKeyFile  string
	verifyRepoDir        string
	verifyJSONOutput     bool
)

// FullVerificationReport aggregates the complete cross-layer verification and decision
type FullVerificationReport struct {
	Timestamp   time.Time           `json:"timestamp"`
	Artifact    *artifact.Metadata  `json:"artifact"`
	Correlation *correlation.Result `json:"correlation"`
	Decision    *decision.Decision  `json:"decision"`
}

var verifyCmd = &cobra.Command{
	Use:   "verify <artifact>",
	Short: "Cross-layer software supply-chain integrity verification and trust-break localization",
	Long: `Performs end-to-end multi-layer evidence correlation across source, dependency,
lockfile, SBOM, environment, process, filesystem, network, artifact, provenance,
and digital signature planes. Pinpoints the earliest trust break and renders an
explainable, deterministic decision: TRUSTED, WARNING, or REJECTED.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		artifactPath := args[0]
		meta, err := artifact.Inspect(artifactPath, "")
		if err != nil {
			return fmt.Errorf("failed inspecting target artifact %s: %w", artifactPath, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		corrInput := &correlation.CorrelationInput{
			Artifact: meta,
		}

		// 1. Source Repository
		repoPath := "."
		if verifyRepoDir != "" {
			repoPath = verifyRepoDir
		}
		repoCol, err := repository.NewCollector()
		if err == nil {
			repoState, _ := repoCol.Collect(ctx, repoPath)
			corrInput.Repository = repoState
		}

		// 2. Dependencies
		depAnalyzer := dependency.NewAnalyzer(nil)
		depReport, _ := depAnalyzer.Analyze(repoPath)
		corrInput.Dependencies = depReport

		// 3. Environment
		envCol := environment.NewCollector()
		envFp, _ := envCol.Collect(ctx)
		corrInput.Environment = envFp

		// 4. SBOM if provided
		if verifySBOMFile != "" {
			doc, _ := parseSBOMFile(verifySBOMFile)
			corrInput.SBOM = doc
		}

		// 5. Provenance if provided
		if verifyProvenanceFile != "" {
			stmt, _ := provenance.ParseInTotoStatement(verifyProvenanceFile)
			corrInput.Provenance = stmt
		}

		// 6. Digital Signature if provided
		if verifySignatureFile != "" && verifyPublicKeyFile != "" {
			pubPEM, err := os.ReadFile(verifyPublicKeyFile)
			if err == nil {
				sigData, err := os.ReadFile(verifySignatureFile)
				if err == nil {
					sigVerifier := signature.NewVerifier()
					sigRes, _ := sigVerifier.VerifyFile(signature.AlgoECDSAP256, pubPEM, artifactPath, sigData)
					corrInput.Signature = sigRes
				}
			}
		}

		// Run Cross-Layer Correlation
		correlator := correlation.NewCorrelator()
		corrResult := correlator.Correlate(corrInput)

		// Load Policy
		var pol *policy.Policy
		if verifyPolicyFile != "" {
			pol, _ = policy.LoadPolicy(verifyPolicyFile)
		}
		if pol == nil {
			pol = policy.DefaultPolicy()
		}

		// Run Decision Engine
		decEngine := decision.NewEngine()
		dec := decEngine.Decide(corrResult, pol)

		fullReport := &FullVerificationReport{
			Timestamp:   time.Now().UTC(),
			Artifact:    meta,
			Correlation: corrResult,
			Decision:    dec,
		}

		if verifyJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(fullReport)
		}

		// Formatted terminal presentation
		fmt.Println("==================================================")
		fmt.Println("        ProvenanceX Integrity Verification       ")
		fmt.Println("==================================================")
		fmt.Printf("Artifact:   %s\n", meta.Name)
		fmt.Printf("SHA-256:    %s\n", meta.SHA256)
		fmt.Printf("Size:       %d bytes (%s)\n\n", meta.Size, meta.MIMEType)

		fmt.Println("--- Cross-Layer Evidence Status ---")
		layers := []evidence.Layer{
			evidence.LayerSource,
			evidence.LayerDependencies,
			evidence.LayerLockfile,
			evidence.LayerEnvironment,
			evidence.LayerFilesystem,
			evidence.LayerNetwork,
			evidence.LayerSBOM,
			evidence.LayerProvenance,
			evidence.LayerSignature,
		}

		for _, l := range layers {
			st, ok := corrResult.LayerStatuses[l]
			if !ok {
				st = evidence.StatusUnobserved
			}
			symbol := "✓"
			if st == evidence.StatusContradicted {
				symbol = "✗ CONTRADICTION"
			} else if st == evidence.StatusMismatch {
				symbol = "⚠ MISMATCH"
			} else if st == evidence.StatusUnobserved {
				symbol = "⚪ UNOBSERVED"
			} else {
				symbol = "✓ VERIFIED"
			}
			fmt.Printf("  %-15s %s\n", l+":", symbol)
		}

		fmt.Println("\n--- Security Verdict ---")
		fmt.Printf("Decision:                 %s\n", dec.Verdict)

		if dec.TrustBreak != nil && dec.TrustBreak.HasTrustBreak {
			fmt.Printf("Trust-Break Localization: %s\n", dec.TrustBreak.EarliestLayer)
			fmt.Printf("Break Reason:             %s\n", dec.TrustBreak.Reason)
		}

		if len(dec.Reasons) > 0 {
			fmt.Println("\nDecision Reasons:")
			for i, r := range dec.Reasons {
				fmt.Printf("  %d. %s\n", i+1, r)
			}
		}

		if len(dec.Warnings) > 0 {
			fmt.Println("\nWarnings:")
			for _, w := range dec.Warnings {
				fmt.Printf("  - %s\n", w)
			}
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().StringVar(&verifyPolicyFile, "policy", "", "Path to YAML policy file")
	verifyCmd.Flags().StringVar(&verifyProvenanceFile, "provenance", "", "Path to SLSA in-toto provenance file")
	verifyCmd.Flags().StringVar(&verifySBOMFile, "sbom", "", "Path to CycloneDX or SPDX SBOM file")
	verifyCmd.Flags().StringVar(&verifySignatureFile, "signature", "", "Path to digital signature file")
	verifyCmd.Flags().StringVar(&verifyPublicKeyFile, "key", "", "Path to public key file for signature verification")
	verifyCmd.Flags().StringVar(&verifyRepoDir, "repo", ".", "Path to source Git repository")
	verifyCmd.Flags().BoolVar(&verifyJSONOutput, "json", false, "Output results as formatted JSON")
	rootCmd.AddCommand(verifyCmd)
}
