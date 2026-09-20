package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/bundle"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/decision"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/localization"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/ramKarthik57/provenancex/internal/signature"
	"github.com/spf13/cobra"
)

var (
	explainPolicyFile     string
	explainProvenanceFile string
	explainSBOMFile       string
	explainSignatureFile  string
	explainPublicKeyFile  string
	explainRepoDir        string
	explainJSONOutput     bool
)

var explainCmd = &cobra.Command{
	Use:   "explain <artifact-or-bundle>",
	Short: "Audit-grade causal root-cause analysis and 'Why?' explainability engine",
	Long: `Explains why a software build was approved or rejected by tracing contradictions
across the 12 normalized supply-chain planes, pinpoints the earliest trust break layer,
and outputs actionable developer remediation steps.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]

		if strings.HasSuffix(targetPath, ".tar.gz") {
			// Bundle offline explanation
			res, err := bundle.VerifyOffline(targetPath)
			if err != nil {
				return fmt.Errorf("failed verifying bundle for explanation: %w", err)
			}

			// Generate synthetic correlation to feed explain engine
			corrRes := &correlation.Result{
				Contradictions: make([]*correlation.Contradiction, 0),
			}
			if !res.ArtifactMatch {
				corrRes.Contradictions = append(corrRes.Contradictions, &correlation.Contradiction{
					Layer1:      evidence.LayerArtifact,
					Layer2:      evidence.LayerProvenance,
					Subject:     "Artifact SHA-256 Digest",
					Description: "Bundle artifact binary digest does not match manifest digest",
					Claim1:      res.ArtifactSHA256,
					Claim2:      "Declared digest in manifest",
				})
			}
			if !res.SignerValid {
				corrRes.Contradictions = append(corrRes.Contradictions, &correlation.Contradiction{
					Layer1:      evidence.LayerSignature,
					Layer2:      evidence.LayerArtifact,
					Subject:     "Cryptographic Signature",
					Description: "Digital signature verification failed against bundle public key",
					Claim1:      "INVALID",
					Claim2:      "VALID_EXPECTED",
				})
			}
			if !res.TamperEvidentLogValid {
				corrRes.Contradictions = append(corrRes.Contradictions, &correlation.Contradiction{
					Layer1:      evidence.LayerProvenance,
					Layer2:      evidence.LayerArtifact,
					Subject:     "Tamper-Evident Hash Log",
					Description: "RFC 6962 append-only hash log integrity broken",
					Claim1:      "BROKEN_TREE",
					Claim2:      "CONSISTENT_TREE",
				})
			}

			explanation := localization.Explain(corrRes, res.Verdict)
			if explainJSONOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(explanation)
			}

			fmt.Print(explanation.FormatTerminal())
			return nil
		}

		// Full cross-layer inspection and explanation
		meta, err := artifact.Inspect(targetPath, "")
		if err != nil {
			return fmt.Errorf("failed inspecting target artifact %s: %w", targetPath, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		corrInput := &correlation.CorrelationInput{
			Artifact: meta,
		}

		repoPath := "."
		if explainRepoDir != "" {
			repoPath = explainRepoDir
		}
		repoCol, err := repository.NewCollector()
		if err == nil {
			repoState, _ := repoCol.Collect(ctx, repoPath)
			corrInput.Repository = repoState
		}

		depAnalyzer := dependency.NewAnalyzer(nil)
		depReport, _ := depAnalyzer.Analyze(repoPath)
		corrInput.Dependencies = depReport

		envCol := environment.NewCollector()
		envFp, _ := envCol.Collect(ctx)
		corrInput.Environment = envFp

		if explainSBOMFile != "" {
			doc, _ := parseSBOMFile(explainSBOMFile)
			corrInput.SBOM = doc
		}

		if explainProvenanceFile != "" {
			stmt, _ := provenance.ParseInTotoStatement(explainProvenanceFile)
			corrInput.Provenance = stmt
		}

		if explainSignatureFile != "" && explainPublicKeyFile != "" {
			pubPEM, err := os.ReadFile(explainPublicKeyFile)
			if err == nil {
				sigData, err := os.ReadFile(explainSignatureFile)
				if err == nil {
					sigVerifier := signature.NewVerifier()
					sigRes, _ := sigVerifier.VerifyFile(signature.AlgoECDSAP256, pubPEM, targetPath, sigData)
					corrInput.Signature = sigRes
				}
			}
		}

		correlator := correlation.NewCorrelator()
		corrResult := correlator.Correlate(corrInput)

		var pol *policy.Policy
		if explainPolicyFile != "" {
			pol, _ = policy.LoadPolicy(explainPolicyFile)
		}
		if pol == nil {
			pol = policy.DefaultPolicy()
		}

		decEngine := decision.NewEngine()
		dec := decEngine.Decide(corrResult, pol)

		explanation := localization.Explain(corrResult, string(dec.Verdict))
		if explainJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(explanation)
		}

		fmt.Print(explanation.FormatTerminal())
		return nil
	},
}

func init() {
	explainCmd.Flags().StringVar(&explainPolicyFile, "policy", "", "Path to policy YAML file")
	explainCmd.Flags().StringVar(&explainProvenanceFile, "provenance", "", "Path to SLSA in-toto provenance JSON")
	explainCmd.Flags().StringVar(&explainSBOMFile, "sbom", "", "Path to CycloneDX or SPDX SBOM JSON")
	explainCmd.Flags().StringVar(&explainSignatureFile, "signature", "", "Path to digital signature file")
	explainCmd.Flags().StringVar(&explainPublicKeyFile, "public-key", "", "Path to public key PEM file")
	explainCmd.Flags().StringVar(&explainRepoDir, "repo", "", "Path to repository directory (defaults to current dir)")
	explainCmd.Flags().BoolVar(&explainJSONOutput, "json", false, "Output explanation as JSON")

	rootCmd.AddCommand(explainCmd)
}
