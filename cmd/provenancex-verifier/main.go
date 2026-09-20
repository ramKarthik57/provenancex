package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ramKarthik57/provenancex/internal/bundle"
	"github.com/spf13/cobra"
)

var jsonOutput bool

var rootCmd = &cobra.Command{
	Use:   "provenancex-verifier <evidence-bundle.tar.gz>",
	Short: "Air-Gapped Independent Evidence Bundle Verifier",
	Long: `provenancex-verifier is a physically separate, independent verification tool
designed for air-gapped consumer environments, release gates, and audit pipelines.

Core Architectural Invariant: "The build system does not get to verify itself."

It has:
  - Zero database dependency
  - Zero web UI dependency
  - Zero network dependency
  - Deterministic evaluation of bundle checksums, digital signatures,
    SLSA/in-toto attestations, and RFC 6962 tamper-evident hash logs.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bundlePath := args[0]
		absPath, err := filepath.Abs(bundlePath)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}

		res, err := bundle.VerifyOffline(absPath)
		if err != nil {
			return fmt.Errorf("verification error: %w", err)
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		printReport(res)

		if res.Verdict == "REJECTED" {
			os.Exit(1)
		}
		return nil
	},
}

func printReport(r *bundle.OfflineVerificationResult) {
	fmt.Println("================================================================================")
	fmt.Println("         PROVENANCEX INDEPENDENT VERIFIER (AIR-GAPPED SEPARATE BINARY)          ")
	fmt.Println("================================================================================")
	fmt.Printf("OVERALL VERDICT:        [%s]\n", r.Verdict)
	fmt.Printf("Artifact SHA-256:       %s\n", r.ArtifactSHA256)
	fmt.Printf("Bundle Structure:       %s\n", badge(r.BundleValid))
	fmt.Printf("Artifact Digest Match:  %s\n", badge(r.ArtifactMatch))
	fmt.Printf("Digital Signature:      %s (%s)\n", badge(r.SignerValid), r.SignerAlgorithm)
	fmt.Printf("Tamper-Evident Hash Log:%s\n", badge(r.TamperEvidentLogValid))
	fmt.Printf("Provenance Attestation: %s (Builder: %s)\n", badge(r.ProvenanceValid), r.BuilderID)
	fmt.Printf("Verification Latency:   %d ms\n", r.DurationMs)
	fmt.Println("--------------------------------------------------------------------------------")

	if len(r.PassedChecks) > 0 {
		fmt.Printf("PASSED CHECKS (%d):\n", len(r.PassedChecks))
		for _, pc := range r.PassedChecks {
			fmt.Printf("  [PASS] %s\n", pc)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("WARNINGS (%d):\n", len(r.Warnings))
		for _, w := range r.Warnings {
			fmt.Printf("  [WARN] %s\n", w)
		}
	}

	if len(r.FailedChecks) > 0 {
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("FAILED CHECKS (%d):\n", len(r.FailedChecks))
		for _, fc := range r.FailedChecks {
			fmt.Printf("  [FAIL] %s\n", fc)
		}
	}
	fmt.Println("================================================================================")
}

func badge(b bool) string {
	if b {
		return "VERIFIED"
	}
	return "UNVERIFIED / FAILED"
}

func main() {
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output verification result as JSON")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
