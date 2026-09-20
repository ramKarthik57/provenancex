package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ramKarthik57/provenancex/internal/bundle"
	"github.com/spf13/cobra"
)

var (
	bundleArtifactPath    string
	bundleProvenancePath  string
	bundleSBOMPath        string
	bundleSignaturePath   string
	bundlePublicKeyPath   string
	bundleEvidenceLogPath string
	bundleManifestPath    string
	bundleOutputPath      string
	bundleJSONOutput      bool
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Package and verify self-contained, portable software supply chain evidence bundles",
	Long: `Packages build artifacts, in-toto/SLSA provenance attestations, CycloneDX/SPDX SBOMs,
cryptographic signatures, public keys, and tamper-evident append-only logs into a
portable, cryptographically indexed .tar.gz bundle.

Enables 100% offline, air-gapped cryptographic verification without database or network access.`,
}

var bundlePackCmd = &cobra.Command{
	Use:   "pack --artifact <file> --output <bundle.tar.gz>",
	Short: "Assemble and seal a portable evidence bundle",
	RunE: func(cmd *cobra.Command, args []string) error {
		if bundleArtifactPath == "" {
			return fmt.Errorf("--artifact is required")
		}
		if bundleOutputPath == "" {
			return fmt.Errorf("--output is required")
		}

		opts := bundle.PackOptions{
			ArtifactPath:         bundleArtifactPath,
			ProvenancePath:       bundleProvenancePath,
			SBOMPath:             bundleSBOMPath,
			SignaturePath:        bundleSignaturePath,
			PublicKeyPath:        bundlePublicKeyPath,
			EvidenceLogPath:      bundleEvidenceLogPath,
			EvidenceManifestPath: bundleManifestPath,
			OutputPath:           bundleOutputPath,
		}

		fmt.Printf("Packaging evidence bundle for %s...\n", bundleArtifactPath)
		if err := bundle.Pack(opts); err != nil {
			return fmt.Errorf("failed creating bundle: %w", err)
		}

		fmt.Printf("[OK] Portable evidence bundle successfully created: %s\n", bundleOutputPath)
		return nil
	},
}

var bundleVerifyCmd = &cobra.Command{
	Use:   "verify <bundle.tar.gz>",
	Short: "Perform 100% offline verification of an evidence bundle",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bundlePath := args[0]

		res, err := bundle.VerifyOffline(bundlePath)
		if err != nil {
			return fmt.Errorf("bundle verification encountered fatal error: %w", err)
		}

		if bundleJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		printOfflineVerificationResult(res)

		if res.Verdict == "REJECTED" {
			os.Exit(1)
		}
		return nil
	},
}

func printOfflineVerificationResult(r *bundle.OfflineVerificationResult) {
	fmt.Println("================================================================================")
	fmt.Println("                   PROVENANCEX OFFLINE BUNDLE VERIFICATION                      ")
	fmt.Println("================================================================================")
	fmt.Printf("OVERALL VERDICT:        [%s]\n", r.Verdict)
	fmt.Printf("Artifact SHA-256:       %s\n", r.ArtifactSHA256)
	fmt.Printf("Bundle Structure:       %s\n", boolBadge(r.BundleValid))
	fmt.Printf("Artifact Digest Match:  %s\n", boolBadge(r.ArtifactMatch))
	fmt.Printf("Digital Signature:      %s (%s)\n", boolBadge(r.SignerValid), r.SignerAlgorithm)
	fmt.Printf("Tamper-Evident Hash Log:%s\n", boolBadge(r.TamperEvidentLogValid))
	fmt.Printf("Provenance Attestation: %s (Builder: %s)\n", boolBadge(r.ProvenanceValid), r.BuilderID)
	fmt.Printf("Verification Time:      %d ms\n", r.DurationMs)
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

func boolBadge(b bool) string {
	if b {
		return "VERIFIED"
	}
	return "UNVERIFIED / FAILED"
}

func init() {
	bundlePackCmd.Flags().StringVarP(&bundleArtifactPath, "artifact", "a", "", "Path to target binary or artifact")
	bundlePackCmd.Flags().StringVarP(&bundleProvenancePath, "provenance", "p", "", "Path to in-toto / SLSA provenance JSON")
	bundlePackCmd.Flags().StringVar(&bundleSBOMPath, "sbom", "", "Path to SBOM JSON")
	bundlePackCmd.Flags().StringVarP(&bundleSignaturePath, "signature", "s", "", "Path to digital signature file")
	bundlePackCmd.Flags().StringVarP(&bundlePublicKeyPath, "key", "k", "", "Path to signer public key PEM")
	bundlePackCmd.Flags().StringVar(&bundleEvidenceLogPath, "evidence-log", "", "Path to tamper-evident append-only log")
	bundlePackCmd.Flags().StringVarP(&bundleManifestPath, "manifest", "m", "", "Path to build execution manifest")
	bundlePackCmd.Flags().StringVarP(&bundleOutputPath, "output", "o", "", "Destination path for .tar.gz bundle")

	bundleVerifyCmd.Flags().BoolVar(&bundleJSONOutput, "json", false, "Output verification result as JSON")

	bundleCmd.AddCommand(bundlePackCmd)
	bundleCmd.AddCommand(bundleVerifyCmd)
	rootCmd.AddCommand(bundleCmd)
}
