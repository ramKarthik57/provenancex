package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/execution"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/spf13/cobra"
)

var (
	provFile       string
	provArtifact   string
	provRepoDir    string
	provOutputJSON bool
	provOutputFile string
)

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Generate and verify SLSA v1.0 and in-toto provenance attestations",
	Long: `Inspects, generates, or cryptographically verifies in-toto SLSA provenance
statements against compiled artifacts and source repository commit state.`,
}

var provVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify an in-toto SLSA provenance file against an artifact",
	RunE: func(cmd *cobra.Command, args []string) error {
		if provFile == "" || provArtifact == "" {
			return fmt.Errorf("both --provenance and --artifact flags are required")
		}

		stmt, err := provenance.ParseInTotoStatement(provFile)
		if err != nil {
			return fmt.Errorf("failed parsing provenance statement: %w", err)
		}

		meta, err := artifact.Inspect(provArtifact, "")
		if err != nil {
			return fmt.Errorf("failed inspecting artifact %s: %w", provArtifact, err)
		}

		var repoState *repository.State
		if provRepoDir != "" {
			col, err := repository.NewCollector()
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				repoState, _ = col.Collect(ctx, provRepoDir)
			}
		}

		verifier := provenance.NewVerifier(nil)
		res := verifier.Verify(stmt, meta, repoState)

		if provOutputJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}

		fmt.Println("=== ProvenanceX SLSA Attestation Verification ===")
		fmt.Printf("Artifact:        %s (SHA-256: %s)\n", meta.Name, meta.SHA256)
		fmt.Printf("Claimed Builder: %s\n", res.BuilderID)
		fmt.Printf("Build Type:      %s\n", res.BuildType)
		if res.Valid {
			fmt.Println("Verdict:         VERIFIED & CONSISTENT (✓)")
		} else {
			fmt.Println("Verdict:         CONTRADICTION DETECTED (✗)")
			fmt.Printf("\n[Contradictions (%d)]\n", len(res.Contradictions))
			for _, c := range res.Contradictions {
				fmt.Printf("  - [%s]\n", c.Field)
				fmt.Printf("    Claimed:  %s\n", c.Claimed)
				fmt.Printf("    Observed: %s\n", c.Observed)
				fmt.Printf("    Details:  %s\n", c.Description)
			}
		}

		return nil
	},
}

var provGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an in-toto SLSA v1.0 provenance attestation for an artifact",
	RunE: func(cmd *cobra.Command, args []string) error {
		if provArtifact == "" {
			return fmt.Errorf("--artifact flag is required")
		}

		meta, err := artifact.Inspect(provArtifact, "")
		if err != nil {
			return fmt.Errorf("failed inspecting artifact: %w", err)
		}

		var repoState *repository.State
		col, err := repository.NewCollector()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			repoDir := "."
			if provRepoDir != "" {
				repoDir = provRepoDir
			}
			repoState, _ = col.Collect(ctx, repoDir)
		}

		now := time.Now().UTC()
		buildID := execution.GenerateBuildID()

		stmt, err := provenance.GenerateSLSAv1(
			meta,
			repoState,
			buildID,
			"provenancex",
			[]string{"build"},
			now.Add(-10*time.Second),
			now,
		)
		if err != nil {
			return fmt.Errorf("failed generating SLSA statement: %w", err)
		}

		outData, err := json.MarshalIndent(stmt, "", "  ")
		if err != nil {
			return err
		}

		if provOutputFile != "" {
			if err := os.WriteFile(provOutputFile, outData, 0644); err != nil {
				return fmt.Errorf("failed writing provenance to %s: %w", provOutputFile, err)
			}
			fmt.Printf("SLSA Provenance successfully generated and saved to: %s\n", provOutputFile)
			return nil
		}

		fmt.Println(string(outData))
		return nil
	},
}

func init() {
	provVerifyCmd.Flags().StringVarP(&provFile, "provenance", "p", "", "Path to in-toto SLSA provenance JSON file")
	provVerifyCmd.Flags().StringVarP(&provArtifact, "artifact", "a", "", "Path to software artifact file")
	provVerifyCmd.Flags().StringVarP(&provRepoDir, "repo", "r", "", "Optional path to Git repository to verify commit SHA")
	provVerifyCmd.Flags().BoolVar(&provOutputJSON, "json", false, "Output results as formatted JSON")

	provGenerateCmd.Flags().StringVarP(&provArtifact, "artifact", "a", "", "Path to software artifact file")
	provGenerateCmd.Flags().StringVarP(&provRepoDir, "repo", "r", "", "Optional path to Git repository")
	provGenerateCmd.Flags().StringVarP(&provOutputFile, "output", "o", "", "File path to save generated provenance JSON")

	provenanceCmd.AddCommand(provVerifyCmd)
	provenanceCmd.AddCommand(provGenerateCmd)
	rootCmd.AddCommand(provenanceCmd)
}
