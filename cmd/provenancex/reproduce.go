package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ramKarthik57/provenancex/internal/reproducibility"
	"github.com/spf13/cobra"
)

var (
	reproduceCmdStr   string
	reproduceWorkDir  string
	reproduceArtifact string
	reproduceEpoch    int64
	reproduceJSONOut  bool
)

var reproduceCmd = &cobra.Command{
	Use:   "reproduce",
	Short: "Reproducibility verification and divergence root-cause analysis",
	Long: `Verifies bitwise reproducibility of build outputs and diagnoses root causes
of build non-determinism, including embedded timestamps, host filesystem path
leakage, compiler optimizations, dependency drift, and archive entry ordering.`,
}

var reproduceCompareCmd = &cobra.Command{
	Use:   "compare <artifact1> <artifact2>",
	Short: "Compare two build outputs and diagnose divergence root causes",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path1 := args[0]
		path2 := args[1]

		report, err := reproducibility.CompareArtifacts(path1, path2)
		if err != nil {
			return fmt.Errorf("reproducibility comparison failed: %w", err)
		}

		if reproduceJSONOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		printReproducibilityReport(report)
		return nil
	},
}

var reproduceRunCmd = &cobra.Command{
	Use:   "run --cmd <command> --artifact <relativePath>",
	Short: "Execute a controlled dual-run rebuild in isolated sandboxes",
	RunE: func(cmd *cobra.Command, args []string) error {
		if reproduceCmdStr == "" {
			return fmt.Errorf("--cmd is required")
		}
		if reproduceArtifact == "" {
			return fmt.Errorf("--artifact is required")
		}

		workDir := "."
		if reproduceWorkDir != "" {
			workDir = reproduceWorkDir
		}

		opts := reproducibility.RebuildOptions{
			BuildCmd:    reproduceCmdStr,
			BuildDir:    workDir,
			ArtifactRel: reproduceArtifact,
			SourceEpoch: reproduceEpoch,
		}

		fmt.Printf("Starting controlled rebuild experiment...\n")
		fmt.Printf("Command:  %s\n", opts.BuildCmd)
		fmt.Printf("Artifact: %s\n\n", opts.ArtifactRel)

		report, err := reproducibility.ControlledRebuilder(opts)
		if err != nil {
			return fmt.Errorf("controlled rebuild failed: %w", err)
		}

		if reproduceJSONOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		printReproducibilityReport(report)
		return nil
	},
}

func printReproducibilityReport(r *reproducibility.Report) {
	fmt.Println("================================================================================")
	fmt.Println("                     PROVENANCEX REPRODUCIBILITY REPORT                         ")
	fmt.Println("================================================================================")
	fmt.Printf("Verdict:          %s\n", r.Status)
	fmt.Printf("Bitwise Match:    %t\n", r.BitwiseMatch)
	fmt.Printf("Artifact 1:       %s (SHA-256: %s, Size: %d bytes)\n", r.Artifact1.Name, r.Artifact1.SHA256, r.Artifact1.Size)
	fmt.Printf("Artifact 2:       %s (SHA-256: %s, Size: %d bytes)\n", r.Artifact2.Name, r.Artifact2.SHA256, r.Artifact2.Size)
	fmt.Printf("Byte Difference:  %+d bytes\n", r.ByteDifference)
	fmt.Printf("Analysis Time:    %d ms\n", r.DurationMs)
	fmt.Println("--------------------------------------------------------------------------------")

	if r.BitwiseMatch {
		fmt.Println("  [OK] Output binaries are 100% bit-for-bit identical across independent runs.")
	} else {
		fmt.Printf("ROOT CAUSES DETECTED (%d):\n", len(r.DivergenceCauses))
		for i, c := range r.DivergenceCauses {
			fmt.Printf("\n[%d] [%s] %s\n", i+1, c.Severity, c.Category)
			fmt.Printf("    Description:    %s\n", c.Description)
			if c.Evidence != "" {
				fmt.Printf("    Evidence:       %s\n", c.Evidence)
			}
			if c.Recommendation != "" {
				fmt.Printf("    Recommendation: %s\n", c.Recommendation)
			}
		}

		if len(r.Recommendations) > 0 {
			fmt.Println("\n--------------------------------------------------------------------------------")
			fmt.Println("ACTIONABLE RECOMMENDATIONS FOR DETERMINISTIC BUILDS:")
			for _, rec := range r.Recommendations {
				fmt.Printf("  * %s\n", rec)
			}
		}
	}
	fmt.Println("================================================================================")
}

func init() {
	reproduceCompareCmd.Flags().BoolVar(&reproduceJSONOut, "json", false, "Output report as JSON")

	reproduceRunCmd.Flags().StringVar(&reproduceCmdStr, "cmd", "", "Build command to execute")
	reproduceRunCmd.Flags().StringVarP(&reproduceWorkDir, "work-dir", "w", "", "Directory context for build")
	reproduceRunCmd.Flags().StringVarP(&reproduceArtifact, "artifact", "a", "", "Relative path of output artifact")
	reproduceRunCmd.Flags().Int64Var(&reproduceEpoch, "epoch", 0, "SOURCE_DATE_EPOCH value (optional)")
	reproduceRunCmd.Flags().BoolVar(&reproduceJSONOut, "json", false, "Output report as JSON")

	reproduceCmd.AddCommand(reproduceCompareCmd)
	reproduceCmd.AddCommand(reproduceRunCmd)
	rootCmd.AddCommand(reproduceCmd)
}
