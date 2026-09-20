package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/gaps"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/spf13/cobra"
)

var (
	evidenceJSONOutput bool
	evidenceRepoDir    string
)

var evidenceCmd = &cobra.Command{
	Use:   "evidence",
	Short: "Audit and verify supply-chain evidence completeness and gaps",
	Long: `Inspects evidence presence, identifies missing or unobserved telemetry planes,
and traces causal decision lineage without treating absence of evidence as evidence of safety.`,
}

var evidenceGapsCmd = &cobra.Command{
	Use:   "gaps <artifact>",
	Short: "Analyze required vs observed evidence planes and report missing evidence gaps",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]
		meta, err := artifact.Inspect(targetPath, "")
		if err != nil {
			return fmt.Errorf("failed inspecting artifact: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		corrInput := &correlation.CorrelationInput{
			Artifact: meta,
		}

		repoPath := "."
		if evidenceRepoDir != "" {
			repoPath = evidenceRepoDir
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

		correlator := correlation.NewCorrelator()
		corrResult := correlator.Correlate(corrInput)

		analyzer := gaps.NewAnalyzer(nil)
		report := analyzer.Analyze(corrInput, corrResult)

		if evidenceJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		fmt.Print(report.FormatTerminal())
		return nil
	},
}

func init() {
	evidenceCmd.PersistentFlags().BoolVar(&evidenceJSONOutput, "json", false, "Output report as JSON")
	evidenceCmd.PersistentFlags().StringVar(&evidenceRepoDir, "repo", "", "Path to repository directory")

	evidenceCmd.AddCommand(evidenceGapsCmd)
	rootCmd.AddCommand(evidenceCmd)
}
