package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ramKarthik57/provenancex/internal/experiment"
	"github.com/ramKarthik57/provenancex/internal/policy"
	"github.com/spf13/cobra"
)

var (
	benchJSONOutput  bool
	benchMarkdownOut bool
	benchOutputFile  string
	benchPolicyPath  string
	benchScenarioID  string
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Execute empirical supply-chain attack benchmark and localization evaluation",
	Long: `Executes the ProvenanceX empirical security benchmark across 10 controlled,
non-destructive software supply chain attack scenarios:

  1. Source Code Tampering (uncommitted/dirty working tree)
  2. Dependency Substitution & Typosquatting
  3. Unpinned Floating Dependencies
  4. Build Process Injection (pipe to shell)
  5. Build Stage Execution Failure
  6. Unexpected Filesystem Input Injection
  7. Unauthorized Network Egress
  8. SBOM Component Discrepancy
  9. Provenance Subject Contradiction
 10. Cryptographic Signature Forgery

Evaluates detection sensitivity, causal trust-break localization accuracy, and mean verification latency.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var pol *policy.Policy
		if benchPolicyPath != "" {
			var err error
			pol, err = policy.LoadPolicy(benchPolicyPath)
			if err != nil {
				return fmt.Errorf("failed loading policy from %s: %w", benchPolicyPath, err)
			}
		}

		runner := experiment.NewRunner(pol)
		allScenarios := experiment.DefaultScenarios()

		var selected []experiment.Scenario
		if benchScenarioID != "" {
			for _, s := range allScenarios {
				if s.ID == benchScenarioID {
					selected = append(selected, s)
					break
				}
			}
			if len(selected) == 0 {
				return fmt.Errorf("scenario ID %q not found", benchScenarioID)
			}
		} else {
			selected = allScenarios
		}

		ctx := context.Background()
		report, err := runner.RunAll(ctx, selected)
		if err != nil {
			return fmt.Errorf("benchmark execution failed: %w", err)
		}

		if benchOutputFile != "" {
			ext := filepath.Ext(benchOutputFile)
			if ext == ".json" {
				if err := experiment.SaveJSON(report, benchOutputFile); err != nil {
					return fmt.Errorf("failed saving JSON output: %w", err)
				}
				fmt.Printf("[OK] Benchmark JSON saved to %s\n", benchOutputFile)
			} else {
				md := experiment.FormatMarkdown(report)
				if err := os.WriteFile(benchOutputFile, []byte(md), 0644); err != nil {
					return fmt.Errorf("failed saving Markdown output: %w", err)
				}
				fmt.Printf("[OK] Benchmark Markdown report saved to %s\n", benchOutputFile)
			}
		}

		if benchJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		if benchMarkdownOut {
			fmt.Println(experiment.FormatMarkdown(report))
			return nil
		}

		fmt.Print(experiment.FormatTerminal(report))
		return nil
	},
}

func init() {
	benchmarkCmd.Flags().BoolVar(&benchJSONOutput, "json", false, "Output report as JSON")
	benchmarkCmd.Flags().BoolVar(&benchMarkdownOut, "markdown", false, "Output report as Markdown")
	benchmarkCmd.Flags().StringVarP(&benchOutputFile, "output", "o", "", "Write benchmark results to file (.json or .md)")
	benchmarkCmd.Flags().StringVarP(&benchPolicyPath, "policy", "p", "", "Path to custom YAML policy file")
	benchmarkCmd.Flags().StringVarP(&benchScenarioID, "scenario", "s", "", "Run specific scenario by ID (e.g. EXP-01)")

	rootCmd.AddCommand(benchmarkCmd)
}
