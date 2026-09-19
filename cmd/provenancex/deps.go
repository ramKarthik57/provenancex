package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/spf13/cobra"
)

var (
	depsJSONOutput bool
)

var depsCmd = &cobra.Command{
	Use:   "deps [path]",
	Short: "Inspect dependencies, lockfiles, and drift across Python, Node.js, and Docker",
	Long: `Discovers declared dependencies and lockfiles (package.json/package-lock.json,
requirements.txt/pyproject.toml/poetry.lock, Dockerfile), correlates direct and
transitive dependencies, and detects version drift, missing lockfiles, or untrusted registries.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetDir := "."
		if len(args) > 0 {
			targetDir = args[0]
		}

		analyzer := dependency.NewAnalyzer(nil)
		report, err := analyzer.Analyze(targetDir)
		if err != nil {
			return fmt.Errorf("dependency analysis failed: %w", err)
		}

		if depsJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		fmt.Println("=== ProvenanceX Dependency Intelligence Report ===")
		fmt.Printf("Directory:   %s\n", report.Directory)
		fmt.Printf("Timestamp:   %s\n", report.Timestamp.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("Ecosystems:  %v\n", report.Ecosystems)
		fmt.Printf("Direct Deps: %d\n", report.DirectCount)
		fmt.Printf("Total Deps:  %d\n", report.TotalCount)
		if report.HasLockfile {
			fmt.Println("Lockfile:    PRESENT (✓)")
		} else {
			fmt.Println("Lockfile:    MISSING / UNPINNED (✗)")
		}

		if report.IsConsistent {
			fmt.Println("Consistency: CONSISTENT (✓)")
		} else {
			fmt.Println("Consistency: DISCREPANCIES DETECTED (✗)")
		}

		if len(report.Mismatches) > 0 {
			fmt.Println("\n[Discrepancy Alerts]")
			for _, m := range report.Mismatches {
				fmt.Printf("  [%s] %s: %s\n", m.Severity, m.Type, m.Package)
				fmt.Printf("    Expected: %s\n", m.Expected)
				fmt.Printf("    Observed: %s\n", m.Observed)
				fmt.Printf("    Details:  %s\n", m.Description)
			}
		}

		if len(report.Dependencies) > 0 {
			fmt.Println("\n[Resolved Dependencies (Sample)]")
			limit := 15
			if len(report.Dependencies) < limit {
				limit = len(report.Dependencies)
			}
			for i := 0; i < limit; i++ {
				d := report.Dependencies[i]
				directStr := "transitive"
				if d.Direct {
					directStr = "direct"
				}
				fmt.Printf("  - %s@%s (%s, %s)\n", d.Name, d.Version, d.Ecosystem, directStr)
			}
			if len(report.Dependencies) > limit {
				fmt.Printf("  ... and %d more dependencies\n", len(report.Dependencies)-limit)
			}
		}

		return nil
	},
}

func init() {
	depsCmd.Flags().BoolVar(&depsJSONOutput, "json", false, "Output results as formatted JSON")
	rootCmd.AddCommand(depsCmd)
}
