package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ramKarthik57/provenancex/internal/delta"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/spf13/cobra"
)

var diffJSONOutput bool

var diffCmd = &cobra.Command{
	Use:   "diff <manifest1.json> <manifest2.json>",
	Short: "Cross-layer comparative diff between two build execution manifests",
	Long: `Compares two build evidence manifests across all 12 planes:
environment fingerprint, compiler runtimes, commands, arguments, filesystem mutations,
network connections, and output artifacts. Identifies mutations and classify drift.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path1 := args[0]
		path2 := args[1]

		m1, err := evidence.LoadManifest(path1)
		if err != nil {
			return fmt.Errorf("failed loading manifest 1 from %s: %w", path1, err)
		}

		m2, err := evidence.LoadManifest(path2)
		if err != nil {
			return fmt.Errorf("failed loading manifest 2 from %s: %w", path2, err)
		}

		report := delta.CompareManifests(m1, m2)

		if diffJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		fmt.Print(delta.FormatTerminal(report))
		return nil
	},
}

func init() {
	diffCmd.Flags().BoolVar(&diffJSONOutput, "json", false, "Output diff report as formatted JSON")
	rootCmd.AddCommand(diffCmd)
}
