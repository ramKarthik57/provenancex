package main

import (
	"fmt"
	"os"

	"github.com/ramKarthik57/provenancex/pkg/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "provenancex",
	Short: "ProvenanceX — A Cross-Layer Software Supply-Chain Integrity Verification Framework",
	Long: `ProvenanceX is an independent verification and evidence-correlation engine
designed to detect discrepancies between declared build metadata (source, lockfiles,
SBOM, provenance, signatures) and observed build-time behavior (process executions,
filesystem mutations, network egress, rebuild reproducibility).

It localizes trust breaks and renders deterministic, policy-driven security decisions.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the ProvenanceX version and runtime build information",
	Run: func(cmd *cobra.Command, args []string) {
		info := version.Get()
		fmt.Println(info.String())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
