package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/spf13/cobra"
)

var (
	envJSONOutput    bool
	showRedactedVars bool
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Capture build environment fingerprint with deterministic secret redaction",
	Long: `Inspects host OS, architecture, OS release, compilers, runtimes, package managers,
and environment variables. All passwords, tokens, API keys, and credentials are automatically
scrubbed and replaced with [REDACTED]. Computes a reproducible SHA-256 fingerprint hash.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		collector := environment.NewCollector()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		fp, err := collector.Collect(ctx)
		if err != nil {
			return fmt.Errorf("failed to collect environment: %w", err)
		}

		if envJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(fp)
		}

		fmt.Println("=== ProvenanceX Build Environment Fingerprint ===")
		fmt.Printf("Timestamp:        %s\n", fp.Timestamp.Format(time.RFC3339))
		fmt.Printf("OS / Platform:    %s (%s)\n", fp.OS, fp.OSVersion)
		fmt.Printf("Architecture:     %s\n", fp.Architecture)
		fmt.Printf("Hostname:         %s\n", fp.Hostname)
		fmt.Printf("Fingerprint SHA:  %s\n\n", fp.FingerprintHash)

		fmt.Println("[Detected Runtimes & Toolchains]")
		if len(fp.Tools) == 0 {
			fmt.Println("  (No standard build tools detected)")
		} else {
			for _, tool := range fp.Tools {
				fmt.Printf("  - %-8s %-30s (%s)\n", tool.Name, tool.Version, tool.Path)
			}
		}

		if showRedactedVars {
			fmt.Printf("\n[Environment Variables (Redacted Count: %d)]\n", len(fp.EnvironmentVars))
			for k, v := range fp.EnvironmentVars {
				fmt.Printf("  %s=%s\n", k, v)
			}
		}

		return nil
	},
}

func init() {
	envCmd.Flags().BoolVar(&envJSONOutput, "json", false, "Output results as formatted JSON")
	envCmd.Flags().BoolVar(&showRedactedVars, "show-vars", false, "Print sanitized environment variables")
	rootCmd.AddCommand(envCmd)
}
