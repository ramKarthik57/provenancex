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
	"github.com/ramKarthik57/provenancex/internal/graph"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/spf13/cobra"
)

var (
	graphJSONOutput bool
	graphRepoDir    string
)

var graphCmd = &cobra.Command{
	Use:   "graph <artifact>",
	Short: "ProvenanceX Trust Graph 2.0 formal evidence DAG explorer",
	Long: `Constructs and renders the formal 12-layer evidence Directed Acyclic Graph (DAG)
mapping relationships from Repository through Source, Dependencies, Processes, Filesystem,
Network, Artifact Binary, SBOM, Provenance, and Digital Signatures.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := buildGraphForTarget(args[0])
		if err != nil {
			return err
		}

		if graphJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(g)
		}

		fmt.Print(g.RenderASCII())
		return nil
	},
}

var graphPathCmd = &cobra.Command{
	Use:   "path <artifact>",
	Short: "Trace causal lineage path from source repository to artifact in Trust Graph",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := buildGraphForTarget(args[0])
		if err != nil {
			return err
		}

		path := g.FindPath(g.RootID, g.TargetID)
		if graphJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(path)
		}

		fmt.Println("================================================================================")
		fmt.Printf("        CAUSAL LINEAGE PATH: [%s] -> [%s]\n", g.RootID, g.TargetID)
		fmt.Println("================================================================================")
		for i, n := range path {
			fmt.Printf("  Step %d: [%s] %s (State: %s, Source: %s)\n", i+1, n.Type, n.ID, n.VerificationState, n.Source)
		}
		fmt.Println("================================================================================")
		return nil
	},
}

var graphContradictionsCmd = &cobra.Command{
	Use:   "contradictions <artifact>",
	Short: "Query all contradicted or failing nodes in the Trust Graph",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := buildGraphForTarget(args[0])
		if err != nil {
			return err
		}

		nodes := g.GetContradictionNodes()
		if graphJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(nodes)
		}

		fmt.Println("================================================================================")
		fmt.Printf("       CONTRADICTED TRUST GRAPH NODES (%d FOUND)\n", len(nodes))
		fmt.Println("================================================================================")
		if len(nodes) == 0 {
			fmt.Println("  All graph nodes are mutually consistent and policy-compliant.")
		} else {
			for i, n := range nodes {
				fmt.Printf("  [%d] Node ID: %s | Type: %s | State: %s | Source: %s\n", i+1, n.ID, n.Type, n.VerificationState, n.Source)
			}
		}
		fmt.Println("================================================================================")
		return nil
	},
}

func buildGraphForTarget(targetPath string) (*graph.TrustGraph, error) {
	meta, err := artifact.Inspect(targetPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed inspecting artifact: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	corrInput := &correlation.CorrelationInput{
		Artifact: meta,
	}

	repoPath := "."
	if graphRepoDir != "" {
		repoPath = graphRepoDir
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

	return graph.BuildFromCorrelation(corrInput, corrResult), nil
}

func init() {
	graphCmd.PersistentFlags().BoolVar(&graphJSONOutput, "json", false, "Output graph as JSON")
	graphCmd.PersistentFlags().StringVar(&graphRepoDir, "repo", "", "Path to repository directory")

	graphCmd.AddCommand(graphPathCmd)
	graphCmd.AddCommand(graphContradictionsCmd)

	rootCmd.AddCommand(graphCmd)
}
