package main

import (
	"fmt"

	"github.com/ramKarthik57/provenancex/internal/server"
	"github.com/spf13/cobra"
)

var (
	servePort       int
	serveWebDir     string
	servePolicyPath string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the ProvenanceX verification API and interactive web dashboard",
	Long: `Launches an HTTP server providing REST API endpoints for artifact and evidence
verification, policy evaluation, live supply-chain attack benchmark simulations,
build delta analysis, and serves the React-based explainability dashboard.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := server.Config{
			Port:       servePort,
			WebDir:     serveWebDir,
			PolicyPath: servePolicyPath,
		}

		srv, err := server.NewServer(cfg)
		if err != nil {
			return fmt.Errorf("failed initializing server: %w", err)
		}

		return srv.Start()
	},
}

func init() {
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "HTTP port to listen on")
	serveCmd.Flags().StringVar(&serveWebDir, "web-dir", "web/dist", "Path to static web frontend distribution directory")
	serveCmd.Flags().StringVar(&servePolicyPath, "policy", "", "Path to YAML policy file")

	rootCmd.AddCommand(serveCmd)
}
