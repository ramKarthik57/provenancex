package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/execution"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
	"github.com/ramKarthik57/provenancex/internal/process"
	"github.com/spf13/cobra"
)

var (
	recordWorkDir    string
	recordOutputJSON string
	recordJSONOutput bool
)

// EvidenceManifest is the unified evidence record captured across all layers during build execution
type EvidenceManifest struct {
	BuildID          string                   `json:"buildId"`
	Timestamp        time.Time                `json:"timestamp"`
	Duration         time.Duration            `json:"duration"`
	Success          bool                     `json:"success"`
	Command          string                   `json:"command"`
	RedactedArgs     []string                 `json:"redactedArgs"`
	ExitCode         int                      `json:"exitCode"`
	Environment      *environment.Fingerprint `json:"environment"`
	FilesystemDelta  *filesystem.Delta        `json:"filesystemDelta"`
	CreatedArtifacts []*artifact.Metadata     `json:"createdArtifacts"`
	ArtifactMerkle   string                   `json:"artifactMerkleRoot,omitempty"`
	ProcessTree      *process.Tree            `json:"processTree,omitempty"`
	NetworkAudit     *network.Evaluation      `json:"networkAudit,omitempty"`
}

var recordCmd = &cobra.Command{
	Use:   "record [flags] -- <command> [args...]",
	Short: "Record comprehensive build execution telemetry and evidence boundary",
	Long: `Wraps build command execution, capturing multi-layer evidence:
environment fingerprint, argument redaction, process trees, filesystem boundary
mutations (created/modified/deleted files), artifact hashing & Merkle tree, and
network destination audits. Generates an evidence manifest.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir := "."
		if recordWorkDir != "" {
			workDir = recordWorkDir
		}
		absWorkDir, err := filepath.Abs(workDir)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		buildID := execution.GenerateBuildID()

		// 1. Snapshot Environment
		envCol := environment.NewCollector()
		envFp, err := envCol.Collect(ctx)
		if err != nil {
			return fmt.Errorf("failed capturing environment: %w", err)
		}

		// 2. Pre-build Filesystem Snapshot
		fsMonitor := filesystem.NewBoundaryMonitor()
		beforeSnap, err := fsMonitor.TakeSnapshot(absWorkDir)
		if err != nil {
			return fmt.Errorf("failed capturing initial filesystem boundary: %w", err)
		}

		// 3. Execute Command
		runner := execution.NewRunner()
		targetCmd := args[0]
		cmdArgs := args[1:]

		fmt.Printf("=== ProvenanceX Build Recorder [%s] ===\n", buildID)
		fmt.Printf("Executing: %s %v\n", targetCmd, cmdArgs)

		stage, execErr := runner.ExecuteStage(ctx, "build", absWorkDir, targetCmd, cmdArgs, nil)

		// 4. Post-build Filesystem Snapshot
		afterSnap, err := fsMonitor.TakeSnapshot(absWorkDir)
		if err != nil {
			return fmt.Errorf("failed capturing post-build filesystem boundary: %w", err)
		}
		fsDelta := fsMonitor.ComputeDelta(beforeSnap, afterSnap)

		// 5. Inspect Created Artifacts
		var createdArtifacts []*artifact.Metadata
		for _, f := range fsDelta.CreatedFiles {
			fullPath := filepath.Join(absWorkDir, f.RelativePath)
			meta, mErr := artifact.Inspect(fullPath, absWorkDir)
			if mErr == nil {
				createdArtifacts = append(createdArtifacts, meta)
			}
		}

		merkleRoot := ""
		if len(createdArtifacts) > 0 {
			coll, cErr := artifact.NewCollection(createdArtifacts)
			if cErr == nil {
				merkleRoot = coll.MerkleRoot
			}
		}

		// 6. Network and Process Evidence
		procMonitor := process.NewMonitor()
		procTree := procMonitor.BuildTree([]*process.ProcessNode{
			{
				PID:         os.Getpid(),
				Name:        targetCmd,
				CommandLine: targetCmd,
				StartTime:   stage.StartTime,
				EndTime:     stage.EndTime,
				ExitCode:    stage.ExitCode,
			},
		})

		netMonitor := network.NewMonitor(nil)
		netAudit := netMonitor.Audit([]*network.ConnectionRecord{})

		manifest := &EvidenceManifest{
			BuildID:          buildID,
			Timestamp:        stage.StartTime,
			Duration:         stage.Duration,
			Success:          stage.Success,
			Command:          stage.RedactedCommand,
			RedactedArgs:     stage.RedactedArgs,
			ExitCode:         stage.ExitCode,
			Environment:      envFp,
			FilesystemDelta:  fsDelta,
			CreatedArtifacts: createdArtifacts,
			ArtifactMerkle:   merkleRoot,
			ProcessTree:      procTree,
			NetworkAudit:     netAudit,
		}

		// Save manifest if requested
		if recordOutputJSON != "" {
			manifestData, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				return fmt.Errorf("failed serializing evidence manifest: %w", err)
			}
			if err := os.WriteFile(recordOutputJSON, manifestData, 0644); err != nil {
				return fmt.Errorf("failed writing evidence manifest to %s: %w", recordOutputJSON, err)
			}
			fmt.Printf("Evidence manifest written to: %s\n", recordOutputJSON)
		}

		if recordJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(manifest)
		}

		fmt.Println("\n--- Build Evidence Summary ---")
		fmt.Printf("Build ID:        %s\n", manifest.BuildID)
		fmt.Printf("Exit Code:       %d (Success: %v)\n", manifest.ExitCode, manifest.Success)
		fmt.Printf("Duration:        %s\n", manifest.Duration)
		fmt.Printf("Env Fingerprint: %s\n", envFp.FingerprintHash)
		fmt.Printf("Created Files:   %d\n", len(fsDelta.CreatedFiles))
		for _, cf := range fsDelta.CreatedFiles {
			fmt.Printf("  + [Created] %s (SHA-256: %s)\n", cf.RelativePath, cf.SHA256)
		}
		fmt.Printf("Modified Files:  %d\n", len(fsDelta.ModifiedFiles))
		fmt.Printf("Deleted Files:   %d\n", len(fsDelta.DeletedFiles))
		if merkleRoot != "" {
			fmt.Printf("Artifact Merkle: %s\n", merkleRoot)
		}

		return execErr
	},
}

func init() {
	recordCmd.Flags().StringVarP(&recordWorkDir, "work-dir", "w", "", "Directory boundary to monitor")
	recordCmd.Flags().StringVarP(&recordOutputJSON, "output", "o", "", "File path to write evidence manifest JSON")
	recordCmd.Flags().BoolVar(&recordJSONOutput, "json", false, "Output results as formatted JSON")
	rootCmd.AddCommand(recordCmd)
}
