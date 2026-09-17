package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/spf13/cobra"
)

var (
	inspectJSONOutput  bool
	inspectArtifactDir string
)

// InspectionReport aggregates repository and/or artifact integrity results
type InspectionReport struct {
	Timestamp  time.Time            `json:"timestamp"`
	Repository *repository.State    `json:"repository,omitempty"`
	Artifacts  *artifact.Collection `json:"artifacts,omitempty"`
}

var inspectCmd = &cobra.Command{
	Use:   "inspect [path]",
	Short: "Inspect source repository integrity and/or artifact metadata",
	Long: `Inspects the Git repository integrity state (branch, commit SHA, tree SHA, author,
clean/dirty status, untracked/modified files) and artifact directory or file metadata.
Defaults to inspecting the current repository.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		info, err := os.Stat(targetPath)
		if err != nil {
			return fmt.Errorf("target path error: %w", err)
		}

		report := &InspectionReport{
			Timestamp: time.Now().UTC(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if info.IsDir() {
			// Check if target directory is a git repository
			col, err := repository.NewCollector()
			if err == nil {
				repoState, repoErr := col.Collect(ctx, targetPath)
				if repoErr == nil {
					report.Repository = repoState
				}
			}

			// If explicitly requested via flag or if target is not a repo, scan artifacts
			scanDir := ""
			if inspectArtifactDir != "" {
				scanDir = inspectArtifactDir
			} else if report.Repository == nil {
				scanDir = targetPath
			}

			if scanDir != "" {
				coll, err := artifact.ScanDirectory(scanDir)
				if err != nil {
					return fmt.Errorf("failed scanning artifact directory %s: %w", scanDir, err)
				}
				report.Artifacts = coll
			}
		} else {
			// Single file artifact inspection
			meta, err := artifact.Inspect(targetPath, "")
			if err != nil {
				return fmt.Errorf("failed inspecting artifact: %w", err)
			}
			coll, err := artifact.NewCollection([]*artifact.Metadata{meta})
			if err != nil {
				return fmt.Errorf("failed creating artifact collection: %w", err)
			}
			report.Artifacts = coll
		}

		if inspectJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		fmt.Println("=== ProvenanceX Integrity Inspection Report ===")
		fmt.Printf("Timestamp: %s\n\n", report.Timestamp.Format(time.RFC3339))

		if report.Repository != nil {
			r := report.Repository
			fmt.Println("[Repository Integrity]")
			fmt.Printf("  Branch:            %s\n", r.Branch)
			fmt.Printf("  Commit SHA:        %s\n", r.CommitSHA)
			if r.ParentCommitSHA != "" {
				fmt.Printf("  Parent Commit:     %s\n", r.ParentCommitSHA)
			}
			fmt.Printf("  Tree SHA:          %s\n", r.TreeSHA)
			fmt.Printf("  Author:            %s <%s>\n", r.Author, r.AuthorEmail)
			fmt.Printf("  Commit Date:       %s\n", r.CommitTimestamp.Format(time.RFC3339))
			if r.IsClean {
				fmt.Println("  Working Tree:      CLEAN (✓)")
			} else {
				fmt.Println("  Working Tree:      DIRTY (✗ Discrepancy Detected)")
				if len(r.ModifiedFiles) > 0 {
					fmt.Printf("  Modified Files (%d):\n", len(r.ModifiedFiles))
					for _, f := range r.ModifiedFiles {
						fmt.Printf("    - %s\n", f)
					}
				}
				if len(r.UntrackedFiles) > 0 {
					fmt.Printf("  Untracked Files (%d):\n", len(r.UntrackedFiles))
					for _, f := range r.UntrackedFiles {
						fmt.Printf("    - %s\n", f)
					}
				}
			}
			fmt.Println()
		}

		if report.Artifacts != nil && report.Artifacts.Count > 0 {
			a := report.Artifacts
			fmt.Println("[Artifact Integrity]")
			fmt.Printf("  Total Artifacts:   %d\n", a.Count)
			fmt.Printf("  Total Size:        %d bytes\n", a.TotalSize)
			fmt.Printf("  Merkle Root:       %s\n", a.MerkleRoot)
			fmt.Println("  Artifact Details:")
			for _, item := range a.Artifacts {
				fmt.Printf("    - %s (%d bytes, %s)\n", item.RelativePath, item.Size, item.MIMEType)
				fmt.Printf("      SHA-256: %s\n", item.SHA256)
			}
			fmt.Println()
		}

		return nil
	},
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectJSONOutput, "json", false, "Output results as formatted JSON")
	inspectCmd.Flags().StringVarP(&inspectArtifactDir, "artifacts", "a", "", "Path to artifacts directory to scan")
	rootCmd.AddCommand(inspectCmd)
}
