package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/spf13/cobra"
)

var (
	hashJSONOutput bool
)

var hashCmd = &cobra.Command{
	Use:   "hash <file> [file...]",
	Short: "Compute cryptographic SHA-256 digests and Merkle root for artifacts",
	Long: `Compute SHA-256 digests, file size, and MIME types for one or more files.
When multiple files are provided, computes a deterministic Merkle root over the artifact set.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var metas []*artifact.Metadata
		for _, path := range args {
			meta, err := artifact.Inspect(path, "")
			if err != nil {
				return fmt.Errorf("error inspecting %s: %w", path, err)
			}
			metas = append(metas, meta)
		}

		coll, err := artifact.NewCollection(metas)
		if err != nil {
			return fmt.Errorf("failed computing artifact collection: %w", err)
		}

		if hashJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(coll)
		}

		fmt.Println("=== ProvenanceX Artifact Hash Report ===")
		for _, m := range coll.Artifacts {
			fmt.Printf("File:      %s\n", m.Name)
			fmt.Printf("Path:      %s\n", m.Path)
			fmt.Printf("Size:      %d bytes\n", m.Size)
			fmt.Printf("MIME:      %s\n", m.MIMEType)
			fmt.Printf("SHA-256:   %s\n", m.SHA256)
			fmt.Println("----------------------------------------")
		}

		if coll.Count > 1 {
			fmt.Printf("Artifact Count: %d\n", coll.Count)
			fmt.Printf("Total Size:     %d bytes\n", coll.TotalSize)
			fmt.Printf("Merkle Root:    %s\n", coll.MerkleRoot)
		}

		return nil
	},
}

func init() {
	hashCmd.Flags().BoolVar(&hashJSONOutput, "json", false, "Output results as formatted JSON")
	rootCmd.AddCommand(hashCmd)
}
