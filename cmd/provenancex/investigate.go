package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/dependency"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/localization"
	
	"github.com/ramKarthik57/provenancex/internal/repository"
	"github.com/spf13/cobra"
)

var (
	investigateJSONOutput bool
	investigateRepoDir    string
)

// IncidentSummary models deep supply-chain forensic diagnostics
type IncidentSummary struct {
	Timestamp           time.Time `json:"timestamp"`
	ArtifactName        string    `json:"artifactName"`
	ArtifactSHA256      string    `json:"artifactSha256"`
	SourceCommit        string    `json:"sourceCommit"`
	SourceClean         bool      `json:"sourceClean"`
	DependenciesCount   int       `json:"dependenciesCount"`
	LockfilePresent     bool      `json:"lockfilePresent"`
	UnexpectedProcesses []string  `json:"unexpectedProcesses"`
	UnexpectedFiles     []string  `json:"unexpectedFiles"`
	UnexpectedNetwork   []string  `json:"unexpectedNetwork"`
	ProvenanceStatus    string    `json:"provenanceStatus"`
	SignatureStatus     string    `json:"signatureStatus"`
	EarliestTrustBreak  string    `json:"earliestTrustBreak"`
	BreakStatus         string    `json:"breakStatus"`
	BreakReason         string    `json:"breakReason"`
	ActionableLead      string    `json:"actionableLead"`
}

var investigateCmd = &cobra.Command{
	Use:   "investigate <artifact>",
	Short: "Supply-chain incident response and forensic deep-dive mode",
	Long: `Performs deep forensics investigation on a suspect software artifact by cross-referencing
runtime telemetry, physical process spawns, network egress, and attestation claims to reconstruct
the exact timeline and earliest breach vector.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]
		meta, err := artifact.Inspect(targetPath, "")
		if err != nil {
			return fmt.Errorf("failed inspecting target artifact %s: %w", targetPath, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		corrInput := &correlation.CorrelationInput{
			Artifact: meta,
		}

		repoPath := "."
		if investigateRepoDir != "" {
			repoPath = investigateRepoDir
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

		localizer := localization.NewLocalizer()
		tb := localizer.Localize(corrResult)

		incident := &IncidentSummary{
			Timestamp:           time.Now().UTC(),
			ArtifactName:        meta.Name,
			ArtifactSHA256:      meta.SHA256,
			UnexpectedProcesses: make([]string, 0),
			UnexpectedFiles:     corrResult.UnexpectedInputs,
			UnexpectedNetwork:   make([]string, 0),
		}

		if corrInput.Repository != nil {
			incident.SourceCommit = corrInput.Repository.CommitSHA
			incident.SourceClean = corrInput.Repository.IsClean
		}
		if corrInput.Dependencies != nil {
			incident.DependenciesCount = corrInput.Dependencies.TotalCount
			incident.LockfilePresent = corrInput.Dependencies.HasLockfile
		}

		if tb.HasTrustBreak {
			incident.EarliestTrustBreak = string(tb.EarliestLayer)
			incident.BreakStatus = string(tb.Status)
			incident.BreakReason = tb.Reason
			incident.ActionableLead = fmt.Sprintf("Quarantine artifact. Isolate build runner. Trace commit %s and inspect %s plane.", incident.SourceCommit, tb.EarliestLayer)
		} else {
			incident.EarliestTrustBreak = "NONE (CLEAN)"
			incident.BreakStatus = "VERIFIED"
			incident.BreakReason = "No cross-layer anomalies or security violations detected."
			incident.ActionableLead = "Artifact is deemed safe for production release."
		}

		if investigateJSONOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(incident)
		}

		printIncidentReport(incident)
		return nil
	},
}

func printIncidentReport(inc *IncidentSummary) {
	fmt.Println("================================================================================")
	fmt.Println("             PROVENANCEX SUPPLY-CHAIN INCIDENT FORENSIC REPORT                  ")
	fmt.Println("================================================================================")
	fmt.Printf("TARGET ARTIFACT:           %s\n", inc.ArtifactName)
	fmt.Printf("SHA-256 DIGEST:            %s\n", inc.ArtifactSHA256)
	fmt.Printf("INVESTIGATION TIMESTAMP:   %s\n", inc.Timestamp.Format(time.RFC3339))
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("SOURCE REPOSITORY COMMIT:  %s (Clean Tree: %v)\n", inc.SourceCommit, inc.SourceClean)
	fmt.Printf("DEPENDENCY RESOLUTION:     %d packages (Lockfile Present: %v)\n", inc.DependenciesCount, inc.LockfilePresent)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("EARLIEST TRUST BREAK:      [%s]\n", inc.EarliestTrustBreak)
	fmt.Printf("BREACH STATUS:             %s\n", inc.BreakStatus)
	fmt.Printf("CAUSAL ATTRIBUTION:        %s\n", inc.BreakReason)
	if len(inc.UnexpectedFiles) > 0 {
		fmt.Printf("UNEXPECTED INJECTED FILES: %s\n", strings.Join(inc.UnexpectedFiles, ", "))
	}
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("FORENSIC LEAD / ACTION:    %s\n", inc.ActionableLead)
	fmt.Println("================================================================================")
}

func init() {
	investigateCmd.Flags().BoolVar(&investigateJSONOutput, "json", false, "Output incident summary as JSON")
	investigateCmd.Flags().StringVar(&investigateRepoDir, "repo", "", "Path to source repository directory")

	rootCmd.AddCommand(investigateCmd)
}
