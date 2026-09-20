package delta

import (
	"fmt"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/environment"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/filesystem"
	"github.com/ramKarthik57/provenancex/internal/network"
)

// CompareManifests evaluates differences across all evidence layers between two builds
func CompareManifests(m1, m2 *evidence.EvidenceManifest) *Report {
	report := &Report{
		Build1ID:             m1.BuildID,
		Build2ID:             m2.BuildID,
		Timestamp1:           m1.Timestamp,
		Timestamp2:           m2.Timestamp,
		ArtifactsIdentical:   true,
		EnvironmentIdentical: true,
		CommandIdentical:     true,
		FilesystemIdentical:  true,
		NetworkIdentical:     true,
		Differences:          make([]DiffItem, 0),
		EvaluatedAt:          time.Now().UTC(),
	}

	// 1. Metadata Differences
	if m1.ExitCode != m2.ExitCode {
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryMetadata,
			Severity:    SeverityCritical,
			Field:       "ExitCode",
			Value1:      fmt.Sprintf("%d", m1.ExitCode),
			Value2:      fmt.Sprintf("%d", m2.ExitCode),
			Description: "Build execution exit status changed between runs.",
		})
	}

	if m1.Success != m2.Success {
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryMetadata,
			Severity:    SeverityCritical,
			Field:       "Success",
			Value1:      fmt.Sprintf("%t", m1.Success),
			Value2:      fmt.Sprintf("%t", m2.Success),
			Description: "Build outcome changed between success and failure.",
		})
	}

	// 2. Command Differences
	if m1.Command != m2.Command {
		report.CommandIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryCommand,
			Severity:    SeverityWarning,
			Field:       "Command",
			Value1:      m1.Command,
			Value2:      m2.Command,
			Description: "Build command string differs.",
		})
	}

	args1 := strings.Join(m1.RedactedArgs, " ")
	args2 := strings.Join(m2.RedactedArgs, " ")
	if args1 != args2 {
		report.CommandIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryCommand,
			Severity:    SeverityWarning,
			Field:       "RedactedArgs",
			Value1:      args1,
			Value2:      args2,
			Description: "Build command arguments differ.",
		})
	}

	// 3. Environment Differences
	if m1.Environment != nil && m2.Environment != nil {
		compareEnvironments(m1.Environment, m2.Environment, report)
	}

	// 4. Filesystem Differences
	if m1.FilesystemDelta != nil && m2.FilesystemDelta != nil {
		compareFilesystems(m1.FilesystemDelta, m2.FilesystemDelta, report)
	}

	// 5. Artifact Differences
	if m1.ArtifactMerkle != m2.ArtifactMerkle {
		report.ArtifactsIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryArtifact,
			Severity:    SeverityCritical,
			Field:       "ArtifactMerkleRoot",
			Value1:      m1.ArtifactMerkle,
			Value2:      m2.ArtifactMerkle,
			Description: "Artifact collection Merkle root hash mismatch between builds.",
		})
	}

	compareArtifactLists(m1.CreatedArtifacts, m2.CreatedArtifacts, report)

	// 6. Network Differences
	if m1.NetworkAudit != nil && m2.NetworkAudit != nil {
		compareNetworks(m1.NetworkAudit, m2.NetworkAudit, report)
	}

	report.TotalDifferences = len(report.Differences)

	// Overall Classification
	classifyReport(report)

	return report
}

func compareEnvironments(e1, e2 *environment.Fingerprint, report *Report) {
	if e1.OS != e2.OS || e1.Architecture != e2.Architecture {
		report.EnvironmentIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryEnvironment,
			Severity:    SeverityCritical,
			Field:       "HostOS_Arch",
			Value1:      fmt.Sprintf("%s/%s", e1.OS, e1.Architecture),
			Value2:      fmt.Sprintf("%s/%s", e2.OS, e2.Architecture),
			Description: "Host operating system or architecture differs between builds.",
		})
	}

	// Compare tools/runtimes
	tools1 := make(map[string]string)
	for _, t := range e1.Tools {
		tools1[t.Name] = t.Version
	}
	tools2 := make(map[string]string)
	for _, t := range e2.Tools {
		tools2[t.Name] = t.Version
	}

	for k, v1 := range tools1 {
		if v2, ok := tools2[k]; ok {
			if v1 != v2 {
				report.EnvironmentIdentical = false
				report.Differences = append(report.Differences, DiffItem{
					Category:    CategoryEnvironment,
					Severity:    SeverityWarning,
					Field:       "Tool:" + k,
					Value1:      v1,
					Value2:      v2,
					Description: fmt.Sprintf("Tool/Runtime %s version changed.", k),
				})
			}
		} else {
			report.EnvironmentIdentical = false
			report.Differences = append(report.Differences, DiffItem{
				Category:    CategoryEnvironment,
				Severity:    SeverityInfo,
				Field:       "Tool:" + k,
				Value1:      v1,
				Value2:      "<missing>",
				Description: fmt.Sprintf("Tool/Runtime %s absent in second build.", k),
			})
		}
	}
	for k, v2 := range tools2 {
		if _, ok := tools1[k]; !ok {
			report.EnvironmentIdentical = false
			report.Differences = append(report.Differences, DiffItem{
				Category:    CategoryEnvironment,
				Severity:    SeverityInfo,
				Field:       "Tool:" + k,
				Value1:      "<missing>",
				Value2:      v2,
				Description: fmt.Sprintf("Tool/Runtime %s added in second build.", k),
			})
		}
	}

	// Compare FingerprintHash
	if e1.FingerprintHash != e2.FingerprintHash && report.EnvironmentIdentical {
		report.EnvironmentIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryEnvironment,
			Severity:    SeverityInfo,
			Field:       "FingerprintHash",
			Value1:      e1.FingerprintHash,
			Value2:      e2.FingerprintHash,
			Description: "Subtle environment variable or configuration variance detected.",
		})
	}
}

func compareFilesystems(fs1, fs2 *filesystem.Delta, report *Report) {
	c1Map := make(map[string]string)
	for _, f := range fs1.CreatedFiles {
		c1Map[f.RelativePath] = f.SHA256
	}

	c2Map := make(map[string]string)
	for _, f := range fs2.CreatedFiles {
		c2Map[f.RelativePath] = f.SHA256
	}

	for path, h1 := range c1Map {
		if h2, ok := c2Map[path]; ok {
			if h1 != h2 {
				report.FilesystemIdentical = false
				report.Differences = append(report.Differences, DiffItem{
					Category:    CategoryFilesystem,
					Severity:    SeverityCritical,
					Field:       "CreatedFileHash:" + path,
					Value1:      h1,
					Value2:      h2,
					Description: fmt.Sprintf("File %s created in both builds but contents differ.", path),
				})
			}
		} else {
			report.FilesystemIdentical = false
			report.Differences = append(report.Differences, DiffItem{
				Category:    CategoryFilesystem,
				Severity:    SeverityWarning,
				Field:       "CreatedFileMissing:" + path,
				Value1:      h1,
				Value2:      "<none>",
				Description: fmt.Sprintf("File %s created in Build 1 but omitted in Build 2.", path),
			})
		}
	}

	for path, h2 := range c2Map {
		if _, ok := c1Map[path]; !ok {
			report.FilesystemIdentical = false
			report.Differences = append(report.Differences, DiffItem{
				Category:    CategoryFilesystem,
				Severity:    SeverityWarning,
				Field:       "CreatedFileExtra:" + path,
				Value1:      "<none>",
				Value2:      h2,
				Description: fmt.Sprintf("Unexpected extra file %s created only in Build 2.", path),
			})
		}
	}
}

func compareArtifactLists(arts1, arts2 []*artifact.Metadata, report *Report) {
	a1Map := make(map[string]string)
	for _, a := range arts1 {
		a1Map[a.RelativePath] = a.SHA256
	}
	a2Map := make(map[string]string)
	for _, a := range arts2 {
		a2Map[a.RelativePath] = a.SHA256
	}

	for path, h1 := range a1Map {
		if h2, ok := a2Map[path]; ok {
			if h1 != h2 {
				report.ArtifactsIdentical = false
				report.Differences = append(report.Differences, DiffItem{
					Category:    CategoryArtifact,
					Severity:    SeverityCritical,
					Field:       "ArtifactSHA256:" + path,
					Value1:      h1,
					Value2:      h2,
					Description: fmt.Sprintf("Artifact %s output digest altered.", path),
				})
			}
		} else {
			report.ArtifactsIdentical = false
			report.Differences = append(report.Differences, DiffItem{
				Category:    CategoryArtifact,
				Severity:    SeverityCritical,
				Field:       "ArtifactMissing:" + path,
				Value1:      h1,
				Value2:      "<missing>",
				Description: fmt.Sprintf("Artifact %s produced in Build 1 is missing in Build 2.", path),
			})
		}
	}

	for path, h2 := range a2Map {
		if _, ok := a1Map[path]; !ok {
			report.ArtifactsIdentical = false
			report.Differences = append(report.Differences, DiffItem{
				Category:    CategoryArtifact,
				Severity:    SeverityWarning,
				Field:       "ArtifactExtra:" + path,
				Value1:      "<missing>",
				Value2:      h2,
				Description: fmt.Sprintf("New artifact %s produced only in Build 2.", path),
			})
		}
	}
}

func compareNetworks(n1, n2 *network.Evaluation, report *Report) {
	if n1.TotalConnections != n2.TotalConnections {
		report.NetworkIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryNetwork,
			Severity:    SeverityInfo,
			Field:       "TotalConnections",
			Value1:      fmt.Sprintf("%d", n1.TotalConnections),
			Value2:      fmt.Sprintf("%d", n2.TotalConnections),
			Description: "Observed socket connection counts differ.",
		})
	}

	if len(n2.Violations) > len(n1.Violations) {
		report.NetworkIdentical = false
		report.Differences = append(report.Differences, DiffItem{
			Category:    CategoryNetwork,
			Severity:    SeverityCritical,
			Field:       "NetworkViolations",
			Value1:      fmt.Sprintf("%d", len(n1.Violations)),
			Value2:      fmt.Sprintf("%d", len(n2.Violations)),
			Description: "Second build incurred new unauthorized egress network connections.",
		})
	}
}

func classifyReport(r *Report) {
	if !r.ArtifactsIdentical {
		r.OverallClassification = "ARTIFACT_DIVERGENCE"
		r.Summary = "Critical: Build output artifacts differ between executions."
		return
	}

	hasCritical := false
	hasWarning := false
	for _, d := range r.Differences {
		if d.Severity == SeverityCritical {
			hasCritical = true
		} else if d.Severity == SeverityWarning {
			hasWarning = true
		}
	}

	if hasCritical {
		r.OverallClassification = "SUSPICIOUS_MUTATION"
		r.Summary = "Critical: Significant filesystem mutation or exit code divergence detected."
	} else if hasWarning || !r.EnvironmentIdentical || !r.CommandIdentical {
		r.OverallClassification = "ENVIRONMENT_OR_COMMAND_DRIFT"
		r.Summary = "Warning: Environment, compiler runtime, or command drifted between runs, though artifacts match."
	} else if len(r.Differences) > 0 {
		r.OverallClassification = "BENIGN_DRIFT"
		r.Summary = "Info: Only non-functional variances (timestamps, metrics) detected. Build is consistent."
	} else {
		r.OverallClassification = "IDENTICAL"
		r.Summary = "Build runs are bitwise and contextually identical across all layers."
	}
}

// FormatTerminal prints a formatted terminal diff view of the comparative report
func FormatTerminal(r *Report) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                     PROVENANCEX BUILD DELTA COMPARISON                         \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Build 1:        %s (%s)\n", r.Build1ID, r.Timestamp1.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Build 2:        %s (%s)\n", r.Build2ID, r.Timestamp2.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Classification: %s\n", r.OverallClassification))
	sb.WriteString(fmt.Sprintf("Summary:        %s\n", r.Summary))
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("LAYER CONSISTENCY:\n")
	sb.WriteString(fmt.Sprintf("  - Artifacts:   %s\n", boolStatus(r.ArtifactsIdentical)))
	sb.WriteString(fmt.Sprintf("  - Environment: %s\n", boolStatus(r.EnvironmentIdentical)))
	sb.WriteString(fmt.Sprintf("  - Command:     %s\n", boolStatus(r.CommandIdentical)))
	sb.WriteString(fmt.Sprintf("  - Filesystem:  %s\n", boolStatus(r.FilesystemIdentical)))
	sb.WriteString(fmt.Sprintf("  - Network:     %s\n", boolStatus(r.NetworkIdentical)))
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("DISCOVERED DIFFERENCES (%d):\n", r.TotalDifferences))

	if len(r.Differences) == 0 {
		sb.WriteString("  (None - No cross-layer variances discovered)\n")
	} else {
		for i, diff := range r.Differences {
			sb.WriteString(fmt.Sprintf("[%d] [%s] [%s] %s\n", i+1, diff.Severity, diff.Category, diff.Field))
			sb.WriteString(fmt.Sprintf("    Build 1: %s\n", diff.Value1))
			sb.WriteString(fmt.Sprintf("    Build 2: %s\n", diff.Value2))
			sb.WriteString(fmt.Sprintf("    Reason:  %s\n", diff.Description))
		}
	}
	sb.WriteString("================================================================================\n")
	return sb.String()
}

func boolStatus(b bool) string {
	if b {
		return "IDENTICAL"
	}
	return "DIVERGED"
}
