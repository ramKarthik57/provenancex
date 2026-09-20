package provenance

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/repository"
)

// ParseInTotoStatement reads and decodes an in-toto attestation JSON file
func ParseInTotoStatement(filePath string) (*InTotoStatement, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading provenance file: %w", err)
	}

	var stmt InTotoStatement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("invalid in-toto statement JSON: %w", err)
	}

	if stmt.Type != InTotoStatementV1 {
		return nil, fmt.Errorf("unsupported attestation type: %q (expected %s)", stmt.Type, InTotoStatementV1)
	}

	return &stmt, nil
}

// GenerateSLSAv1 creates a standard in-toto SLSA v1.0 statement
func GenerateSLSAv1(
	art *artifact.Metadata,
	repo *repository.State,
	buildID string,
	command string,
	args []string,
	startTime, endTime time.Time,
) (*InTotoStatement, error) {
	if art == nil {
		return nil, fmt.Errorf("artifact metadata cannot be nil")
	}

	// Subjects
	subject := Subject{
		Name: art.Name,
		Digest: map[string]string{
			"sha256": art.SHA256,
		},
	}

	// Materials / Dependencies from repository
	var resolvedDeps []ResourceDescriptor
	if repo != nil && repo.CommitSHA != "" {
		resolvedDeps = append(resolvedDeps, ResourceDescriptor{
			URI: repo.RepoURL,
			Digest: map[string]string{
				"sha1": repo.CommitSHA,
			},
		})
	}

	stmt := &InTotoStatement{
		Type:          InTotoStatementV1,
		Subject:       []Subject{subject},
		PredicateType: SLSAProvenanceV1,
		Predicate: SLSAv1Predicate{
			BuildDefinition: BuildDefinition{
				BuildType: GenericBuildType,
				ExternalParameters: map[string]any{
					"command": command,
					"args":    args,
				},
				ResolvedDependencies: resolvedDeps,
			},
			RunDetails: RunDetails{
				Builder: BuilderMetadata{
					ID: DefaultBuilderID,
				},
				Metadata: BuildMetadata{
					InvocationID: buildID,
					StartedOn:    startTime,
					FinishedOn:   endTime,
				},
			},
		},
	}

	return stmt, nil
}
