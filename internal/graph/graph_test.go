package graph

import (
	"testing"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/correlation"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/repository"
)

func TestTrustGraphConstruction(t *testing.T) {
	in := &correlation.CorrelationInput{
		Repository: &repository.State{
			CommitSHA:  "9af08e100f749553f1d248fe4ebf32b12bf087e5",
			TreeSHA: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			IsClean:    true,
		},
		Artifact: &artifact.Metadata{
			Name:   "app.exe",
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	res := &correlation.Result{
		IsConsistent: true,
		LayerStatuses: map[evidence.Layer]evidence.Status{
			evidence.LayerSource:       evidence.StatusVerified,
			evidence.LayerDependencies: evidence.StatusVerified,
			evidence.LayerArtifact:     evidence.StatusVerified,
		},
	}

	g := BuildFromCorrelation(in, res)

	if len(g.Nodes) < 10 {
		t.Fatalf("expected at least 10 nodes in Trust Graph, got %d", len(g.Nodes))
	}
	if len(g.Edges) < 10 {
		t.Fatalf("expected at least 10 edges in Trust Graph, got %d", len(g.Edges))
	}

	path := g.FindPath("node-repo", "node-artifact")
	if len(path) == 0 {
		t.Fatalf("expected non-empty path from repo to artifact")
	}

	ascii := g.RenderASCII()
	if len(ascii) == 0 {
		t.Fatalf("expected non-empty ASCII representation")
	}
}

func TestTrustGraphContradictionDetection(t *testing.T) {
	in := &correlation.CorrelationInput{
		Artifact: &artifact.Metadata{Name: "app.exe"},
	}
	res := &correlation.Result{
		IsConsistent: false,
		LayerStatuses: map[evidence.Layer]evidence.Status{
			evidence.LayerSource:       evidence.StatusVerified,
			evidence.LayerDependencies: evidence.StatusContradicted,
			evidence.LayerArtifact:     evidence.StatusMismatch,
		},
	}

	g := BuildFromCorrelation(in, res)
	contradictions := g.GetContradictionNodes()

	if len(contradictions) != 3 {
		t.Fatalf("expected 3 contradicted nodes (2 layers + decision), got %d", len(contradictions))
	}
}
