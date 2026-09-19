package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

// DefaultIgnoredPaths lists directories ignored during filesystem evidence capture
var DefaultIgnoredPaths = map[string]bool{
	".git":         true,
	".cache":       true,
	"node_modules": true,
}

// BoundaryMonitor captures and analyzes filesystem modifications within a controlled directory
type BoundaryMonitor struct {
	ignored map[string]bool
}

// NewBoundaryMonitor constructs a filesystem boundary monitor
func NewBoundaryMonitor() *BoundaryMonitor {
	return &BoundaryMonitor{
		ignored: DefaultIgnoredPaths,
	}
}

// TakeSnapshot captures all files, sizes, modification times, and SHA-256 digests in rootDir
func (b *BoundaryMonitor) TakeSnapshot(rootDir string) (*Snapshot, error) {
	absDir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid directory path: %w", err)
	}

	snap := &Snapshot{
		RootDir:   absDir,
		Timestamp: time.Now().UTC(),
		Files:     make(map[string]*FileSnapshot),
	}

	err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name := info.Name()
		if info.IsDir() {
			if strings.HasPrefix(name, ".") || b.ignored[name] {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(absDir, path)
		if err != nil {
			return err
		}
		canonicalRel := filepath.ToSlash(rel)

		hash, _, err := crypto.HashFile(path)
		if err != nil {
			return err
		}

		snap.Files[canonicalRel] = &FileSnapshot{
			RelativePath: canonicalRel,
			Size:         info.Size(),
			ModTime:      info.ModTime().UTC(),
			SHA256:       hash,
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed creating snapshot of %s: %w", absDir, err)
	}

	return snap, nil
}

// ComputeDelta calculates files created, modified, or deleted between two snapshots
func (b *BoundaryMonitor) ComputeDelta(before, after *Snapshot) *Delta {
	delta := &Delta{
		CreatedFiles:  []*FileSnapshot{},
		ModifiedFiles: []*FileSnapshot{},
		DeletedFiles:  []string{},
	}

	for rel, afterFile := range after.Files {
		beforeFile, exists := before.Files[rel]
		if !exists {
			delta.CreatedFiles = append(delta.CreatedFiles, afterFile)
		} else if beforeFile.SHA256 != afterFile.SHA256 {
			delta.ModifiedFiles = append(delta.ModifiedFiles, afterFile)
		}
	}

	for rel := range before.Files {
		if _, exists := after.Files[rel]; !exists {
			delta.DeletedFiles = append(delta.DeletedFiles, rel)
		}
	}

	// Sort for deterministic reporting
	sort.Slice(delta.CreatedFiles, func(i, j int) bool {
		return delta.CreatedFiles[i].RelativePath < delta.CreatedFiles[j].RelativePath
	})
	sort.Slice(delta.ModifiedFiles, func(i, j int) bool {
		return delta.ModifiedFiles[i].RelativePath < delta.ModifiedFiles[j].RelativePath
	})
	sort.Strings(delta.DeletedFiles)

	return delta
}

// EvaluateInputs calculates set differences between expected and observed build inputs:
// Unexpected = Observed - Expected
// Missing    = Expected - Observed
func (b *BoundaryMonitor) EvaluateInputs(expected, observed []string) *InputEvaluation {
	expectedSet := make(map[string]bool)
	observedSet := make(map[string]bool)

	for _, e := range expected {
		norm := filepath.ToSlash(filepath.Clean(strings.TrimSpace(e)))
		if norm != "" && norm != "." {
			expectedSet[norm] = true
		}
	}
	for _, o := range observed {
		norm := filepath.ToSlash(filepath.Clean(strings.TrimSpace(o)))
		if norm != "" && norm != "." {
			observedSet[norm] = true
		}
	}

	var unexpected []string
	var missing []string

	for o := range observedSet {
		if !expectedSet[o] {
			unexpected = append(unexpected, o)
		}
	}

	for e := range expectedSet {
		if !observedSet[e] {
			missing = append(missing, e)
		}
	}

	sort.Strings(unexpected)
	sort.Strings(missing)

	normExpected := make([]string, 0, len(expectedSet))
	for e := range expectedSet {
		normExpected = append(normExpected, e)
	}
	sort.Strings(normExpected)

	normObserved := make([]string, 0, len(observedSet))
	for o := range observedSet {
		normObserved = append(normObserved, o)
	}
	sort.Strings(normObserved)

	return &InputEvaluation{
		ExpectedInputs:   normExpected,
		ObservedInputs:   normObserved,
		UnexpectedInputs: unexpected,
		MissingInputs:    missing,
		HasDiscrepancy:   len(unexpected) > 0 || len(missing) > 0,
	}
}
