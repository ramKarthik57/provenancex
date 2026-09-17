package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

// DefaultIgnoredDirs defines directories that should never be scanned for build artifacts
var DefaultIgnoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	".vscode":      true,
	".idea":        true,
	".cache":       true,
	"vendor":       true,
}

// Collection represents a set of software artifacts produced by a build
type Collection struct {
	Artifacts  []*Metadata        `json:"artifacts"`
	MerkleTree *crypto.MerkleTree `json:"merkleTree"`
	MerkleRoot string             `json:"merkleRoot"`
	TotalSize  int64              `json:"totalSize"`
	Count      int                `json:"count"`
}

// NewCollection constructs an artifact collection and computes its Merkle Tree
func NewCollection(items []*Metadata) (*Collection, error) {
	if items == nil {
		items = []*Metadata{}
	}

	// Sort artifacts canonically by relative path
	sort.Slice(items, func(i, j int) bool {
		return items[i].RelativePath < items[j].RelativePath
	})

	var totalSize int64
	hashes := make([]string, len(items))
	for i, item := range items {
		hashes[i] = item.SHA256
		totalSize += item.Size
	}

	tree, err := crypto.NewMerkleTree(hashes)
	if err != nil {
		return nil, fmt.Errorf("failed to build artifact Merkle tree: %w", err)
	}

	return &Collection{
		Artifacts:  items,
		MerkleTree: tree,
		MerkleRoot: tree.RootHash(),
		TotalSize:  totalSize,
		Count:      len(items),
	}, nil
}

// ScanDirectory discovers and inspects all artifacts inside a target directory, skipping VCS and dependency caches
func ScanDirectory(dirPath string) (*Collection, error) {
	absDir, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute directory %s: %w", dirPath, err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return nil, fmt.Errorf("cannot access directory %s: %w", absDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absDir)
	}

	var artifacts []*Metadata
	err = filepath.Walk(absDir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		name := f.Name()
		if f.IsDir() {
			// Skip hidden or well-known non-artifact directories
			if strings.HasPrefix(name, ".") || DefaultIgnoredDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			return nil
		}

		meta, err := Inspect(path, absDir)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, meta)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed scanning directory %s: %w", absDir, err)
	}

	return NewCollection(artifacts)
}
