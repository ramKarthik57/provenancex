package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

var (
	// ErrEmptyInput is returned when an empty input is provided where prohibited
	ErrEmptyInput = errors.New("input data cannot be empty")
	// ErrFileNotFound is returned when the target file does not exist
	ErrFileNotFound = errors.New("file not found")
)

// HashBytes computes the SHA-256 hex-encoded hash of arbitrary byte slice
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashFile streams a file and computes its SHA-256 hex-encoded digest
func HashFile(filePath string) (string, int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, fmt.Errorf("%w: %s", ErrFileNotFound, filePath)
		}
		return "", 0, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	hasher := sha256.New()
	written, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, fmt.Errorf("failed to compute hash for %s: %w", filePath, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

// MerkleNode represents a node in a Merkle tree
type MerkleNode struct {
	Hash  string      `json:"hash"`
	Left  *MerkleNode `json:"left,omitempty"`
	Right *MerkleNode `json:"right,omitempty"`
}

// MerkleTree computes a deterministic Merkle Tree over a set of artifact hashes.
// Uses RFC 6962 domain separation (0x00 for leaf hashes, 0x01 for internal nodes)
// to prevent second-preimage attacks.
type MerkleTree struct {
	Root       *MerkleNode `json:"root"`
	LeafHashes []string    `json:"leafHashes"`
}

// NewMerkleTree constructs a MerkleTree from a list of leaf hashes (hex strings).
// Leaves are sorted deterministically to ensure reproducibility across platforms.
func NewMerkleTree(leafHashes []string) (*MerkleTree, error) {
	if len(leafHashes) == 0 {
		return &MerkleTree{
			Root: &MerkleNode{
				Hash: HashBytes([]byte{}),
			},
			LeafHashes: []string{},
		}, nil
	}

	// Copy and sort leaves for canonical ordering
	sortedLeaves := make([]string, len(leafHashes))
	copy(sortedLeaves, leafHashes)
	sort.Strings(sortedLeaves)

	nodes := make([]*MerkleNode, len(sortedLeaves))
	for i, leaf := range sortedLeaves {
		leafBytes, err := hex.DecodeString(leaf)
		if err != nil {
			// If not hex, hash raw string
			leafBytes = []byte(leaf)
		}
		// Prefix with 0x00 for leaf separation
		leafDigest := sha256.Sum256(append([]byte{0x00}, leafBytes...))
		nodes[i] = &MerkleNode{
			Hash: hex.EncodeToString(leafDigest[:]),
		}
	}

	for len(nodes) > 1 {
		var nextLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				left := nodes[i]
				right := nodes[i+1]
				leftBytes, _ := hex.DecodeString(left.Hash)
				rightBytes, _ := hex.DecodeString(right.Hash)

				combined := append([]byte{0x01}, leftBytes...)
				combined = append(combined, rightBytes...)
				parentHash := sha256.Sum256(combined)

				nextLevel = append(nextLevel, &MerkleNode{
					Hash:  hex.EncodeToString(parentHash[:]),
					Left:  left,
					Right: right,
				})
			} else {
				// Odd number of nodes: duplicate last node for balanced tree
				left := nodes[i]
				leftBytes, _ := hex.DecodeString(left.Hash)
				combined := append([]byte{0x01}, leftBytes...)
				combined = append(combined, leftBytes...)
				parentHash := sha256.Sum256(combined)

				nextLevel = append(nextLevel, &MerkleNode{
					Hash:  hex.EncodeToString(parentHash[:]),
					Left:  left,
					Right: left,
				})
			}
		}
		nodes = nextLevel
	}

	return &MerkleTree{
		Root:       nodes[0],
		LeafHashes: sortedLeaves,
	}, nil
}

// RootHash returns the hex-encoded root hash of the Merkle Tree
func (m *MerkleTree) RootHash() string {
	if m == nil || m.Root == nil {
		return ""
	}
	return m.Root.Hash
}
