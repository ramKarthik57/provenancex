package artifact

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

// Metadata represents comprehensive integrity and provenance metadata for a build artifact
type Metadata struct {
	Name         string            `json:"name"`
	Path         string            `json:"path"`
	RelativePath string            `json:"relativePath"`
	SHA256       string            `json:"sha256"`
	Size         int64             `json:"size"`
	MIMEType     string            `json:"mimeType"`
	CreatedAt    time.Time         `json:"createdAt"`
	Permissions  string            `json:"permissions"`
	BuildID      string            `json:"buildId,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

// Inspect inspects a single artifact file, computing its SHA-256, size, MIME type, and metadata
func Inspect(path string, baseDir string) (*Metadata, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for %s: %w", path, err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("artifact not found: %s", absPath)
		}
		return nil, fmt.Errorf("failed to stat artifact %s: %w", absPath, err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("target path is a directory, not an artifact file: %s", absPath)
	}

	sha256Hash, size, err := crypto.HashFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute artifact hash: %w", err)
	}

	mimeType, err := detectMIMEType(absPath)
	if err != nil {
		mimeType = "application/octet-stream"
	}

	relPath := filepath.Base(absPath)
	if baseDir != "" {
		if r, err := filepath.Rel(baseDir, absPath); err == nil {
			relPath = filepath.ToSlash(r)
		}
	}

	return &Metadata{
		Name:         info.Name(),
		Path:         absPath,
		RelativePath: relPath,
		SHA256:       sha256Hash,
		Size:         size,
		MIMEType:     mimeType,
		CreatedAt:    info.ModTime().UTC(),
		Permissions:  info.Mode().String(),
		Tags:         make(map[string]string),
	}, nil
}

// detectMIMEType sniffs the first 512 bytes of the file and falls back to extension heuristic
func detectMIMEType(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}

	detected := http.DetectContentType(buffer[:n])

	// Refine generic octet-stream for well-known artifact extensions
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".exe":
		return "application/x-msdownload", nil
	case ".zip":
		return "application/zip", nil
	case ".tar":
		return "application/x-tar", nil
	case ".gz", ".tgz":
		return "application/gzip", nil
	case ".whl":
		return "application/x-wheel+zip", nil
	case ".jar":
		return "application/java-archive", nil
	case ".json":
		return "application/json", nil
	case ".spdx", ".spdx.json":
		return "application/spdx+json", nil
	case ".cdx.json":
		return "application/vnd.cyclonedx+json", nil
	case ".sig":
		return "application/pgp-signature", nil
	default:
		return detected, nil
	}
}
