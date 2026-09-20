package bundle

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

// Pack packages artifact, attestations, signatures, and evidence into a portable .tar.gz bundle
func Pack(opts PackOptions) error {
	if opts.ArtifactPath == "" {
		return fmt.Errorf("artifact path is required for packaging")
	}
	if opts.OutputPath == "" {
		return fmt.Errorf("output path is required for packaging")
	}

	artHash, _, err := crypto.HashFile(opts.ArtifactPath)
	if err != nil {
		return fmt.Errorf("failed to hash artifact: %w", err)
	}
	artName := filepath.Base(opts.ArtifactPath)

	bundleManifest := &BundleManifest{
		ManifestVersion: "1.0",
		CreatedAt:       time.Now().UTC(),
		Creator:         "ProvenanceX v0.1.0",
		ArtifactName:    artName,
		ArtifactSHA256:  artHash,
		Files:           make(map[string]string),
		Metadata:        opts.Metadata,
	}

	// Staging mapping: internalPath -> hostPath
	filesToPack := make(map[string]string)
	filesToPack["artifact/"+artName] = opts.ArtifactPath

	if opts.ProvenancePath != "" {
		filesToPack["provenance/provenance.json"] = opts.ProvenancePath
	}
	if opts.SBOMPath != "" {
		filesToPack["sbom/sbom.json"] = opts.SBOMPath
	}
	if opts.SignaturePath != "" {
		filesToPack["signature/signature.sig"] = opts.SignaturePath
	}
	if opts.PublicKeyPath != "" {
		filesToPack["signature/public.key"] = opts.PublicKeyPath
	}
	if opts.EvidenceLogPath != "" {
		filesToPack["evidence/evidence-log.json"] = opts.EvidenceLogPath
	}
	if opts.EvidenceManifestPath != "" {
		filesToPack["evidence/manifest.json"] = opts.EvidenceManifestPath
	}

	// Compute hashes for all staged files
	for internalRel, hostPath := range filesToPack {
		h, _, err := crypto.HashFile(hostPath)
		if err != nil {
			return fmt.Errorf("failed hashing input file %s: %w", hostPath, err)
		}
		bundleManifest.Files[internalRel] = h
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0755); err != nil {
		return fmt.Errorf("failed creating output directory: %w", err)
	}

	outFile, err := os.Create(opts.OutputPath)
	if err != nil {
		return fmt.Errorf("failed creating bundle archive: %w", err)
	}
	defer outFile.Close()

	gw := gzip.NewWriter(outFile)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Write bundle-manifest.json
	manifestBytes, err := json.MarshalIndent(bundleManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed serializing bundle manifest: %w", err)
	}

	if err := addTarEntry(tw, "bundle-manifest.json", manifestBytes); err != nil {
		return fmt.Errorf("failed writing bundle manifest to archive: %w", err)
	}

	// Write staged files
	for internalRel, hostPath := range filesToPack {
		data, err := os.ReadFile(hostPath)
		if err != nil {
			return fmt.Errorf("failed reading file %s: %w", hostPath, err)
		}
		if err := addTarEntry(tw, internalRel, data); err != nil {
			return fmt.Errorf("failed writing %s to archive: %w", internalRel, err)
		}
	}

	return nil
}

// Unpack extracts a .tar.gz bundle into destDir and verifies cryptographic checksums against bundle-manifest.json
func Unpack(bundlePath, destDir string) (*BundleManifest, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening bundle file: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed opening gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var manifest *BundleManifest
	extractedFiles := make(map[string]string) // internalRel -> hostDestPath

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed reading tar entry: %w", err)
		}

		// Security: prevent path traversal
		cleanRel := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			return nil, fmt.Errorf("illegal path traversal in bundle entry: %s", header.Name)
		}

		targetPath := filepath.Join(destDir, cleanRel)

		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return nil, err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return nil, err
		}

		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
		if err != nil {
			return nil, fmt.Errorf("failed creating target file %s: %w", targetPath, err)
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return nil, fmt.Errorf("failed writing unpacked file: %w", err)
		}
		outFile.Close()

		if filepath.ToSlash(cleanRel) == "bundle-manifest.json" {
			data, err := os.ReadFile(targetPath)
			if err != nil {
				return nil, fmt.Errorf("failed reading bundle-manifest: %w", err)
			}
			var bm BundleManifest
			if err := json.Unmarshal(data, &bm); err != nil {
				return nil, fmt.Errorf("invalid bundle-manifest JSON: %w", err)
			}
			manifest = &bm
		} else {
			extractedFiles[filepath.ToSlash(cleanRel)] = targetPath
		}
	}

	if manifest == nil {
		return nil, fmt.Errorf("corrupted bundle: missing bundle-manifest.json")
	}

	// Verify cryptographic checksums for all extracted files
	for relPath, expectedHash := range manifest.Files {
		hostPath, exists := extractedFiles[relPath]
		if !exists {
			return nil, fmt.Errorf("missing bundle file expected by manifest: %s", relPath)
		}

		actualHash, _, err := crypto.HashFile(hostPath)
		if err != nil {
			return nil, fmt.Errorf("failed hashing extracted file %s: %w", hostPath, err)
		}

		if actualHash != expectedHash {
			return nil, fmt.Errorf("tamper alert: checksum mismatch for bundled file %s (expected %s, got %s)", relPath, expectedHash, actualHash)
		}
	}

	return manifest, nil
}

func addTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0644,
		Size:     int64(len(data)),
		ModTime:  time.Unix(0, 0).UTC(), // Normalized epoch for reproducibility
		Typeflag: tar.TypeReg,
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	_, err := tw.Write(data)
	return err
}
