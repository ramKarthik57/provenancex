package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ramKarthik57/provenancex/internal/artifact"
	"github.com/ramKarthik57/provenancex/internal/evidence"
	"github.com/ramKarthik57/provenancex/internal/provenance"
	"github.com/ramKarthik57/provenancex/internal/signature"
	"github.com/ramKarthik57/provenancex/pkg/crypto"
)

func TestBundlePackAndVerifyOfflineTrusted(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create target artifact
	artPath := filepath.Join(tmpDir, "sample-service.exe")
	artContent := []byte("compiled binary code for production service")
	if err := os.WriteFile(artPath, artContent, 0644); err != nil {
		t.Fatalf("failed to write artifact: %v", err)
	}
	artMeta, err := artifact.Inspect(artPath, "")
	if err != nil {
		t.Fatalf("failed inspecting artifact: %v", err)
	}

	// 2. Generate ECDSA keys & sign artifact
	keyPair, err := signature.GenerateKeyPair(signature.AlgoECDSAP256)
	if err != nil {
		t.Fatalf("failed generating key pair: %v", err)
	}
	sigBytes, err := signature.SignPayload(signature.AlgoECDSAP256, keyPair.PrivateKeyPEM, artContent)
	if err != nil {
		t.Fatalf("failed signing artifact: %v", err)
	}

	sigPath := filepath.Join(tmpDir, "signature.sig")
	keyPath := filepath.Join(tmpDir, "public.key")
	if err := os.WriteFile(sigPath, sigBytes, 0644); err != nil {
		t.Fatalf("failed writing signature: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPair.PublicKeyPEM, 0644); err != nil {
		t.Fatalf("failed writing public key: %v", err)
	}

	// 3. Generate provenance statement
	stmt, err := provenance.GenerateSLSAv1(
		artMeta,
		nil,
		"build-bundle-001",
		"go build -trimpath",
		[]string{"-o", "sample-service.exe"},
		time.Now().Add(-1*time.Minute),
		time.Now(),
	)
	if err != nil {
		t.Fatalf("failed generating provenance: %v", err)
	}
	provPath := filepath.Join(tmpDir, "provenance.json")
	provData, _ := json.MarshalIndent(stmt, "", "  ")
	if err := os.WriteFile(provPath, provData, 0644); err != nil {
		t.Fatalf("failed writing provenance: %v", err)
	}

	// 4. Generate valid append-only evidence log
	evLog := evidence.NewLog()
	evLog.Append(evidence.LayerSource, evidence.CategoryDirect, evidence.StatusVerified, "git", "commit", "abc1234", "clean repo", "test")
	evLog.Append(evidence.LayerArtifact, evidence.CategoryDerived, evidence.StatusVerified, "sample-service.exe", "sha256", artMeta.SHA256, "hash match", "test")
	evLogPath := filepath.Join(tmpDir, "evidence-log.json")
	evLogData, _ := json.MarshalIndent(evLog, "", "  ")
	if err := os.WriteFile(evLogPath, evLogData, 0644); err != nil {
		t.Fatalf("failed writing evidence log: %v", err)
	}

	// 5. Pack into bundle
	bundlePath := filepath.Join(tmpDir, "bundle.tar.gz")
	packOpts := PackOptions{
		ArtifactPath:    artPath,
		ProvenancePath:  provPath,
		SignaturePath:   sigPath,
		PublicKeyPath:   keyPath,
		EvidenceLogPath: evLogPath,
		OutputPath:      bundlePath,
	}

	if err := Pack(packOpts); err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// 6. Verify bundle offline
	res, err := VerifyOffline(bundlePath)
	if err != nil {
		t.Fatalf("VerifyOffline failed: %v", err)
	}

	if res.Verdict != "TRUSTED" {
		t.Errorf("expected TRUSTED verdict, got %s (failed checks: %v)", res.Verdict, res.FailedChecks)
	}
	if !res.BundleValid {
		t.Errorf("expected BundleValid to be true")
	}
	if !res.ArtifactMatch {
		t.Errorf("expected ArtifactMatch to be true")
	}
	if !res.SignerValid {
		t.Errorf("expected SignerValid to be true")
	}
	if !res.TamperEvidentLogValid {
		t.Errorf("expected TamperEvidentLogValid to be true")
	}
	if !res.ProvenanceValid {
		t.Errorf("expected ProvenanceValid to be true")
	}
}

func TestBundleTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()

	artPath := filepath.Join(tmpDir, "app.bin")
	if err := os.WriteFile(artPath, []byte("valid binary content"), 0644); err != nil {
		t.Fatalf("failed to write app.bin: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "tampered.tar.gz")
	if err := Pack(PackOptions{
		ArtifactPath: artPath,
		OutputPath:   bundlePath,
	}); err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	// Tamper with archive bytes directly
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("failed reading bundle: %v", err)
	}
	// Invert bytes in the middle
	if len(bundleBytes) > 50 {
		bundleBytes[40] ^= 0xFF
		bundleBytes[41] ^= 0xFF
	}
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatalf("failed writing tampered bundle: %v", err)
	}

	res, err := VerifyOffline(bundlePath)
	if err != nil {
		t.Fatalf("VerifyOffline returned unexpected Go error: %v", err)
	}

	if res.Verdict != "REJECTED" {
		t.Errorf("expected REJECTED verdict for tampered bundle, got %s", res.Verdict)
	}
	if res.BundleValid {
		t.Errorf("expected BundleValid to be false for corrupted/tampered archive")
	}
}

func TestBundleContradictingProvenance(t *testing.T) {
	tmpDir := t.TempDir()

	artPath := filepath.Join(tmpDir, "app.bin")
	if err := os.WriteFile(artPath, []byte("genuine binary"), 0644); err != nil {
		t.Fatalf("failed to write app.bin: %v", err)
	}

	// Provenance claiming a different sha256
	stmt := &provenance.InTotoStatement{
		Type:          provenance.InTotoStatementV1,
		PredicateType: provenance.SLSAProvenanceV1,
		Subject: []provenance.Subject{
			{Name: "app.bin", Digest: map[string]string{"sha256": crypto.HashBytes([]byte("completely different malicious binary"))}},
		},
		Predicate: provenance.SLSAv1Predicate{
			RunDetails: provenance.RunDetails{
				Builder: provenance.BuilderMetadata{ID: "malicious-builder"},
			},
		},
	}
	provPath := filepath.Join(tmpDir, "provenance.json")
	provData, _ := json.MarshalIndent(stmt, "", "  ")
	if err := os.WriteFile(provPath, provData, 0644); err != nil {
		t.Fatalf("failed to write provenance: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "contradict.tar.gz")
	if err := Pack(PackOptions{
		ArtifactPath:   artPath,
		ProvenancePath: provPath,
		OutputPath:     bundlePath,
	}); err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	res, err := VerifyOffline(bundlePath)
	if err != nil {
		t.Fatalf("VerifyOffline failed: %v", err)
	}

	if res.Verdict != "REJECTED" {
		t.Errorf("expected REJECTED verdict on contradicting provenance, got %s", res.Verdict)
	}
	if res.ProvenanceValid {
		t.Errorf("expected ProvenanceValid to be false")
	}
}
