package dependency

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRequirementsTxt(t *testing.T) {
	tmpDir := t.TempDir()
	reqFile := filepath.Join(tmpDir, "requirements.txt")
	content := `
# Production dependencies
requests==2.31.0 --hash=sha256:abc123456
flask>=2.0.1
urllib3~=2.0.0
`
	if err := os.WriteFile(reqFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed writing test requirements.txt: %v", err)
	}

	deps, err := ParseRequirementsTxt(reqFile)
	if err != nil {
		t.Fatalf("ParseRequirementsTxt failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	if deps[0].Name != "requests" || deps[0].Version != "2.31.0" {
		t.Errorf("expected requests==2.31.0, got %s==%s", deps[0].Name, deps[0].Version)
	}
	if deps[0].Checksum != "sha256:abc123456" {
		t.Errorf("expected checksum sha256:abc123456, got %s", deps[0].Checksum)
	}
}

func TestParsePackageJSONAndLock(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := filepath.Join(tmpDir, "package.json")
	pkgLock := filepath.Join(tmpDir, "package-lock.json")

	jsonContent := `{
  "name": "sample-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}`
	lockContent := `{
  "name": "sample-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/psL6iVEkiGu9P0R6328YHM87VMiq801WbP328RkdSRTu810V43bQ==",
      "dev": false
    },
    "node_modules/typescript": {
      "version": "5.0.4",
      "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.0.4.tgz",
      "integrity": "sha512-cW9T5W9xY37cc+jfEnaUvX91QOT26vyCU47tBo49qFa19VqeQKcq4WGyZKz04nOj4M3o4PWMr2HY3KUDdHwDA==",
      "dev": true
    }
  }
}`

	os.WriteFile(pkgJSON, []byte(jsonContent), 0644)
	os.WriteFile(pkgLock, []byte(lockContent), 0644)

	analyzer := NewAnalyzer(nil)
	report, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if !report.HasLockfile {
		t.Errorf("expected HasLockfile to be true")
	}
	if report.DirectCount != 2 {
		t.Errorf("expected 2 direct dependencies, got %d", report.DirectCount)
	}
	if !report.IsConsistent {
		t.Errorf("expected report to be consistent, got mismatches: %+v", report.Mismatches)
	}
}

func TestMissingLockfileAndUntrustedRegistry(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := filepath.Join(tmpDir, "package.json")
	pkgLock := filepath.Join(tmpDir, "package-lock.json")

	// Missing lockfile scenario
	os.WriteFile(pkgJSON, []byte(`{"dependencies": {"lodash": "4.17.21"}}`), 0644)

	analyzer := NewAnalyzer(nil)
	report, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if report.HasLockfile {
		t.Errorf("expected HasLockfile to be false")
	}
	if report.IsConsistent {
		t.Errorf("expected report to be inconsistent due to missing lockfile")
	}

	// Untrusted registry scenario
	untrustedLock := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "http://evil-untrusted-mirror.com/lodash.tgz"
    }
  }
}`
	os.WriteFile(pkgLock, []byte(untrustedLock), 0644)
	report, err = analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze with untrusted registry failed: %v", err)
	}

	if report.IsConsistent {
		t.Errorf("expected inconsistent status for untrusted registry")
	}
	hasRegistryMismatch := false
	for _, m := range report.Mismatches {
		if m.Type == MismatchUntrustedRegistry {
			hasRegistryMismatch = true
			break
		}
	}
	if !hasRegistryMismatch {
		t.Errorf("expected MismatchUntrustedRegistry alert")
	}
}

func TestParseDockerfile(t *testing.T) {
	tmpDir := t.TempDir()
	dockerfile := filepath.Join(tmpDir, "Dockerfile")
	content := `
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o app

FROM alpine:3.20@sha256:beefcafe1234567890
WORKDIR /app
COPY --from=builder /app/app .
CMD ["./app"]
`
	os.WriteFile(dockerfile, []byte(content), 0644)

	deps, err := ParseDockerfile(dockerfile)
	if err != nil {
		t.Fatalf("ParseDockerfile failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 base images, got %d", len(deps))
	}
	if deps[0].Name != "golang" || deps[0].Version != "1.23-alpine" {
		t.Errorf("unexpected first base image: %+v", deps[0])
	}
	if deps[1].Name != "alpine" || deps[1].Checksum != "sha256:beefcafe1234567890" {
		t.Errorf("unexpected second base image: %+v", deps[1])
	}
}
