package dependency

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AllowedRegistries defines baseline recognized package registries
var AllowedRegistries = map[string]bool{
	"https://registry.npmjs.org": true,
	"https://pypi.org/simple":    true,
	"docker.io":                  true,
	"registry.hub.docker.com":    true,
	"ghcr.io":                    true,
	"gcr.io":                     true,
	"quay.io":                    true,
}

// Analyzer inspects and cross-references dependencies across ecosystems
type Analyzer struct {
	allowedRegistries map[string]bool
}

// NewAnalyzer constructs a dependency analyzer
func NewAnalyzer(customRegistries []string) *Analyzer {
	registries := make(map[string]bool)
	for k, v := range AllowedRegistries {
		registries[k] = v
	}
	for _, r := range customRegistries {
		registries[strings.TrimSpace(r)] = true
	}
	return &Analyzer{
		allowedRegistries: registries,
	}
}

// Analyze scans a project directory for dependency manifests and lockfiles,
// performing cross-layer consistency and drift analysis.
func (a *Analyzer) Analyze(dirPath string) (*Report, error) {
	absDir, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("invalid directory path %s: %w", dirPath, err)
	}

	report := &Report{
		Timestamp:    time.Now().UTC(),
		Directory:    absDir,
		Ecosystems:   []Ecosystem{},
		Dependencies: []*Dependency{},
		Mismatches:   []*Mismatch{},
		IsConsistent: true,
	}

	// 1. Node.js inspection
	pkgJSONPath := filepath.Join(absDir, "package.json")
	pkgLockPath := filepath.Join(absDir, "package-lock.json")
	if _, err := os.Stat(pkgJSONPath); err == nil {
		report.Ecosystems = append(report.Ecosystems, EcosystemNPM)
		manifestDeps, mErr := ParsePackageJSON(pkgJSONPath)
		if mErr != nil {
			return nil, fmt.Errorf("failed to parse package.json: %w", mErr)
		}

		if _, err := os.Stat(pkgLockPath); err == nil {
			report.HasLockfile = true
			lockDeps, lErr := ParsePackageLockJSON(pkgLockPath)
			if lErr != nil {
				return nil, fmt.Errorf("failed to parse package-lock.json: %w", lErr)
			}
			a.correlateNPM(manifestDeps, lockDeps, report)
		} else {
			report.HasLockfile = false
			report.IsConsistent = false
			report.Mismatches = append(report.Mismatches, &Mismatch{
				Type:        MismatchMissingLockfile,
				Package:     "package.json",
				Ecosystem:   EcosystemNPM,
				Expected:    "package-lock.json present",
				Observed:    "package-lock.json missing",
				Description: "NPM manifest package.json is missing accompanying lockfile package-lock.json",
				Severity:    "REJECTED",
			})
			report.Dependencies = append(report.Dependencies, manifestDeps...)
		}
	}

	// 2. Python inspection
	reqTxtPath := filepath.Join(absDir, "requirements.txt")
	pyprojectPath := filepath.Join(absDir, "pyproject.toml")
	poetryLockPath := filepath.Join(absDir, "poetry.lock")

	var pythonManifestDeps []*Dependency
	hasPythonManifest := false

	if _, err := os.Stat(reqTxtPath); err == nil {
		hasPythonManifest = true
		deps, _ := ParseRequirementsTxt(reqTxtPath)
		pythonManifestDeps = append(pythonManifestDeps, deps...)
	}
	if _, err := os.Stat(pyprojectPath); err == nil {
		hasPythonManifest = true
		deps, _ := ParsePyprojectToml(pyprojectPath)
		pythonManifestDeps = append(pythonManifestDeps, deps...)
	}

	if hasPythonManifest {
		report.Ecosystems = append(report.Ecosystems, EcosystemPython)
		if _, err := os.Stat(poetryLockPath); err == nil {
			report.HasLockfile = true
			lockDeps, _ := ParsePoetryLock(poetryLockPath)
			a.correlatePython(pythonManifestDeps, lockDeps, report)
		} else {
			// For requirements.txt, check if all direct deps have pinned versions (==)
			unpinnedCount := 0
			for _, d := range pythonManifestDeps {
				if d.Version == "" && !strings.HasPrefix(d.Constraint, "==") {
					unpinnedCount++
					report.Mismatches = append(report.Mismatches, &Mismatch{
						Type:        MismatchVersionDrift,
						Package:     d.Name,
						Ecosystem:   EcosystemPython,
						Expected:    "pinned version (==x.y.z)",
						Observed:    d.Constraint,
						Description: fmt.Sprintf("Python dependency '%s' is not strictly pinned and no lockfile is present", d.Name),
						Severity:    "WARNING",
					})
				}
			}
			if unpinnedCount > 0 {
				report.IsConsistent = false
			}
			report.Dependencies = append(report.Dependencies, pythonManifestDeps...)
		}
	}

	// 3. Docker inspection
	dockerfilePath := filepath.Join(absDir, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); err == nil {
		report.Ecosystems = append(report.Ecosystems, EcosystemDocker)
		dockerDeps, dErr := ParseDockerfile(dockerfilePath)
		if dErr == nil {
			for _, d := range dockerDeps {
				report.Dependencies = append(report.Dependencies, d)
				// Check for unpinned latest or missing digest
				if d.Version == "latest" && d.Checksum == "" {
					report.Mismatches = append(report.Mismatches, &Mismatch{
						Type:        MismatchVersionDrift,
						Package:     d.Name,
						Ecosystem:   EcosystemDocker,
						Expected:    "pinned tag or digest (@sha256:...)",
						Observed:    "latest",
						Description: fmt.Sprintf("Docker base image '%s' uses mutable 'latest' tag without digest pinning", d.Name),
						Severity:    "WARNING",
					})
					report.IsConsistent = false
				}
				// Verify registry allowlist
				if !a.isAllowedRegistry(d.Registry) {
					report.Mismatches = append(report.Mismatches, &Mismatch{
						Type:        MismatchUntrustedRegistry,
						Package:     d.Name,
						Ecosystem:   EcosystemDocker,
						Expected:    "authorized registry",
						Observed:    d.Registry,
						Description: fmt.Sprintf("Docker base image '%s' references unauthorized registry '%s'", d.Name, d.Registry),
						Severity:    "REJECTED",
					})
					report.IsConsistent = false
				}
			}
		}
	}

	// Calculate counts
	directCount := 0
	for _, d := range report.Dependencies {
		if d.Direct {
			directCount++
		}
	}
	report.DirectCount = directCount
	report.TotalCount = len(report.Dependencies)

	return report, nil
}

func (a *Analyzer) correlateNPM(manifestDeps, lockDeps []*Dependency, report *Report) {
	lockMap := make(map[string]*Dependency)
	for _, ld := range lockDeps {
		lockMap[ld.Name] = ld
	}

	for _, md := range manifestDeps {
		ld, exists := lockMap[md.Name]
		if !exists {
			report.IsConsistent = false
			report.Mismatches = append(report.Mismatches, &Mismatch{
				Type:        MismatchLockfileDiscrepancy,
				Package:     md.Name,
				Ecosystem:   EcosystemNPM,
				Expected:    fmt.Sprintf("lockfile entry for %s", md.Constraint),
				Observed:    "missing in package-lock.json",
				Description: fmt.Sprintf("Declared NPM dependency '%s' is missing in package-lock.json", md.Name),
				Severity:    "REJECTED",
			})
			report.Dependencies = append(report.Dependencies, md)
			continue
		}

		md.Version = ld.Version
		md.Checksum = ld.Checksum
		md.Registry = ld.Registry

		// Check registry
		if !a.isAllowedRegistry(ld.Registry) {
			report.IsConsistent = false
			report.Mismatches = append(report.Mismatches, &Mismatch{
				Type:        MismatchUntrustedRegistry,
				Package:     md.Name,
				Ecosystem:   EcosystemNPM,
				Expected:    "https://registry.npmjs.org",
				Observed:    ld.Registry,
				Description: fmt.Sprintf("NPM package '%s' resolved to unauthorized registry '%s'", md.Name, ld.Registry),
				Severity:    "REJECTED",
			})
		}

		report.Dependencies = append(report.Dependencies, md)
	}

	// Add transitive dependencies from lockfile
	for _, ld := range lockDeps {
		if !ld.Direct {
			report.Dependencies = append(report.Dependencies, ld)
		}
	}
}

func (a *Analyzer) correlatePython(manifestDeps, lockDeps []*Dependency, report *Report) {
	lockMap := make(map[string]*Dependency)
	for _, ld := range lockDeps {
		lockMap[ld.Name] = ld
	}

	for _, md := range manifestDeps {
		ld, exists := lockMap[md.Name]
		if !exists {
			report.IsConsistent = false
			report.Mismatches = append(report.Mismatches, &Mismatch{
				Type:        MismatchLockfileDiscrepancy,
				Package:     md.Name,
				Ecosystem:   EcosystemPython,
				Expected:    fmt.Sprintf("poetry.lock entry for %s", md.Constraint),
				Observed:    "missing in poetry.lock",
				Description: fmt.Sprintf("Declared Python dependency '%s' is missing in poetry.lock", md.Name),
				Severity:    "REJECTED",
			})
			report.Dependencies = append(report.Dependencies, md)
			continue
		}

		md.Version = ld.Version
		report.Dependencies = append(report.Dependencies, md)
	}
}

func (a *Analyzer) isAllowedRegistry(reg string) bool {
	if reg == "" {
		return true
	}
	clean := strings.TrimRight(strings.ToLower(reg), "/")
	for allowed := range a.allowedRegistries {
		if strings.TrimRight(strings.ToLower(allowed), "/") == clean {
			return true
		}
	}
	return false
}
