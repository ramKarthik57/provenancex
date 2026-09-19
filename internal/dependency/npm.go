package dependency

import (
	"encoding/json"
	"os"
	"strings"
)

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type packageLockV2 struct {
	Name            string                       `json:"name"`
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string]packageLockItem   `json:"packages"`
	Dependencies    map[string]packageLockLegacy `json:"dependencies"`
}

type packageLockItem struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
}

type packageLockLegacy struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
}

// ParsePackageJSON parses declared dependencies in package.json
func ParsePackageJSON(filePath string) ([]*Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []*Dependency
	for name, constraint := range pkg.Dependencies {
		deps = append(deps, &Dependency{
			Name:       name,
			Constraint: constraint,
			Ecosystem:  EcosystemNPM,
			Direct:     true,
			Registry:   "https://registry.npmjs.org",
		})
	}
	for name, constraint := range pkg.DevDependencies {
		deps = append(deps, &Dependency{
			Name:       name,
			Constraint: constraint,
			Ecosystem:  EcosystemNPM,
			Direct:     true,
			Registry:   "https://registry.npmjs.org",
		})
	}

	return deps, nil
}

// ParsePackageLockJSON parses lockfile v1, v2, and v3 package-lock.json
func ParsePackageLockJSON(filePath string) ([]*Dependency, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lock packageLockV2
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []*Dependency
	seen := make(map[string]bool)

	// v2 / v3 format: "packages"
	if len(lock.Packages) > 0 {
		for pkgPath, item := range lock.Packages {
			if pkgPath == "" {
				continue // Root project itself
			}
			// e.g. "node_modules/express" -> "express"
			cleanName := strings.TrimPrefix(pkgPath, "node_modules/")
			if idx := strings.LastIndex(pkgPath, "node_modules/"); idx != -1 {
				cleanName = pkgPath[idx+len("node_modules/"):]
			}

			if seen[cleanName] {
				continue
			}
			seen[cleanName] = true

			deps = append(deps, &Dependency{
				Name:      cleanName,
				Version:   item.Version,
				Ecosystem: EcosystemNPM,
				Direct:    !strings.Contains(strings.TrimPrefix(pkgPath, "node_modules/"), "node_modules/"),
				Registry:  extractRegistry(item.Resolved),
				Checksum:  item.Integrity,
			})
		}
	} else if len(lock.Dependencies) > 0 {
		// v1 format: "dependencies"
		for name, item := range lock.Dependencies {
			deps = append(deps, &Dependency{
				Name:      name,
				Version:   item.Version,
				Ecosystem: EcosystemNPM,
				Direct:    true,
				Registry:  extractRegistry(item.Resolved),
				Checksum:  item.Integrity,
			})
		}
	}

	return deps, nil
}

func extractRegistry(resolved string) string {
	if resolved == "" {
		return "https://registry.npmjs.org"
	}
	if strings.HasPrefix(resolved, "https://") || strings.HasPrefix(resolved, "http://") {
		parts := strings.Split(resolved, "/")
		if len(parts) >= 3 {
			return parts[0] + "//" + parts[2]
		}
	}
	return resolved
}
