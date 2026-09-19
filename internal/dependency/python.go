package dependency

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var (
	// regex for requirements.txt e.g., requests==2.31.0, flask>=2.0.0, urllib3~=2.0
	reqLineRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]=?.*)?$`)
	hashRegex    = regexp.MustCompile(`--hash=([a-zA-Z0-9:]+)`)
)

// ParseRequirementsTxt parses standard Python requirements.txt
func ParseRequirementsTxt(filePath string) ([]*Dependency, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []*Dependency
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "-i") {
			continue
		}

		// Extract hash if present
		var checksum string
		if hashMatch := hashRegex.FindStringSubmatch(line); len(hashMatch) > 1 {
			checksum = hashMatch[1]
			line = strings.TrimSpace(hashRegex.ReplaceAllString(line, ""))
		}

		// Remove inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		matches := reqLineRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			pkgName := matches[1]
			constraint := ""
			version := ""
			if len(matches) > 2 {
				constraint = strings.TrimSpace(matches[2])
				if strings.HasPrefix(constraint, "==") {
					version = strings.TrimPrefix(constraint, "==")
				}
			}

			deps = append(deps, &Dependency{
				Name:       strings.ToLower(pkgName),
				Version:    version,
				Constraint: constraint,
				Ecosystem:  EcosystemPython,
				Direct:     true,
				Registry:   "https://pypi.org/simple",
				Checksum:   checksum,
			})
		}
	}

	return deps, scanner.Err()
}

// ParsePyprojectToml extracts declared dependencies from pyproject.toml
func ParsePyprojectToml(filePath string) ([]*Dependency, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var deps []*Dependency
	lines := strings.Split(string(content), "\n")
	inDependenciesSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Section headers
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			sec := strings.ToLower(trimmed)
			if sec == "[project.dependencies]" || sec == "[tool.poetry.dependencies]" {
				inDependenciesSection = true
			} else {
				inDependenciesSection = false
			}
			continue
		}

		if inDependenciesSection {
			// e.g. requests = "^2.31.0" or "flask>=2.0.0",
			if strings.Contains(trimmed, "=") {
				parts := strings.SplitN(trimmed, "=", 2)
				pkgName := strings.ToLower(strings.Trim(strings.TrimSpace(parts[0]), `"'`))
				if pkgName == "python" {
					continue
				}
				val := strings.Trim(strings.TrimSpace(parts[1]), `"',`)
				deps = append(deps, &Dependency{
					Name:       pkgName,
					Constraint: val,
					Ecosystem:  EcosystemPython,
					Direct:     true,
					Registry:   "https://pypi.org/simple",
				})
			} else if strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, `'`) {
				// Array format: "requests>=2.31.0",
				cleaned := strings.Trim(trimmed, `"',`)
				matches := reqLineRegex.FindStringSubmatch(cleaned)
				if len(matches) > 1 {
					pkgName := strings.ToLower(matches[1])
					constraint := ""
					if len(matches) > 2 {
						constraint = matches[2]
					}
					deps = append(deps, &Dependency{
						Name:       pkgName,
						Constraint: constraint,
						Ecosystem:  EcosystemPython,
						Direct:     true,
						Registry:   "https://pypi.org/simple",
					})
				}
			}
		}
	}

	return deps, nil
}

// ParsePoetryLock extracts resolved dependencies and hashes from poetry.lock
func ParsePoetryLock(filePath string) ([]*Dependency, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var deps []*Dependency
	lines := strings.Split(string(content), "\n")
	var currentDep *Dependency

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			if currentDep != nil && currentDep.Name != "" {
				deps = append(deps, currentDep)
			}
			currentDep = &Dependency{
				Ecosystem: EcosystemPython,
				Direct:    false, // will be resolved against manifest
				Registry:  "https://pypi.org/simple",
			}
			continue
		}

		if currentDep != nil {
			if strings.HasPrefix(trimmed, "name =") {
				parts := strings.SplitN(trimmed, "=", 2)
				currentDep.Name = strings.ToLower(strings.Trim(strings.TrimSpace(parts[1]), `"'`))
			} else if strings.HasPrefix(trimmed, "version =") {
				parts := strings.SplitN(trimmed, "=", 2)
				currentDep.Version = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		}
	}

	if currentDep != nil && currentDep.Name != "" {
		deps = append(deps, currentDep)
	}

	return deps, nil
}
