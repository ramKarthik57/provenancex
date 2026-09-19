package dependency

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var (
	// regex matches FROM [--platform=...] image[:tag][@digest] [AS stage]
	fromRegex = regexp.MustCompile(`(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
)

// ParseDockerfile extracts base image dependencies from a Dockerfile
func ParseDockerfile(filePath string) ([]*Dependency, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []*Dependency
	stages := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := fromRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			fullImage := matches[1]
			stageAlias := ""
			if len(matches) > 2 {
				stageAlias = matches[2]
			}

			// If FROM references a previously defined stage in multi-stage build, skip
			if stages[strings.ToLower(fullImage)] {
				if stageAlias != "" {
					stages[strings.ToLower(stageAlias)] = true
				}
				continue
			}

			if stageAlias != "" {
				stages[strings.ToLower(stageAlias)] = true
			}

			// Parse image, tag/digest
			imageName := fullImage
			version := "latest"
			checksum := ""
			registry := "docker.io"

			if strings.Contains(fullImage, "@") {
				parts := strings.SplitN(fullImage, "@", 2)
				imageName = parts[0]
				checksum = parts[1]
				version = checksum
				if strings.Contains(imageName, ":") {
					tagParts := strings.SplitN(imageName, ":", 2)
					imageName = tagParts[0]
					version = tagParts[1]
				}
			} else if strings.Contains(fullImage, ":") {
				parts := strings.SplitN(fullImage, ":", 2)
				imageName = parts[0]
				version = parts[1]
			}

			// Detect private registry or ghcr / gcr
			if strings.Contains(imageName, "/") {
				parts := strings.Split(imageName, "/")
				if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
					registry = parts[0]
				}
			}

			deps = append(deps, &Dependency{
				Name:      imageName,
				Version:   version,
				Ecosystem: EcosystemDocker,
				Direct:    true,
				Registry:  registry,
				Checksum:  checksum,
			})
		}
	}

	return deps, scanner.Err()
}
