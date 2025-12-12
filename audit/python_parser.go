package audit

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// PythonPackage represents a Python package with its version
type PythonPackage struct {
	Name    string
	Version string
	Line    int // Line number where found (for debugging)
}

// ParseRequirementsTxt parses a requirements.txt file and extracts packages
func ParseRequirementsTxt(filepath string) ([]PythonPackage, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer file.Close()

	var packages []PythonPackage
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Regex to match package specifications
	// Matches: package==1.0.0, package>=1.0.0, package~=1.0, etc.
	pkgRegex := regexp.MustCompile(`^([a-zA-Z0-9\-_\.]+)\s*([=<>~!]+)\s*([0-9\.\*]+.*)$`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip lines with -r (requirements file includes)
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement") {
			continue
		}

		// Skip editable installs and URLs
		if strings.HasPrefix(line, "-e ") || strings.Contains(line, "://") {
			continue
		}

		// Parse package specification
		matches := pkgRegex.FindStringSubmatch(line)
		if len(matches) >= 4 {
			pkg := PythonPackage{
				Name:    strings.TrimSpace(matches[1]),
				Version: strings.TrimSpace(matches[3]),
				Line:    lineNum,
			}

			// Handle version specifiers - for OSV we need exact version
			// If it's ==, use that version. For other operators, we'll skip for now
			operator := strings.TrimSpace(matches[2])
			if operator == "==" {
				packages = append(packages, pkg)
			} else {
				// For >=, ~=, etc., we can't determine exact version
				// OSV API can work without version to get all vulns
				pkg.Version = "" // Query all versions
				packages = append(packages, pkg)
			}
		} else {
			// Try simple package name without version
			if matched, _ := regexp.MatchString(`^[a-zA-Z0-9\-_\.]+$`, line); matched {
				packages = append(packages, PythonPackage{
					Name:    line,
					Version: "", // No version specified
					Line:    lineNum,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading requirements.txt: %w", err)
	}

	return packages, nil
}

// ParsePipfile parses a Pipfile and extracts packages
func ParsePipfile(filepath string) ([]PythonPackage, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Pipfile: %w", err)
	}
	defer file.Close()

	var packages []PythonPackage
	scanner := bufio.NewScanner(file)
	inPackagesSection := false
	lineNum := 0

	// Simple TOML parsing for [packages] section
	pkgRegex := regexp.MustCompile(`^([a-zA-Z0-9\-_\.]+)\s*=\s*"==([0-9\.]+)"`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check for [packages] section
		if line == "[packages]" {
			inPackagesSection = true
			continue
		}

		// Check for other sections (end of [packages])
		if strings.HasPrefix(line, "[") && line != "[packages]" {
			inPackagesSection = false
			continue
		}

		// Parse packages in [packages] section
		if inPackagesSection && line != "" && !strings.HasPrefix(line, "#") {
			matches := pkgRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				packages = append(packages, PythonPackage{
					Name:    strings.TrimSpace(matches[1]),
					Version: strings.TrimSpace(matches[2]),
					Line:    lineNum,
				})
			} else {
				// Try to match package = "*" (any version)
				simpleRegex := regexp.MustCompile(`^([a-zA-Z0-9\-_\.]+)\s*=\s*"\*"`)
				matches := simpleRegex.FindStringSubmatch(line)
				if len(matches) >= 2 {
					packages = append(packages, PythonPackage{
						Name:    strings.TrimSpace(matches[1]),
						Version: "", // Any version
						Line:    lineNum,
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Pipfile: %w", err)
	}

	return packages, nil
}

// ParsePyprojectToml parses a pyproject.toml file and extracts dependencies
func ParsePyprojectToml(filepath string) ([]PythonPackage, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open pyproject.toml: %w", err)
	}
	defer file.Close()

	var packages []PythonPackage
	scanner := bufio.NewScanner(file)
	inDependenciesSection := false
	lineNum := 0

	// Regex to match dependencies in TOML format
	// Matches: "package==1.0.0", "package>=1.0.0", etc.
	pkgRegex := regexp.MustCompile(`"([a-zA-Z0-9\-_\.]+)\s*([=<>~!]+)\s*([0-9\.]+.*)"`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Check for dependencies section
		if strings.Contains(line, "dependencies") && strings.Contains(line, "[") {
			inDependenciesSection = true
			continue
		}

		// Check for end of array
		if inDependenciesSection && strings.Contains(line, "]") {
			inDependenciesSection = false
			continue
		}

		// Parse dependencies
		if inDependenciesSection && line != "" && !strings.HasPrefix(line, "#") {
			matches := pkgRegex.FindStringSubmatch(line)
			if len(matches) >= 4 {
				operator := strings.TrimSpace(matches[2])
				version := strings.TrimSpace(matches[3])

				// For == we use exact version, for others we query all versions
				if operator != "==" {
					version = ""
				}

				packages = append(packages, PythonPackage{
					Name:    strings.TrimSpace(matches[1]),
					Version: version,
					Line:    lineNum,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading pyproject.toml: %w", err)
	}

	return packages, nil
}
