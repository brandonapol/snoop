package audit

import (
	"fmt"
	"path/filepath"

	"github.com/brandonapol/snoop/osv"
)

// PythonVulnerability represents a security vulnerability in a Python package
type PythonVulnerability struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	ID          string   `json:"id"`
	FixVersions []string `json:"fix_versions"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
	Severity    string   `json:"severity"`
}

// PythonAuditResult contains the results of running Python vulnerability check
type PythonAuditResult struct {
	ManifestPath     string
	ManifestType     string
	Vulnerabilities  []PythonVulnerability
	Summary          VulnerabilitySummary
	PackagesScanned  int
	Error            error
}

// RunPythonAudit checks Python packages for vulnerabilities using OSV API
func (r *Runner) RunPythonAudit(manifestPath string, manifestType string) *PythonAuditResult {
	result := &PythonAuditResult{
		ManifestPath: manifestPath,
		ManifestType: manifestType,
	}

	// Parse the manifest file to extract packages
	var packages []PythonPackage
	var err error

	switch manifestType {
	case "requirements.txt":
		packages, err = ParseRequirementsTxt(manifestPath)
	case "Pipfile":
		packages, err = ParsePipfile(manifestPath)
	case "pyproject.toml":
		packages, err = ParsePyprojectToml(manifestPath)
	default:
		result.Error = fmt.Errorf("unsupported Python manifest type: %s", manifestType)
		return result
	}

	if err != nil {
		result.Error = fmt.Errorf("failed to parse manifest: %w", err)
		return result
	}

	if len(packages) == 0 {
		// No packages found, not an error
		return result
	}

	result.PackagesScanned = len(packages)

	if r.verbose {
		fmt.Printf("Found %d packages in %s\n", len(packages), filepath.Base(manifestPath))
	}

	// Create OSV client
	osvClient := osv.NewClient()

	// Query OSV for each package
	for _, pkg := range packages {
		if r.verbose {
			if pkg.Version != "" {
				fmt.Printf("  Checking %s==%s...\n", pkg.Name, pkg.Version)
			} else {
				fmt.Printf("  Checking %s (all versions)...\n", pkg.Name)
			}
		}

		// Query OSV API
		osvPkg := osv.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: osv.PyPI,
		}

		response, err := osvClient.QueryPackage(osvPkg)
		if err != nil {
			if r.verbose {
				fmt.Printf("    Warning: Failed to query %s: %v\n", pkg.Name, err)
			}
			continue
		}

		// Process vulnerabilities
		if len(response.Vulns) > 0 {
			if r.verbose {
				fmt.Printf("    Found %d vulnerability(ies)\n", len(response.Vulns))
			}

			for _, vuln := range response.Vulns {
				// Extract fix versions
				fixVersions := extractFixVersions(vuln)

				pythonVuln := PythonVulnerability{
					Name:        pkg.Name,
					Version:     pkg.Version,
					ID:          vuln.ID,
					FixVersions: fixVersions,
					Description: vuln.Summary,
					Aliases:     vuln.Aliases,
					Severity:    vuln.GetSeverityLevel(),
				}

				result.Vulnerabilities = append(result.Vulnerabilities, pythonVuln)

				// Update summary based on severity
				switch pythonVuln.Severity {
				case "critical":
					result.Summary.Critical++
				case "high":
					result.Summary.High++
				case "moderate", "medium":
					result.Summary.Moderate++
				case "low":
					result.Summary.Low++
				default:
					result.Summary.High++ // Default to high
				}
				result.Summary.Total++
			}
		}
	}

	return result
}

// extractFixVersions extracts fixed versions from OSV vulnerability
func extractFixVersions(vuln osv.Vulnerability) []string {
	var fixVersions []string
	seen := make(map[string]bool)

	for _, affected := range vuln.Affected {
		for _, vrange := range affected.Ranges {
			for _, event := range vrange.Events {
				if event.Fixed != "" && !seen[event.Fixed] {
					fixVersions = append(fixVersions, event.Fixed)
					seen[event.Fixed] = true
				}
			}
		}
	}

	return fixVersions
}

// HasVulnerabilities returns true if the Python audit result contains vulnerabilities
func (r *PythonAuditResult) HasVulnerabilities() bool {
	return r.Summary.Total > 0
}
