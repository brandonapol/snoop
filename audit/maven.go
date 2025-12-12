package audit

import (
	"fmt"
	"path/filepath"

	"github.com/brandonapol/snoop/osv"
)

// MavenVulnerability represents a security vulnerability in a Maven package
type MavenVulnerability struct {
	GroupID     string   `json:"group_id"`
	ArtifactID  string   `json:"artifact_id"`
	Version     string   `json:"version"`
	ID          string   `json:"id"`
	FixVersions []string `json:"fix_versions"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
	Severity    string   `json:"severity"`
}

// MavenAuditResult contains the results of running Maven vulnerability check
type MavenAuditResult struct {
	ManifestPath    string
	ManifestType    string
	Vulnerabilities []MavenVulnerability
	Summary         VulnerabilitySummary
	PackagesScanned int
	Error           error
}

// RunMavenAudit checks Maven dependencies for vulnerabilities using OSV API
func (r *Runner) RunMavenAudit(manifestPath string, manifestType string) *MavenAuditResult {
	result := &MavenAuditResult{
		ManifestPath: manifestPath,
		ManifestType: manifestType,
	}

	// Only parse pom.xml files
	if manifestType != "pom.xml" {
		return result
	}

	// Parse pom.xml file
	dependencies, err := ParsePomXML(manifestPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to parse pom.xml: %w", err)
		return result
	}

	if len(dependencies) == 0 {
		// No dependencies found
		return result
	}

	result.PackagesScanned = len(dependencies)

	if r.verbose {
		fmt.Printf("Found %d Maven dependencies in %s\n", len(dependencies), filepath.Base(manifestPath))
	}

	// Create OSV client
	osvClient := osv.NewClient()

	// Query OSV for each dependency
	for _, dep := range dependencies {
		if r.verbose {
			fmt.Printf("  Checking %s@%s...\n", dep.GetMavenPackageName(), dep.Version)
		}

		// Query OSV API
		osvPkg := osv.Package{
			Name:      dep.GetMavenPackageName(),
			Version:   dep.Version,
			Ecosystem: osv.Maven,
		}

		response, err := osvClient.QueryPackage(osvPkg)
		if err != nil {
			if r.verbose {
				fmt.Printf("    Warning: Failed to query %s: %v\n", dep.GetMavenPackageName(), err)
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

				mavenVuln := MavenVulnerability{
					GroupID:     dep.GroupID,
					ArtifactID:  dep.ArtifactID,
					Version:     dep.Version,
					ID:          vuln.ID,
					FixVersions: fixVersions,
					Description: vuln.Summary,
					Aliases:     vuln.Aliases,
					Severity:    vuln.GetSeverityLevel(),
				}

				result.Vulnerabilities = append(result.Vulnerabilities, mavenVuln)

				// Update summary based on severity
				switch mavenVuln.Severity {
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

// HasVulnerabilities returns true if the Maven audit result contains vulnerabilities
func (r *MavenAuditResult) HasVulnerabilities() bool {
	return r.Summary.Total > 0
}
