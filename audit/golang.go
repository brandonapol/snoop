package audit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/brandonapol/snoop/osv"
)

// GoModule represents a Go module dependency
type GoModule struct {
	Path    string
	Version string
	Line    int
}

// GoVulnerability represents a security vulnerability in a Go module
type GoVulnerability struct {
	Module      string   `json:"module"`
	Version     string   `json:"version"`
	ID          string   `json:"id"`
	FixVersions []string `json:"fix_versions"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
	Severity    string   `json:"severity"`
}

// GoAuditResult contains the results of running Go vulnerability check
type GoAuditResult struct {
	ManifestPath     string
	ManifestType     string
	Vulnerabilities  []GoVulnerability
	Summary          VulnerabilitySummary
	ModulesScanned   int
	Error            error
}

// ParseGoMod parses a go.mod file and extracts dependencies
func ParseGoMod(filepath string) ([]GoModule, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open go.mod: %w", err)
	}
	defer file.Close()

	var modules []GoModule
	scanner := bufio.NewScanner(file)
	lineNum := 0
	inRequireBlock := false

	// Regex to match require statements
	// Matches: github.com/user/repo v1.2.3
	requireRegex := regexp.MustCompile(`^\s*([a-zA-Z0-9\-_\./]+)\s+v?([0-9]+\.[0-9]+\.[0-9]+[^\s]*)`)

	// Simple require statement
	simpleRequireRegex := regexp.MustCompile(`^require\s+([a-zA-Z0-9\-_\./]+)\s+v?([0-9]+\.[0-9]+\.[0-9]+[^\s]*)`)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "//") {
			continue
		}

		// Check for require block
		if strings.HasPrefix(trimmedLine, "require (") {
			inRequireBlock = true
			continue
		}

		// Check for end of require block
		if inRequireBlock && strings.Contains(trimmedLine, ")") {
			inRequireBlock = false
			continue
		}

		// Parse simple require statement (single line)
		if !inRequireBlock && strings.HasPrefix(trimmedLine, "require ") {
			matches := simpleRequireRegex.FindStringSubmatch(trimmedLine)
			if len(matches) >= 3 {
				modules = append(modules, GoModule{
					Path:    matches[1],
					Version: matches[2],
					Line:    lineNum,
				})
			}
			continue
		}

		// Parse dependencies in require block
		if inRequireBlock {
			matches := requireRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				// Skip indirect dependencies if needed
				if !strings.Contains(line, "// indirect") {
					modules = append(modules, GoModule{
						Path:    matches[1],
						Version: matches[2],
						Line:    lineNum,
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading go.mod: %w", err)
	}

	return modules, nil
}

// RunGoAudit checks Go modules for vulnerabilities using OSV API
func (r *Runner) RunGoAudit(manifestPath string, manifestType string) *GoAuditResult {
	result := &GoAuditResult{
		ManifestPath: manifestPath,
		ManifestType: manifestType,
	}

	// Only parse go.mod files
	if manifestType != "go.mod" {
		// go.sum is detected but we only audit go.mod
		return result
	}

	// Parse go.mod file
	modules, err := ParseGoMod(manifestPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to parse go.mod: %w", err)
		return result
	}

	if len(modules) == 0 {
		// No modules found
		return result
	}

	result.ModulesScanned = len(modules)

	if r.verbose {
		fmt.Printf("Found %d modules in %s\n", len(modules), filepath.Base(manifestPath))
	}

	// Create OSV client
	osvClient := osv.NewClient()

	// Query OSV for each module
	for _, module := range modules {
		if r.verbose {
			fmt.Printf("  Checking %s@%s...\n", module.Path, module.Version)
		}

		// Query OSV API
		osvPkg := osv.Package{
			Name:      module.Path,
			Version:   module.Version,
			Ecosystem: osv.Go,
		}

		response, err := osvClient.QueryPackage(osvPkg)
		if err != nil {
			if r.verbose {
				fmt.Printf("    Warning: Failed to query %s: %v\n", module.Path, err)
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

				goVuln := GoVulnerability{
					Module:      module.Path,
					Version:     module.Version,
					ID:          vuln.ID,
					FixVersions: fixVersions,
					Description: vuln.Summary,
					Aliases:     vuln.Aliases,
					Severity:    vuln.GetSeverityLevel(),
				}

				result.Vulnerabilities = append(result.Vulnerabilities, goVuln)

				// Update summary based on severity
				switch goVuln.Severity {
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

// HasVulnerabilities returns true if the Go audit result contains vulnerabilities
func (r *GoAuditResult) HasVulnerabilities() bool {
	return r.Summary.Total > 0
}
