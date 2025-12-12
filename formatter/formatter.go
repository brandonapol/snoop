package formatter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/brandonapol/snoop/audit"
	"github.com/brandonapol/snoop/scanner"
)

// OutputFormat represents the type of output format
type OutputFormat string

const (
	FormatJSON     OutputFormat = "json"
	FormatTable    OutputFormat = "table"
	FormatMarkdown OutputFormat = "markdown"
)

// ScanOutput contains all the data to be formatted
type ScanOutput struct {
	Metadata           OutputMetadata
	ScanResults        *scanner.ScanResult
	AuditResults       []*audit.AuditResult
	PythonAuditResults []*audit.PythonAuditResult
	GoAuditResults     []*audit.GoAuditResult
	MavenAuditResults  []*audit.MavenAuditResult
	TotalVulns         int
	HasErrors          bool
}

// OutputMetadata contains metadata about the scan
type OutputMetadata struct {
	Timestamp   time.Time `json:"timestamp"`
	Directory   string    `json:"directory"`
	ToolName    string    `json:"toolName"`
	ToolVersion string    `json:"toolVersion"`
}

// JSONOutput represents the complete JSON output structure
type JSONOutput struct {
	Metadata        OutputMetadata             `json:"metadata"`
	ManifestsFound  int                        `json:"manifestsFound"`
	ManifestFiles   []scanner.DetectedFile     `json:"manifestFiles"`
	Audits          []JSONAuditResult          `json:"audits"`
	PythonAudits    []JSONPythonAuditResult    `json:"pythonAudits,omitempty"`
	GoAudits        []JSONGoAuditResult        `json:"goAudits,omitempty"`
	MavenAudits     []JSONMavenAuditResult     `json:"mavenAudits,omitempty"`
	TotalVulns      int                        `json:"totalVulnerabilities"`
	Summary         audit.VulnerabilitySummary `json:"summary"`
}

// JSONAuditResult represents audit results for a single package.json
type JSONAuditResult struct {
	PackageJSON     string                     `json:"packageJson"`
	Vulnerabilities []audit.Vulnerability      `json:"vulnerabilities"`
	Summary         audit.VulnerabilitySummary `json:"summary"`
	Error           string                     `json:"error,omitempty"`
}

// JSONPythonAuditResult represents audit results for a single Python manifest
type JSONPythonAuditResult struct {
	ManifestPath    string                        `json:"manifestPath"`
	ManifestType    string                        `json:"manifestType"`
	Vulnerabilities []audit.PythonVulnerability   `json:"vulnerabilities"`
	Summary         audit.VulnerabilitySummary    `json:"summary"`
	Error           string                        `json:"error,omitempty"`
}

// JSONGoAuditResult represents audit results for a single Go manifest
type JSONGoAuditResult struct {
	ManifestPath    string                     `json:"manifestPath"`
	ManifestType    string                     `json:"manifestType"`
	Vulnerabilities []audit.GoVulnerability    `json:"vulnerabilities"`
	Summary         audit.VulnerabilitySummary `json:"summary"`
	Error           string                     `json:"error,omitempty"`
}

// JSONMavenAuditResult represents audit results for a single Maven manifest
type JSONMavenAuditResult struct {
	ManifestPath    string                        `json:"manifestPath"`
	ManifestType    string                        `json:"manifestType"`
	Vulnerabilities []audit.MavenVulnerability    `json:"vulnerabilities"`
	Summary         audit.VulnerabilitySummary    `json:"summary"`
	Error           string                        `json:"error,omitempty"`
}

// Formatter interface for different output formatters
type Formatter interface {
	Format(output *ScanOutput) (string, error)
}

// GetFormatter returns the appropriate formatter based on format type
func GetFormatter(format OutputFormat) Formatter {
	switch format {
	case FormatJSON:
		return &JSONFormatter{}
	case FormatTable:
		return &TableFormatter{}
	case FormatMarkdown:
		return &MarkdownFormatter{}
	default:
		return &TableFormatter{}
	}
}

// JSONFormatter implements JSON output
type JSONFormatter struct{}

func (f *JSONFormatter) Format(output *ScanOutput) (string, error) {
	jsonOut := JSONOutput{
		Metadata:       output.Metadata,
		ManifestsFound: len(output.ScanResults.Files),
		ManifestFiles:  output.ScanResults.Files,
		Audits:         make([]JSONAuditResult, 0),
		TotalVulns:     output.TotalVulns,
	}

	// Aggregate summary
	totalSummary := audit.VulnerabilitySummary{}

	for _, auditResult := range output.AuditResults {
		result := JSONAuditResult{
			PackageJSON:     auditResult.PackageJSONPath,
			Vulnerabilities: auditResult.Vulnerabilities,
			Summary:         auditResult.Summary,
		}
		if auditResult.Error != nil {
			result.Error = auditResult.Error.Error()
		}
		jsonOut.Audits = append(jsonOut.Audits, result)

		// Aggregate summary
		totalSummary.Critical += auditResult.Summary.Critical
		totalSummary.High += auditResult.Summary.High
		totalSummary.Moderate += auditResult.Summary.Moderate
		totalSummary.Low += auditResult.Summary.Low
		totalSummary.Info += auditResult.Summary.Info
		totalSummary.Total += auditResult.Summary.Total
	}

	// Add Python audit results
	jsonOut.PythonAudits = make([]JSONPythonAuditResult, 0)
	for _, pythonResult := range output.PythonAuditResults {
		result := JSONPythonAuditResult{
			ManifestPath:    pythonResult.ManifestPath,
			ManifestType:    pythonResult.ManifestType,
			Vulnerabilities: pythonResult.Vulnerabilities,
			Summary:         pythonResult.Summary,
		}
		if pythonResult.Error != nil {
			result.Error = pythonResult.Error.Error()
		}
		jsonOut.PythonAudits = append(jsonOut.PythonAudits, result)

		// Aggregate summary
		totalSummary.Critical += pythonResult.Summary.Critical
		totalSummary.High += pythonResult.Summary.High
		totalSummary.Moderate += pythonResult.Summary.Moderate
		totalSummary.Low += pythonResult.Summary.Low
		totalSummary.Info += pythonResult.Summary.Info
		totalSummary.Total += pythonResult.Summary.Total
	}

	// Add Go audit results
	jsonOut.GoAudits = make([]JSONGoAuditResult, 0)
	for _, goResult := range output.GoAuditResults {
		result := JSONGoAuditResult{
			ManifestPath:    goResult.ManifestPath,
			ManifestType:    goResult.ManifestType,
			Vulnerabilities: goResult.Vulnerabilities,
			Summary:         goResult.Summary,
		}
		if goResult.Error != nil {
			result.Error = goResult.Error.Error()
		}
		jsonOut.GoAudits = append(jsonOut.GoAudits, result)

		// Aggregate summary
		totalSummary.Critical += goResult.Summary.Critical
		totalSummary.High += goResult.Summary.High
		totalSummary.Moderate += goResult.Summary.Moderate
		totalSummary.Low += goResult.Summary.Low
		totalSummary.Info += goResult.Summary.Info
		totalSummary.Total += goResult.Summary.Total
	}

	// Add Maven audit results
	jsonOut.MavenAudits = make([]JSONMavenAuditResult, 0)
	for _, mavenResult := range output.MavenAuditResults {
		result := JSONMavenAuditResult{
			ManifestPath:    mavenResult.ManifestPath,
			ManifestType:    mavenResult.ManifestType,
			Vulnerabilities: mavenResult.Vulnerabilities,
			Summary:         mavenResult.Summary,
		}
		if mavenResult.Error != nil {
			result.Error = mavenResult.Error.Error()
		}
		jsonOut.MavenAudits = append(jsonOut.MavenAudits, result)

		// Aggregate summary
		totalSummary.Critical += mavenResult.Summary.Critical
		totalSummary.High += mavenResult.Summary.High
		totalSummary.Moderate += mavenResult.Summary.Moderate
		totalSummary.Low += mavenResult.Summary.Low
		totalSummary.Info += mavenResult.Summary.Info
		totalSummary.Total += mavenResult.Summary.Total
	}

	jsonOut.Summary = totalSummary

	data, err := json.MarshalIndent(jsonOut, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(data), nil
}

// TableFormatter implements table output using tablewriter
type TableFormatter struct{}

func (f *TableFormatter) Format(output *ScanOutput) (string, error) {
	var builder strings.Builder

	// Write header
	builder.WriteString(fmt.Sprintf("\n%s Scan Results\n", output.Metadata.ToolName))
	builder.WriteString(strings.Repeat("=", 80) + "\n")
	builder.WriteString(fmt.Sprintf("Directory: %s\n", output.Metadata.Directory))
	builder.WriteString(fmt.Sprintf("Timestamp: %s\n\n", output.Metadata.Timestamp.Format(time.RFC3339)))

	// Manifest files summary
	builder.WriteString(fmt.Sprintf("Found %d manifest file(s)\n\n", len(output.ScanResults.Files)))

	// For each audit result, create a table
	for _, auditResult := range output.AuditResults {
		if auditResult.Error != nil {
			builder.WriteString(fmt.Sprintf("Error auditing %s: %v\n\n", auditResult.PackageJSONPath, auditResult.Error))
			continue
		}

		builder.WriteString(fmt.Sprintf("Package: %s\n", auditResult.PackageJSONPath))
		builder.WriteString(auditResult.Summary.FormatSummary())
		builder.WriteString("\n")

		if len(auditResult.Vulnerabilities) > 0 {
			// Create simple table
			builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
				"Package", "Severity", "Range", "Direct"))
			builder.WriteString(strings.Repeat("-", 85) + "\n")

			for _, vuln := range auditResult.Vulnerabilities {
				isDirect := "No"
				if vuln.IsDirect {
					isDirect = "Yes"
				}

				// Truncate long package names
				pkgName := vuln.Name
				if len(pkgName) > 38 {
					pkgName = pkgName[:35] + "..."
				}

				// Truncate long ranges
				vulnRange := vuln.Range
				if len(vulnRange) > 18 {
					vulnRange = vulnRange[:15] + "..."
				}

				builder.WriteString(fmt.Sprintf("%-40s %s%-12s%s %-20s %s\n",
					pkgName,
					audit.GetSeverityColor(vuln.Severity),
					string(vuln.Severity),
					audit.ResetColor(),
					vulnRange,
					isDirect))
			}
			builder.WriteString("\n")
		}
	}

	// For each Python audit result, create a table
	for _, pythonResult := range output.PythonAuditResults {
		if pythonResult.Error != nil {
			builder.WriteString(fmt.Sprintf("Error auditing Python %s: %v\n\n", pythonResult.ManifestPath, pythonResult.Error))
			continue
		}

		builder.WriteString(fmt.Sprintf("Python Package: %s (%s)\n", pythonResult.ManifestPath, pythonResult.ManifestType))
		builder.WriteString(pythonResult.Summary.FormatSummary())
		builder.WriteString("\n")

		if len(pythonResult.Vulnerabilities) > 0 {
			// Create simple table
			builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
				"Package", "Version", "Vulnerability ID", "Fix Versions"))
			builder.WriteString(strings.Repeat("-", 85) + "\n")

			for _, vuln := range pythonResult.Vulnerabilities {
				// Truncate long package names
				pkgName := vuln.Name
				if len(pkgName) > 38 {
					pkgName = pkgName[:35] + "..."
				}

				// Truncate long version
				version := vuln.Version
				if len(version) > 10 {
					version = version[:7] + "..."
				}

				// Truncate long ID
				vulnID := vuln.ID
				if len(vulnID) > 18 {
					vulnID = vulnID[:15] + "..."
				}

				// Format fix versions
				fixVersions := strings.Join(vuln.FixVersions, ", ")
				if len(fixVersions) == 0 {
					fixVersions = "N/A"
				}

				builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
					pkgName,
					version,
					vulnID,
					fixVersions))
			}
			builder.WriteString("\n")
		}
	}

	// For each Go audit result, create a table
	for _, goResult := range output.GoAuditResults {
		if goResult.Error != nil {
			builder.WriteString(fmt.Sprintf("Error auditing Go %s: %v\n\n", goResult.ManifestPath, goResult.Error))
			continue
		}

		builder.WriteString(fmt.Sprintf("Go Module: %s\n", goResult.ManifestPath))
		builder.WriteString(goResult.Summary.FormatSummary())
		builder.WriteString("\n")

		if len(goResult.Vulnerabilities) > 0 {
			// Create simple table
			builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
				"Module", "Version", "Vulnerability ID", "Fix Versions"))
			builder.WriteString(strings.Repeat("-", 85) + "\n")

			for _, vuln := range goResult.Vulnerabilities {
				// Truncate long module names
				moduleName := vuln.Module
				if len(moduleName) > 38 {
					moduleName = moduleName[:35] + "..."
				}

				// Truncate long version
				version := vuln.Version
				if len(version) > 10 {
					version = version[:7] + "..."
				}

				// Truncate long ID
				vulnID := vuln.ID
				if len(vulnID) > 18 {
					vulnID = vulnID[:15] + "..."
				}

				// Format fix versions
				fixVersions := strings.Join(vuln.FixVersions, ", ")
				if len(fixVersions) == 0 {
					fixVersions = "N/A"
				}

				builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
					moduleName,
					version,
					vulnID,
					fixVersions))
			}
			builder.WriteString("\n")
		}
	}

	// For each Maven audit result, create a table
	for _, mavenResult := range output.MavenAuditResults {
		if mavenResult.Error != nil {
			builder.WriteString(fmt.Sprintf("Error auditing Maven %s: %v\n\n", mavenResult.ManifestPath, mavenResult.Error))
			continue
		}

		builder.WriteString(fmt.Sprintf("Maven Project: %s\n", mavenResult.ManifestPath))
		builder.WriteString(mavenResult.Summary.FormatSummary())
		builder.WriteString("\n")

		if len(mavenResult.Vulnerabilities) > 0 {
			// Create simple table
			builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
				"Dependency", "Version", "Vulnerability ID", "Fix Versions"))
			builder.WriteString(strings.Repeat("-", 85) + "\n")

			for _, vuln := range mavenResult.Vulnerabilities {
				// Create dependency name (groupId:artifactId)
				depName := fmt.Sprintf("%s:%s", vuln.GroupID, vuln.ArtifactID)
				if len(depName) > 38 {
					depName = depName[:35] + "..."
				}

				// Truncate long version
				version := vuln.Version
				if len(version) > 10 {
					version = version[:7] + "..."
				}

				// Truncate long ID
				vulnID := vuln.ID
				if len(vulnID) > 18 {
					vulnID = vulnID[:15] + "..."
				}

				// Format fix versions
				fixVersions := strings.Join(vuln.FixVersions, ", ")
				if len(fixVersions) == 0 {
					fixVersions = "N/A"
				}

				builder.WriteString(fmt.Sprintf("%-40s %-12s %-20s %s\n",
					depName,
					version,
					vulnID,
					fixVersions))
			}
			builder.WriteString("\n")
		}
	}

	// Overall summary
	builder.WriteString(strings.Repeat("=", 80) + "\n")
	builder.WriteString(fmt.Sprintf("Total vulnerabilities: %d\n", output.TotalVulns))

	return builder.String(), nil
}

// MarkdownFormatter implements markdown output
type MarkdownFormatter struct{}

func (f *MarkdownFormatter) Format(output *ScanOutput) (string, error) {
	var builder strings.Builder

	// Write header
	builder.WriteString(fmt.Sprintf("# %s Scan Results\n\n", output.Metadata.ToolName))
	builder.WriteString(fmt.Sprintf("**Directory:** %s  \n", output.Metadata.Directory))
	builder.WriteString(fmt.Sprintf("**Timestamp:** %s  \n", output.Metadata.Timestamp.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("**Version:** %s  \n\n", output.Metadata.ToolVersion))

	// Manifest files summary
	builder.WriteString("## Manifest Files\n\n")
	builder.WriteString(fmt.Sprintf("Found **%d** manifest file(s):\n\n", len(output.ScanResults.Files)))
	for _, file := range output.ScanResults.Files {
		builder.WriteString(fmt.Sprintf("- `%s` (%s)\n", file.Path, file.Type))
	}
	builder.WriteString("\n")

	// Audit results
	builder.WriteString("## Security Audit Results\n\n")

	// Node.js audit results
	if len(output.AuditResults) > 0 {
		builder.WriteString("### Node.js Packages\n\n")
	}

	for _, auditResult := range output.AuditResults {
		builder.WriteString(fmt.Sprintf("#### %s\n\n", auditResult.PackageJSONPath))

		if auditResult.Error != nil {
			builder.WriteString(fmt.Sprintf("**Error:** %v\n\n", auditResult.Error))
			continue
		}

		// Summary
		builder.WriteString("**Summary:**\n\n")
		if auditResult.Summary.Total == 0 {
			builder.WriteString("✅ No vulnerabilities found!\n\n")
		} else {
			builder.WriteString(fmt.Sprintf("- Total: **%d**\n", auditResult.Summary.Total))
			if auditResult.Summary.Critical > 0 {
				builder.WriteString(fmt.Sprintf("- Critical: **%d** 🔴\n", auditResult.Summary.Critical))
			}
			if auditResult.Summary.High > 0 {
				builder.WriteString(fmt.Sprintf("- High: **%d** 🟠\n", auditResult.Summary.High))
			}
			if auditResult.Summary.Moderate > 0 {
				builder.WriteString(fmt.Sprintf("- Moderate: **%d** 🟡\n", auditResult.Summary.Moderate))
			}
			if auditResult.Summary.Low > 0 {
				builder.WriteString(fmt.Sprintf("- Low: **%d** 🔵\n", auditResult.Summary.Low))
			}
			builder.WriteString("\n")
		}

		// Vulnerabilities table
		if len(auditResult.Vulnerabilities) > 0 {
			builder.WriteString("**Vulnerabilities:**\n\n")
			builder.WriteString("| Package | Severity | Range | Direct |\n")
			builder.WriteString("|---------|----------|-------|--------|\n")

			for _, vuln := range auditResult.Vulnerabilities {
				isDirect := "No"
				if vuln.IsDirect {
					isDirect = "Yes"
				}

				// Format severity with emoji
				severityStr := string(vuln.Severity)
				switch vuln.Severity {
				case audit.SeverityCritical:
					severityStr = "🔴 Critical"
				case audit.SeverityHigh:
					severityStr = "🟠 High"
				case audit.SeverityModerate:
					severityStr = "🟡 Moderate"
				case audit.SeverityLow:
					severityStr = "🔵 Low"
				}

				builder.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | %s |\n",
					vuln.Name, severityStr, vuln.Range, isDirect))
			}
			builder.WriteString("\n")
		}
	}

	// Python audit results
	if len(output.PythonAuditResults) > 0 {
		builder.WriteString("### Python Packages\n\n")
	}

	for _, pythonResult := range output.PythonAuditResults {
		builder.WriteString(fmt.Sprintf("#### %s (%s)\n\n", pythonResult.ManifestPath, pythonResult.ManifestType))

		if pythonResult.Error != nil {
			builder.WriteString(fmt.Sprintf("**Error:** %v\n\n", pythonResult.Error))
			continue
		}

		// Summary
		builder.WriteString("**Summary:**\n\n")
		if pythonResult.Summary.Total == 0 {
			builder.WriteString("✅ No vulnerabilities found!\n\n")
		} else {
			builder.WriteString(fmt.Sprintf("- Total: **%d**\n", pythonResult.Summary.Total))
			if pythonResult.Summary.Critical > 0 {
				builder.WriteString(fmt.Sprintf("- Critical: **%d** 🔴\n", pythonResult.Summary.Critical))
			}
			if pythonResult.Summary.High > 0 {
				builder.WriteString(fmt.Sprintf("- High: **%d** 🟠\n", pythonResult.Summary.High))
			}
			if pythonResult.Summary.Moderate > 0 {
				builder.WriteString(fmt.Sprintf("- Moderate: **%d** 🟡\n", pythonResult.Summary.Moderate))
			}
			if pythonResult.Summary.Low > 0 {
				builder.WriteString(fmt.Sprintf("- Low: **%d** 🔵\n", pythonResult.Summary.Low))
			}
			builder.WriteString("\n")
		}

		// Vulnerabilities table
		if len(pythonResult.Vulnerabilities) > 0 {
			builder.WriteString("**Vulnerabilities:**\n\n")
			builder.WriteString("| Package | Version | Vulnerability ID | Fix Versions |\n")
			builder.WriteString("|---------|---------|------------------|-------------|\n")

			for _, vuln := range pythonResult.Vulnerabilities {
				fixVersions := strings.Join(vuln.FixVersions, ", ")
				if len(fixVersions) == 0 {
					fixVersions = "N/A"
				}

				builder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n",
					vuln.Name, vuln.Version, vuln.ID, fixVersions))
			}
			builder.WriteString("\n")
		}
	}

	// Go audit results
	if len(output.GoAuditResults) > 0 {
		builder.WriteString("### Go Modules\n\n")
	}

	for _, goResult := range output.GoAuditResults {
		builder.WriteString(fmt.Sprintf("#### %s\n\n", goResult.ManifestPath))

		if goResult.Error != nil {
			builder.WriteString(fmt.Sprintf("**Error:** %v\n\n", goResult.Error))
			continue
		}

		// Summary
		builder.WriteString("**Summary:**\n\n")
		if goResult.Summary.Total == 0 {
			builder.WriteString("✅ No vulnerabilities found!\n\n")
		} else {
			builder.WriteString(fmt.Sprintf("- Total: **%d**\n", goResult.Summary.Total))
			if goResult.Summary.Critical > 0 {
				builder.WriteString(fmt.Sprintf("- Critical: **%d** 🔴\n", goResult.Summary.Critical))
			}
			if goResult.Summary.High > 0 {
				builder.WriteString(fmt.Sprintf("- High: **%d** 🟠\n", goResult.Summary.High))
			}
			if goResult.Summary.Moderate > 0 {
				builder.WriteString(fmt.Sprintf("- Moderate: **%d** 🟡\n", goResult.Summary.Moderate))
			}
			if goResult.Summary.Low > 0 {
				builder.WriteString(fmt.Sprintf("- Low: **%d** 🔵\n", goResult.Summary.Low))
			}
			builder.WriteString("\n")
		}

		// Vulnerabilities table
		if len(goResult.Vulnerabilities) > 0 {
			builder.WriteString("**Vulnerabilities:**\n\n")
			builder.WriteString("| Module | Version | Vulnerability ID | Fix Versions |\n")
			builder.WriteString("|--------|---------|------------------|-------------|\n")

			for _, vuln := range goResult.Vulnerabilities {
				fixVersions := strings.Join(vuln.FixVersions, ", ")
				if len(fixVersions) == 0 {
					fixVersions = "N/A"
				}

				builder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n",
					vuln.Module, vuln.Version, vuln.ID, fixVersions))
			}
			builder.WriteString("\n")
		}
	}

	// Maven audit results
	if len(output.MavenAuditResults) > 0 {
		builder.WriteString("### Maven/Java Projects\n\n")
	}

	for _, mavenResult := range output.MavenAuditResults {
		builder.WriteString(fmt.Sprintf("#### %s\n\n", mavenResult.ManifestPath))

		if mavenResult.Error != nil {
			builder.WriteString(fmt.Sprintf("**Error:** %v\n\n", mavenResult.Error))
			continue
		}

		// Summary
		builder.WriteString("**Summary:**\n\n")
		if mavenResult.Summary.Total == 0 {
			builder.WriteString("✅ No vulnerabilities found!\n\n")
		} else {
			builder.WriteString(fmt.Sprintf("- Total: **%d**\n", mavenResult.Summary.Total))
			if mavenResult.Summary.Critical > 0 {
				builder.WriteString(fmt.Sprintf("- Critical: **%d** 🔴\n", mavenResult.Summary.Critical))
			}
			if mavenResult.Summary.High > 0 {
				builder.WriteString(fmt.Sprintf("- High: **%d** 🟠\n", mavenResult.Summary.High))
			}
			if mavenResult.Summary.Moderate > 0 {
				builder.WriteString(fmt.Sprintf("- Moderate: **%d** 🟡\n", mavenResult.Summary.Moderate))
			}
			if mavenResult.Summary.Low > 0 {
				builder.WriteString(fmt.Sprintf("- Low: **%d** 🔵\n", mavenResult.Summary.Low))
			}
			builder.WriteString("\n")
		}

		// Vulnerabilities table
		if len(mavenResult.Vulnerabilities) > 0 {
			builder.WriteString("**Vulnerabilities:**\n\n")
			builder.WriteString("| Dependency | Version | Vulnerability ID | Fix Versions |\n")
			builder.WriteString("|------------|---------|------------------|-------------|\n")

			for _, vuln := range mavenResult.Vulnerabilities {
				depName := fmt.Sprintf("%s:%s", vuln.GroupID, vuln.ArtifactID)
				fixVersions := strings.Join(vuln.FixVersions, ", ")
				if len(fixVersions) == 0 {
					fixVersions = "N/A"
				}

				builder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n",
					depName, vuln.Version, vuln.ID, fixVersions))
			}
			builder.WriteString("\n")
		}
	}

	// Overall summary
	builder.WriteString("## Overall Summary\n\n")
	builder.WriteString(fmt.Sprintf("**Total Vulnerabilities:** %d\n\n", output.TotalVulns))

	if output.HasErrors {
		builder.WriteString("⚠️ Some audits encountered errors. See details above.\n")
	}

	return builder.String(), nil
}
