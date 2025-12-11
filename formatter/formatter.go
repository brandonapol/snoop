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
	Metadata        OutputMetadata
	ScanResults     *scanner.ScanResult
	AuditResults    []*audit.AuditResult
	TotalVulns      int
	HasErrors       bool
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
	Metadata        OutputMetadata          `json:"metadata"`
	ManifestsFound  int                     `json:"manifestsFound"`
	ManifestFiles   []scanner.DetectedFile  `json:"manifestFiles"`
	Audits          []JSONAuditResult       `json:"audits"`
	TotalVulns      int                     `json:"totalVulnerabilities"`
	Summary         audit.VulnerabilitySummary `json:"summary"`
}

// JSONAuditResult represents audit results for a single package.json
type JSONAuditResult struct {
	PackageJSON     string                     `json:"packageJson"`
	Vulnerabilities []audit.Vulnerability      `json:"vulnerabilities"`
	Summary         audit.VulnerabilitySummary `json:"summary"`
	Error           string                     `json:"error,omitempty"`
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

	for _, auditResult := range output.AuditResults {
		builder.WriteString(fmt.Sprintf("### %s\n\n", auditResult.PackageJSONPath))

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

	// Overall summary
	builder.WriteString("## Overall Summary\n\n")
	builder.WriteString(fmt.Sprintf("**Total Vulnerabilities:** %d\n\n", output.TotalVulns))

	if output.HasErrors {
		builder.WriteString("⚠️ Some audits encountered errors. See details above.\n")
	}

	return builder.String(), nil
}
