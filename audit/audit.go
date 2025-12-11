package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityModerate Severity = "moderate"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Vulnerability represents a security vulnerability in a package
type Vulnerability struct {
	Name         string          `json:"name"`
	Severity     Severity        `json:"severity"`
	IsDirect     bool            `json:"isDirect"`
	Via          []any           `json:"via"`
	Effects      []string        `json:"effects"`
	Range        string          `json:"range"`
	Nodes        []string        `json:"nodes"`
	FixAvailable json.RawMessage `json:"fixAvailable,omitempty"`
}

// VulnerabilitySummary contains summary statistics for vulnerabilities
type VulnerabilitySummary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}

// DependencyMetadata contains dependency count information
type DependencyMetadata struct {
	Prod         int `json:"prod"`
	Dev          int `json:"dev"`
	Optional     int `json:"optional"`
	Peer         int `json:"peer"`
	PeerOptional int `json:"peerOptional"`
	Total        int `json:"total"`
}

// AuditMetadata contains metadata about the audit
type AuditMetadata struct {
	Vulnerabilities VulnerabilitySummary `json:"vulnerabilities"`
	Dependencies    DependencyMetadata   `json:"dependencies"`
}

// NpmAuditResponse represents the JSON response from npm audit
type NpmAuditResponse struct {
	AuditReportVersion int                       `json:"auditReportVersion"`
	Vulnerabilities    map[string]Vulnerability  `json:"vulnerabilities"`
	Metadata           AuditMetadata             `json:"metadata"`
}

// AuditResult contains the results of running npm audit
type AuditResult struct {
	PackageJSONPath  string
	Response         *NpmAuditResponse
	Vulnerabilities  []Vulnerability
	Summary          VulnerabilitySummary
	RawOutput        string
	Error            error
}

// Runner handles npm audit execution
type Runner struct {
	timeout time.Duration
	verbose bool
}

// NewRunner creates a new audit runner
func NewRunner(timeout time.Duration, verbose bool) *Runner {
	if timeout == 0 {
		timeout = 60 * time.Second // Default 60 second timeout
	}
	return &Runner{
		timeout: timeout,
		verbose: verbose,
	}
}

// CheckNpmInstalled checks if npm is installed and available
func CheckNpmInstalled() error {
	cmd := exec.Command("npm", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("npm is not installed or not available in PATH")
	}

	if len(output) == 0 {
		return fmt.Errorf("npm is not properly configured")
	}

	return nil
}

// RunAudit executes npm audit on a package.json file
func (r *Runner) RunAudit(packageJSONPath string) *AuditResult {
	result := &AuditResult{
		PackageJSONPath: packageJSONPath,
	}

	// Get the directory containing package.json
	dir := filepath.Dir(packageJSONPath)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	// Run npm audit --json
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Dir = dir

	if r.verbose {
		fmt.Printf("Running npm audit in: %s\n", dir)
	}

	output, err := cmd.Output()

	// npm audit returns exit code 1 when vulnerabilities are found
	// This is expected behavior, not an error
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("npm audit timed out after %v", r.timeout)
			return result
		}

		// Check if it's just an exit error (non-zero exit code)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit codes 1-6 are expected when vulnerabilities are found
			// We still want to parse the output
			if r.verbose {
				fmt.Printf("npm audit exited with code: %d (vulnerabilities found)\n", exitErr.ExitCode())
			}
			// Continue to parse output
		} else {
			result.Error = fmt.Errorf("failed to run npm audit: %w", err)
			return result
		}
	}

	result.RawOutput = string(output)

	// Parse JSON output
	var auditResponse NpmAuditResponse
	if err := json.Unmarshal(output, &auditResponse); err != nil {
		result.Error = fmt.Errorf("failed to parse npm audit output: %w", err)
		return result
	}

	result.Response = &auditResponse
	result.Summary = auditResponse.Metadata.Vulnerabilities

	// Convert map to slice for easier processing
	for name, vuln := range auditResponse.Vulnerabilities {
		vuln.Name = name
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	return result
}

// FilterBySeverity filters vulnerabilities by minimum severity level
func FilterBySeverity(vulnerabilities []Vulnerability, minSeverity Severity) []Vulnerability {
	severityLevel := map[Severity]int{
		SeverityInfo:     0,
		SeverityLow:      1,
		SeverityModerate: 2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}

	minLevel := severityLevel[minSeverity]
	var filtered []Vulnerability

	for _, vuln := range vulnerabilities {
		if severityLevel[vuln.Severity] >= minLevel {
			filtered = append(filtered, vuln)
		}
	}

	return filtered
}

// HasVulnerabilities returns true if the result contains vulnerabilities
func (r *AuditResult) HasVulnerabilities() bool {
	return r.Summary.Total > 0
}

// GetSeverityColor returns ANSI color code for severity level
func GetSeverityColor(severity Severity) string {
	switch severity {
	case SeverityCritical:
		return "\033[1;31m" // Bold Red
	case SeverityHigh:
		return "\033[0;31m" // Red
	case SeverityModerate:
		return "\033[0;33m" // Yellow
	case SeverityLow:
		return "\033[0;36m" // Cyan
	default:
		return "\033[0m" // Reset
	}
}

// ResetColor returns ANSI reset code
func ResetColor() string {
	return "\033[0m"
}

// FormatSummary returns a formatted summary string
func (s *VulnerabilitySummary) FormatSummary() string {
	if s.Total == 0 {
		return "No vulnerabilities found!"
	}

	summary := fmt.Sprintf("Found %d vulnerabilities:\n", s.Total)
	if s.Critical > 0 {
		summary += fmt.Sprintf("  %sCritical: %d%s\n", GetSeverityColor(SeverityCritical), s.Critical, ResetColor())
	}
	if s.High > 0 {
		summary += fmt.Sprintf("  %sHigh: %d%s\n", GetSeverityColor(SeverityHigh), s.High, ResetColor())
	}
	if s.Moderate > 0 {
		summary += fmt.Sprintf("  %sModerate: %d%s\n", GetSeverityColor(SeverityModerate), s.Moderate, ResetColor())
	}
	if s.Low > 0 {
		summary += fmt.Sprintf("  %sLow: %d%s\n", GetSeverityColor(SeverityLow), s.Low, ResetColor())
	}
	if s.Info > 0 {
		summary += fmt.Sprintf("  Info: %d\n", s.Info)
	}

	return summary
}
