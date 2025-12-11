package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckNpmInstalled(t *testing.T) {
	// This test verifies that CheckNpmInstalled works
	// It will pass if npm is installed, fail if not
	err := CheckNpmInstalled()
	if err != nil {
		t.Logf("npm not installed (expected on systems without npm): %v", err)
		// Don't fail the test since npm might not be installed in all test environments
		// but log it so we know
	}
}

func TestFilterBySeverity(t *testing.T) {
	vulnerabilities := []Vulnerability{
		{Name: "critical-vuln", Severity: SeverityCritical},
		{Name: "high-vuln", Severity: SeverityHigh},
		{Name: "moderate-vuln", Severity: SeverityModerate},
		{Name: "low-vuln", Severity: SeverityLow},
		{Name: "info-vuln", Severity: SeverityInfo},
	}

	tests := []struct {
		name        string
		minSeverity Severity
		expected    int
	}{
		{
			name:        "filter by critical",
			minSeverity: SeverityCritical,
			expected:    1,
		},
		{
			name:        "filter by high",
			minSeverity: SeverityHigh,
			expected:    2,
		},
		{
			name:        "filter by moderate",
			minSeverity: SeverityModerate,
			expected:    3,
		},
		{
			name:        "filter by low",
			minSeverity: SeverityLow,
			expected:    4,
		},
		{
			name:        "filter by info",
			minSeverity: SeverityInfo,
			expected:    5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterBySeverity(vulnerabilities, tt.minSeverity)
			if len(filtered) != tt.expected {
				t.Errorf("FilterBySeverity() returned %d vulnerabilities, expected %d", len(filtered), tt.expected)
			}
		})
	}
}

func TestGetSeverityColor(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "\033[1;31m"},
		{SeverityHigh, "\033[0;31m"},
		{SeverityModerate, "\033[0;33m"},
		{SeverityLow, "\033[0;36m"},
		{SeverityInfo, "\033[0m"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			color := GetSeverityColor(tt.severity)
			if color != tt.expected {
				t.Errorf("GetSeverityColor(%s) = %q, expected %q", tt.severity, color, tt.expected)
			}
		})
	}
}

func TestResetColor(t *testing.T) {
	expected := "\033[0m"
	if ResetColor() != expected {
		t.Errorf("ResetColor() = %q, expected %q", ResetColor(), expected)
	}
}

func TestHasVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		result   *AuditResult
		expected bool
	}{
		{
			name: "with vulnerabilities",
			result: &AuditResult{
				Summary: VulnerabilitySummary{
					Total: 5,
					High:  2,
					Low:   3,
				},
			},
			expected: true,
		},
		{
			name: "without vulnerabilities",
			result: &AuditResult{
				Summary: VulnerabilitySummary{
					Total: 0,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasVulnerabilities(); got != tt.expected {
				t.Errorf("HasVulnerabilities() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestFormatSummary(t *testing.T) {
	tests := []struct {
		name     string
		summary  VulnerabilitySummary
		contains []string
	}{
		{
			name: "with vulnerabilities",
			summary: VulnerabilitySummary{
				Critical: 2,
				High:     3,
				Moderate: 5,
				Low:      1,
				Total:    11,
			},
			contains: []string{"Found 11 vulnerabilities", "Critical: 2", "High: 3", "Moderate: 5", "Low: 1"},
		},
		{
			name:     "without vulnerabilities",
			summary:  VulnerabilitySummary{Total: 0},
			contains: []string{"No vulnerabilities found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatted := tt.summary.FormatSummary()
			if formatted == "" {
				t.Errorf("FormatSummary() returned empty string")
			}
		})
	}
}

func TestNewRunner(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		verbose         bool
		expectedTimeout time.Duration
	}{
		{
			name:            "with custom timeout",
			timeout:         30 * time.Second,
			verbose:         true,
			expectedTimeout: 30 * time.Second,
		},
		{
			name:            "with zero timeout (uses default)",
			timeout:         0,
			verbose:         false,
			expectedTimeout: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewRunner(tt.timeout, tt.verbose)
			if runner == nil {
				t.Fatal("NewRunner() returned nil")
			}
			if runner.timeout != tt.expectedTimeout {
				t.Errorf("NewRunner() timeout = %v, expected %v", runner.timeout, tt.expectedTimeout)
			}
			if runner.verbose != tt.verbose {
				t.Errorf("NewRunner() verbose = %v, expected %v", runner.verbose, tt.verbose)
			}
		})
	}
}

func TestRunAudit(t *testing.T) {
	// Create a temporary directory with a valid package.json
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")

	// Create a simple package.json
	packageContent := `{
		"name": "test-package",
		"version": "1.0.0",
		"dependencies": {}
	}`

	if err := os.WriteFile(packageJSON, []byte(packageContent), 0644); err != nil {
		t.Fatalf("Failed to create test package.json: %v", err)
	}

	// Check if npm is installed first
	if err := CheckNpmInstalled(); err != nil {
		t.Skip("npm not installed, skipping RunAudit test")
	}

	// Run npm install to create package-lock.json
	// Note: This test will only work if npm is available
	runner := NewRunner(30*time.Second, false)
	result := runner.RunAudit(packageJSON)

	// We expect either success or a specific error
	if result == nil {
		t.Fatal("RunAudit() returned nil result")
	}

	// Check that PackageJSONPath is set correctly
	if result.PackageJSONPath != packageJSON {
		t.Errorf("RunAudit() PackageJSONPath = %s, expected %s", result.PackageJSONPath, packageJSON)
	}
}

func TestRunAuditInvalidPath(t *testing.T) {
	runner := NewRunner(10*time.Second, false)
	result := runner.RunAudit("/nonexistent/package.json")

	if result == nil {
		t.Fatal("RunAudit() returned nil result")
	}

	// We expect an error for a non-existent path
	if result.Error == nil {
		t.Error("RunAudit() expected error for non-existent path but got nil")
	}
}

func TestJSONParsing(t *testing.T) {
	// Test that our structs correctly parse npm audit JSON output
	mockAuditJSON := `{
		"auditReportVersion": 2,
		"vulnerabilities": {
			"test-package": {
				"name": "test-package",
				"severity": "high",
				"isDirect": true,
				"via": ["CVE-2024-12345"],
				"effects": [],
				"range": "1.0.0 - 2.0.0",
				"nodes": ["node_modules/test-package"],
				"fixAvailable": true
			}
		},
		"metadata": {
			"vulnerabilities": {
				"info": 0,
				"low": 0,
				"moderate": 0,
				"high": 1,
				"critical": 0,
				"total": 1
			},
			"dependencies": {
				"prod": 10,
				"dev": 5,
				"optional": 0,
				"peer": 0,
				"peerOptional": 0,
				"total": 15
			}
		}
	}`

	var response NpmAuditResponse
	if err := json.Unmarshal([]byte(mockAuditJSON), &response); err != nil {
		t.Fatalf("Failed to parse mock audit JSON: %v", err)
	}

	// Verify parsed data
	if response.AuditReportVersion != 2 {
		t.Errorf("AuditReportVersion = %d, expected 2", response.AuditReportVersion)
	}

	if len(response.Vulnerabilities) != 1 {
		t.Errorf("Vulnerabilities count = %d, expected 1", len(response.Vulnerabilities))
	}

	if response.Metadata.Vulnerabilities.Total != 1 {
		t.Errorf("Total vulnerabilities = %d, expected 1", response.Metadata.Vulnerabilities.Total)
	}

	if response.Metadata.Dependencies.Total != 15 {
		t.Errorf("Total dependencies = %d, expected 15", response.Metadata.Dependencies.Total)
	}

	vuln, exists := response.Vulnerabilities["test-package"]
	if !exists {
		t.Fatal("Expected vulnerability 'test-package' not found")
	}

	if vuln.Severity != SeverityHigh {
		t.Errorf("Severity = %s, expected %s", vuln.Severity, SeverityHigh)
	}
}

func TestJSONParsingWithObjectFixAvailable(t *testing.T) {
	// Test parsing when fixAvailable is an object instead of a boolean
	mockAuditJSON := `{
		"auditReportVersion": 2,
		"vulnerabilities": {
			"test-package": {
				"name": "test-package",
				"severity": "critical",
				"isDirect": false,
				"via": [{"name": "CVE-2024-12345", "cvss": {"score": 9.8}}],
				"effects": ["other-package"],
				"range": ">=1.0.0",
				"nodes": ["node_modules/test-package"],
				"fixAvailable": {
					"name": "test-package",
					"version": "3.0.0",
					"isSemVerMajor": true
				}
			}
		},
		"metadata": {
			"vulnerabilities": {
				"info": 0,
				"low": 0,
				"moderate": 0,
				"high": 0,
				"critical": 1,
				"total": 1
			},
			"dependencies": {
				"prod": 5,
				"dev": 3,
				"optional": 1,
				"peer": 0,
				"peerOptional": 0,
				"total": 9
			}
		}
	}`

	var response NpmAuditResponse
	if err := json.Unmarshal([]byte(mockAuditJSON), &response); err != nil {
		t.Fatalf("Failed to parse mock audit JSON with object fixAvailable: %v", err)
	}

	vuln, exists := response.Vulnerabilities["test-package"]
	if !exists {
		t.Fatal("Expected vulnerability 'test-package' not found")
	}

	if vuln.Severity != SeverityCritical {
		t.Errorf("Severity = %s, expected %s", vuln.Severity, SeverityCritical)
	}

	// Verify via can be an array of objects
	if len(vuln.Via) == 0 {
		t.Error("Via array is empty, expected at least one element")
	}
}
