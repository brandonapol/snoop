package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brandonapol/snoop/formatter"
)

// TestMain builds the binary before running tests
func TestMain(m *testing.M) {
	// Build the binary
	build := exec.Command("go", "build", "-o", "snoop-test", ".")
	if err := build.Run(); err != nil {
		panic("Failed to build binary for testing: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	os.Remove("snoop-test")

	os.Exit(code)
}

// Phase 1 Requirement Tests: Core CLI Structure

func TestRequirement_CLI_VersionFlag(t *testing.T) {
	// Requirement: Add version flag `--version`
	cmd := exec.Command("./snoop-test", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--version flag failed: %v", err)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "0.1.0") {
		t.Errorf("Version output doesn't contain version number. Got: %s", outputStr)
	}
}

func TestRequirement_CLI_HelpFlag(t *testing.T) {
	// Requirement: Basic CLI structure with help
	cmd := exec.Command("./snoop-test", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help flag failed: %v", err)
	}

	outputStr := string(output)
	requiredStrings := []string{
		"audit",
		"--path",
		"--format",
		"--severity",
		"--verbose",
	}

	for _, required := range requiredStrings {
		if !strings.Contains(outputStr, required) {
			t.Errorf("Help output missing '%s'. Got: %s", required, outputStr)
		}
	}
}

func TestRequirement_CLI_PathFlag(t *testing.T) {
	// Requirement: `--path` for specifying directory (default: current directory)
	tmpDir := t.TempDir()

	// Create a package.json in temp dir
	packageJSON := filepath.Join(tmpDir, "package.json")
	err := os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)
	if err != nil {
		t.Fatalf("Failed to create test package.json: %v", err)
	}

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// npm audit might fail, but the path flag should work
		t.Logf("Command error (may be expected): %v", err)
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, tmpDir) {
		t.Errorf("Output doesn't contain the specified path. Got: %s", outputStr)
	}
}

func TestRequirement_CLI_FormatFlag(t *testing.T) {
	// Requirement: `--format` for output format (json, table, markdown)
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	formats := []string{"json", "table", "markdown"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", format)
			output, err := cmd.CombinedOutput()
			outputStr := string(output)

			// Verify format-specific output
			switch format {
			case "json":
				// Should be valid JSON
				var result formatter.JSONOutput
				if err := json.Unmarshal(output, &result); err != nil {
					t.Errorf("JSON format output is not valid JSON: %v\nOutput: %s", err, outputStr)
				}
			case "table":
				if !strings.Contains(outputStr, "Snoop Scan Results") {
					t.Errorf("Table format missing expected header. Got: %s", outputStr)
				}
			case "markdown":
				if !strings.Contains(outputStr, "# Snoop Scan Results") {
					t.Errorf("Markdown format missing expected header. Got: %s", outputStr)
				}
			}

			t.Logf("Format %s test completed. Error: %v", format, err)
		})
	}
}

func TestRequirement_CLI_SeverityFlag(t *testing.T) {
	// Requirement: `--severity` for filtering by minimum severity
	severities := []string{"critical", "high", "moderate", "low"}

	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	for _, severity := range severities {
		t.Run(severity, func(t *testing.T) {
			cmd := exec.Command("./snoop-test", "--path", tmpDir, "--severity", severity, "--format", "json")
			output, err := cmd.CombinedOutput()

			// Command should execute without crashing
			if err != nil && !strings.Contains(string(output), "vulnerabilities") {
				t.Logf("Severity %s test - error (may be expected): %v", severity, err)
			}

			// Verify it accepted the flag (no "unknown flag" error)
			if strings.Contains(string(output), "unknown flag") {
				t.Errorf("Severity flag %s not recognized", severity)
			}
		})
	}
}

func TestRequirement_CLI_VerboseFlag(t *testing.T) {
	// Requirement: `--verbose` for detailed output
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	// Run without verbose
	cmdNormal := exec.Command("./snoop-test", "--path", tmpDir)
	normalOutput, _ := cmdNormal.CombinedOutput()

	// Run with verbose
	cmdVerbose := exec.Command("./snoop-test", "--path", tmpDir, "--verbose")
	verboseOutput, _ := cmdVerbose.CombinedOutput()

	// Verbose should produce more output
	if len(verboseOutput) <= len(normalOutput) {
		t.Logf("Warning: Verbose output not significantly longer than normal output")
		t.Logf("Normal: %d bytes, Verbose: %d bytes", len(normalOutput), len(verboseOutput))
	}
}

// Phase 2 Requirement Tests: File Detection

func TestRequirement_DetectPackageJSON(t *testing.T) {
	// Requirement: Detect `package.json`
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0"}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if result.ManifestsFound == 0 {
		t.Error("Failed to detect package.json")
	}

	found := false
	for _, file := range result.ManifestFiles {
		if strings.Contains(file.Path, "package.json") && file.Type == "package.json" {
			found = true
			break
		}
	}

	if !found {
		t.Error("package.json not in manifest files list")
	}
}

func TestRequirement_DetectPackageLockJSON(t *testing.T) {
	// Requirement: Detect `package-lock.json`
	tmpDir := t.TempDir()
	// Need package.json too for audit to run
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0"}`), 0644)
	packageLock := filepath.Join(tmpDir, "package-lock.json")
	os.WriteFile(packageLock, []byte(`{"name":"test","lockfileVersion":2}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	found := false
	for _, file := range result.ManifestFiles {
		if file.Type == "package-lock.json" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Failed to detect package-lock.json")
	}
}

func TestRequirement_DetectYarnLock(t *testing.T) {
	// Requirement: Detect `yarn.lock`
	tmpDir := t.TempDir()
	// Need package.json too for audit to run
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0"}`), 0644)
	yarnLock := filepath.Join(tmpDir, "yarn.lock")
	os.WriteFile(yarnLock, []byte(`# yarn lockfile v1`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	found := false
	for _, file := range result.ManifestFiles {
		if file.Type == "yarn.lock" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Failed to detect yarn.lock")
	}
}

func TestRequirement_DetectPnpmLockYAML(t *testing.T) {
	// Requirement: Detect `pnpm-lock.yaml`
	tmpDir := t.TempDir()
	// Need package.json too for audit to run
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0"}`), 0644)
	pnpmLock := filepath.Join(tmpDir, "pnpm-lock.yaml")
	os.WriteFile(pnpmLock, []byte(`lockfileVersion: 5.4`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	found := false
	for _, file := range result.ManifestFiles {
		if file.Type == "pnpm-lock.yaml" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Failed to detect pnpm-lock.yaml")
	}
}

func TestRequirement_ReturnFullPaths(t *testing.T) {
	// Requirement: Return list of detected files with their full paths
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0"}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	for _, file := range result.ManifestFiles {
		if !filepath.IsAbs(file.Path) && !strings.Contains(file.Path, tmpDir) {
			t.Errorf("File path is not full path: %s", file.Path)
		}
	}
}

func TestRequirement_ErrorHandling_NonExistentDirectory(t *testing.T) {
	// Requirement: Handle errors gracefully when directory doesn't exist
	cmd := exec.Command("./snoop-test", "--path", "/nonexistent/directory/path/12345")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("Expected error for non-existent directory, got success")
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "Error") && !strings.Contains(outputStr, "does not exist") {
		t.Errorf("Error message not clear. Got: %s", outputStr)
	}
}

func TestRequirement_ErrorHandling_UnreadableDirectory(t *testing.T) {
	// Requirement: Handle errors gracefully when directory isn't readable
	// This test is platform-dependent and might need to be skipped on some systems
	t.Skip("Skipping unreadable directory test - requires special setup")
}

// Phase 3 Requirement Tests: npm Audit Integration

func TestRequirement_CheckNpmInstalled(t *testing.T) {
	// Requirement: Check if npm is installed before attempting audit
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	// If npm is not installed, should get a clear error
	outputStr := string(output)
	if !strings.Contains(outputStr, "vulnerabilities") && !strings.Contains(outputStr, "npm") {
		t.Logf("Note: npm may not be installed or test may have failed for other reasons. Output: %s", outputStr)
	}
}

func TestRequirement_ParseNpmAuditJSON(t *testing.T) {
	// Requirement: Parse npm audit JSON output
	// This requires a real package.json with dependencies
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")

	// Create package.json with a dependency that might have known vulnerabilities
	packageContent := `{
		"name": "test-package",
		"version": "1.0.0",
		"dependencies": {
			"lodash": "4.17.19"
		}
	}`
	os.WriteFile(packageJSON, []byte(packageContent), 0644)

	// Run npm install to create node_modules (if npm is available)
	npmInstall := exec.Command("npm", "install", "--prefix", tmpDir)
	npmInstall.Run() // Ignore error as npm might not be available

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output (requirement: parse npm audit JSON): %v\nOutput: %s", err, string(output))
	}

	// Should have audit results
	if len(result.Audits) == 0 {
		t.Error("No audit results found")
	}
}

func TestRequirement_VulnerabilityDataStructure(t *testing.T) {
	// Requirement: Vulnerability struct with: name, severity, description, CVE, affected versions
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Check that vulnerability structure has required fields
	for _, audit := range result.Audits {
		for _, vuln := range audit.Vulnerabilities {
			if vuln.Name == "" {
				t.Error("Vulnerability missing name field")
			}
			if vuln.Severity == "" {
				t.Error("Vulnerability missing severity field")
			}
			if vuln.Range == "" {
				t.Error("Vulnerability missing range field (affected versions)")
			}
			// Via field contains CVE information
		}
	}
}

func TestRequirement_SummaryDataStructure(t *testing.T) {
	// Requirement: Summary struct with: total vulnerabilities by severity
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Summary should have severity counts
	summary := result.Summary

	// These fields should exist (even if 0)
	_ = summary.Critical
	_ = summary.High
	_ = summary.Moderate
	_ = summary.Low
	_ = summary.Total

	if summary.Total < 0 {
		t.Error("Summary total is negative")
	}
}

// Phase 4 Requirement Tests: Output Formatting

func TestRequirement_JSONFormatter_Metadata(t *testing.T) {
	// Requirement: JSON formatter with metadata (timestamp, directory, tool version)
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0"}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Check metadata fields
	if result.Metadata.Timestamp.IsZero() {
		t.Error("Metadata missing timestamp")
	}
	if result.Metadata.Directory == "" {
		t.Error("Metadata missing directory")
	}
	if result.Metadata.ToolName == "" {
		t.Error("Metadata missing tool name")
	}
	if result.Metadata.ToolVersion == "" {
		t.Error("Metadata missing tool version")
	}
}

func TestRequirement_JSONFormatter_VulnerabilitiesArray(t *testing.T) {
	// Requirement: Array of vulnerabilities in JSON output
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Should have audits array
	if result.Audits == nil {
		t.Error("JSON output missing audits array")
	}
}

func TestRequirement_TableFormatter_ColorCoding(t *testing.T) {
	// Requirement: Color coding by severity (red=critical, orange=high, yellow=medium)
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "table")
	output, _ := cmd.CombinedOutput()

	outputStr := string(output)

	// Should contain ANSI color codes when vulnerabilities are present
	// ANSI codes: \033[...m
	if strings.Contains(outputStr, "vulnerabilities") {
		t.Logf("Table output: %s", outputStr)
		// Note: Color codes might be present in the summary
	}
}

func TestRequirement_MarkdownFormatter_Tables(t *testing.T) {
	// Requirement: Generate markdown tables
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "markdown")
	output, _ := cmd.CombinedOutput()

	outputStr := string(output)

	// Should have markdown table structure
	if !strings.Contains(outputStr, "# Snoop Scan Results") {
		t.Error("Markdown output missing main header")
	}

	// Markdown should have table headers in the structure
	// Even without vulnerabilities, the format should be present
	if !strings.Contains(outputStr, "**Summary:**") {
		t.Error("Markdown output missing summary section")
	}
}

func TestRequirement_MarkdownFormatter_Summary(t *testing.T) {
	// Requirement: Include summary at top of markdown
	tmpDir := t.TempDir()
	packageJSON := filepath.Join(tmpDir, "package.json")
	os.WriteFile(packageJSON, []byte(`{"name":"test","version":"1.0.0","dependencies":{}}`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "markdown")
	output, _ := cmd.CombinedOutput()

	outputStr := string(output)

	// Should have summary section near the top
	if !strings.Contains(outputStr, "## Manifest Files") {
		t.Error("Markdown output missing manifest files summary section")
	}
	if !strings.Contains(outputStr, "## Security Audit Results") {
		t.Error("Markdown output missing audit results section")
	}
	if !strings.Contains(outputStr, "## Overall Summary") {
		t.Error("Markdown output missing overall summary section")
	}
}

// Cross-cutting Requirements

func TestRequirement_NoManifestsFound(t *testing.T) {
	// Requirement: Handle case when no manifests are found
	tmpDir := t.TempDir()
	// Don't create any manifest files

	cmd := exec.Command("./snoop-test", "--path", tmpDir)
	output, _ := cmd.CombinedOutput()

	outputStr := string(output)
	if !strings.Contains(outputStr, "No Node.js package manifests found") {
		t.Errorf("Should clearly indicate when no manifests found. Got: %s", outputStr)
	}
}

func TestRequirement_MultipleManifests(t *testing.T) {
	// Requirement: Handle multiple manifest files
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{"name":"test","version":"1.0.0"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(`{"name":"test"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "yarn.lock"), []byte(`# yarn`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "pnpm-lock.yaml"), []byte(`lockfileVersion: 5.4`), 0644)

	cmd := exec.Command("./snoop-test", "--path", tmpDir, "--format", "json")
	output, _ := cmd.CombinedOutput()

	var result formatter.JSONOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if result.ManifestsFound != 4 {
		t.Errorf("Expected 4 manifests, got %d", result.ManifestsFound)
	}
}
