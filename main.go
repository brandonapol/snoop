package main

import (
	"fmt"
	"os"
	"time"

	"github.com/brandonapol/snoop/audit"
	"github.com/brandonapol/snoop/formatter"
	"github.com/brandonapol/snoop/scanner"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

var (
	path     string
	format   string
	severity string
	verbose  bool
)

var rootCmd = &cobra.Command{
	Use:   "snoop",
	Short: "A security audit tool for Node.js packages",
	Long: `Snoop is a CLI tool that automatically detects Node.js package manifests
in a directory and runs comprehensive security audits.

It detects package.json, package-lock.json, yarn.lock, and pnpm-lock.yaml files
and runs npm audit to identify vulnerabilities, typosquatting risks, and other
supply chain security issues.

Examples:
  # Scan current directory
  snoop

  # Scan specific directory with verbose output
  snoop --path /path/to/project --verbose

  # Output as JSON
  snoop --format json > report.json

  # Only show high and critical vulnerabilities
  snoop --severity high

  # Generate markdown report
  snoop --format markdown > SECURITY.md`,
	Version: version,
	Run: func(cmd *cobra.Command, args []string) {
		if verbose && format == "table" {
			fmt.Printf("Snoop v%s\n", version)
			fmt.Printf("Scanning directory: %s\n", path)
			fmt.Printf("Output format: %s\n", format)
			fmt.Printf("Minimum severity: %s\n", severity)
			fmt.Println()
		}

		// Create scanner
		s, err := scanner.New(path, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Scan for manifest files
		if verbose && format == "table" {
			fmt.Println("Scanning for Node.js package manifests...")
		}

		result, err := s.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
			os.Exit(1)
		}

		// Display any errors encountered during scanning
		if len(result.Errors) > 0 && verbose && format == "table" {
			fmt.Println("\nWarnings during scan:")
			for _, scanErr := range result.Errors {
				fmt.Printf("  - %v\n", scanErr)
			}
			fmt.Println()
		}

		// Check if manifests found
		if !result.HasManifests() {
			fmt.Println("No Node.js package manifests found in the specified directory.")
			return
		}

		// Check if npm is installed
		if err := audit.CheckNpmInstalled(); err != nil {
			fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
			fmt.Println("npm is required to run security audits. Please install Node.js and npm.")
			os.Exit(1)
		}

		// Get package.json files
		packageJSONFiles := result.GetManifestsByType(scanner.PackageJSON)
		if len(packageJSONFiles) == 0 {
			fmt.Println("\nNo package.json files found. Skipping npm audit.")
			return
		}

		if verbose && format == "table" {
			fmt.Printf("\nRunning npm audit on %d package.json file(s)...\n", len(packageJSONFiles))
		}

		// Create audit runner with 60 second timeout
		runner := audit.NewRunner(60*time.Second, verbose && format == "table")

		// Convert severity flag to audit.Severity type
		minSeverity := audit.Severity(severity)

		// Track overall results
		totalVulnerabilities := 0
		hasErrors := false
		auditResults := make([]*audit.AuditResult, 0)

		// Run audit on each package.json
		for _, pkgFile := range packageJSONFiles {
			if verbose && format == "table" {
				fmt.Printf("\nAuditing: %s\n", pkgFile.Path)
			}

			auditResult := runner.RunAudit(pkgFile.Path)

			if auditResult.Error != nil {
				hasErrors = true
			}

			// Filter vulnerabilities by severity
			auditResult.Vulnerabilities = audit.FilterBySeverity(auditResult.Vulnerabilities, minSeverity)

			auditResults = append(auditResults, auditResult)
			totalVulnerabilities += auditResult.Summary.Total
		}

		// Prepare output data
		output := &formatter.ScanOutput{
			Metadata: formatter.OutputMetadata{
				Timestamp:   time.Now(),
				Directory:   path,
				ToolName:    "Snoop",
				ToolVersion: version,
			},
			ScanResults:  result,
			AuditResults: auditResults,
			TotalVulns:   totalVulnerabilities,
			HasErrors:    hasErrors,
		}

		// Get formatter and format output
		formatterInst := formatter.GetFormatter(formatter.OutputFormat(format))
		formattedOutput, err := formatterInst.Format(output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(formattedOutput)
	},
}

func init() {
	// Get current directory as default
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = "."
	}

	// Define flags
	rootCmd.Flags().StringVarP(&path, "path", "p", currentDir, "Directory to scan for package manifests")
	rootCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (json, table, markdown)")
	rootCmd.Flags().StringVarP(&severity, "severity", "s", "low", "Minimum severity level to report (critical, high, medium, low)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
