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
	Short: "A security audit tool for Node.js, Python, Go, and Maven packages",
	Long: `Snoop is a CLI tool that automatically detects Node.js, Python, Go, and Maven package manifests
in a directory and runs comprehensive security audits.

It detects package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt,
Pipfile, pyproject.toml, go.mod, and pom.xml files. It uses npm audit for Node.js and the
built-in OSV API for Python, Go, and Maven to identify vulnerabilities, typosquatting risks,
and other supply chain security issues.

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
			fmt.Println("No package manifests found in the specified directory.")
			return
		}

		// Check which types of manifests we found
		hasNodeJS := false
		hasPython := false
		hasGo := false
		hasMaven := false
		for _, file := range result.Files {
			if scanner.IsNodeJSManifest(file.Type) {
				hasNodeJS = true
			}
			if scanner.IsPythonManifest(file.Type) {
				hasPython = true
			}
			if scanner.IsGoManifest(file.Type) {
				hasGo = true
			}
			if scanner.IsMavenManifest(file.Type) {
				hasMaven = true
			}
		}

		// Check if npm is installed (only if we have Node.js manifests)
		if hasNodeJS {
			if err := audit.CheckNpmInstalled(); err != nil {
				if verbose && format == "table" {
					fmt.Fprintf(os.Stderr, "Warning: npm is not installed. Skipping Node.js audit.\n")
				}
				hasNodeJS = false
			}
		}

		// Python, Go, and Maven auditing use built-in OSV API, no external tools needed

		// If we have no tools available for Node.js and no Python/Go/Maven manifests, exit
		if !hasNodeJS && !hasPython && !hasGo && !hasMaven {
			fmt.Println("\nNo audit tools available. Please install npm for Node.js auditing.")
			fmt.Println("Python, Go, and Maven auditing use built-in vulnerability database (no additional tools needed).")
			return
		}

		// Get package.json files
		packageJSONFiles := result.GetManifestsByType(scanner.PackageJSON)
		if hasNodeJS && len(packageJSONFiles) == 0 {
			if verbose && format == "table" {
				fmt.Println("\nNo package.json files found. Skipping npm audit.")
			}
			hasNodeJS = false
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

		// Run Python audits
		pythonAuditResults := make([]*audit.PythonAuditResult, 0)

		if hasPython {
			// Get Python manifest files that pip-audit supports
			pythonManifests := []scanner.DetectedFile{}
			for _, manifestType := range []scanner.ManifestType{
				scanner.RequirementsTxt,
				scanner.Pipfile,
				scanner.PyprojectTOML,
			} {
				pythonManifests = append(pythonManifests, result.GetManifestsByType(manifestType)...)
			}

			if len(pythonManifests) > 0 && verbose && format == "table" {
				fmt.Printf("\nChecking %d Python manifest file(s) for vulnerabilities using OSV API...\n", len(pythonManifests))
			}

			for _, manifestFile := range pythonManifests {
				if verbose && format == "table" {
					fmt.Printf("\nAuditing Python: %s\n", manifestFile.Path)
				}

				pythonResult := runner.RunPythonAudit(manifestFile.Path, string(manifestFile.Type))

				if pythonResult.Error != nil {
					hasErrors = true
				}

				// Note: Python audit doesn't provide detailed severity, so we can't filter by severity
				// All vulnerabilities are currently treated as "high" in the python audit module

				pythonAuditResults = append(pythonAuditResults, pythonResult)
				totalVulnerabilities += pythonResult.Summary.Total
			}
		}

		// Run Go audits
		goAuditResults := make([]*audit.GoAuditResult, 0)

		if hasGo {
			// Get go.mod files
			goModFiles := result.GetManifestsByType(scanner.GoMod)

			if len(goModFiles) > 0 && verbose && format == "table" {
				fmt.Printf("\nChecking %d Go module file(s) for vulnerabilities using OSV API...\n", len(goModFiles))
			}

			for _, goModFile := range goModFiles {
				if verbose && format == "table" {
					fmt.Printf("\nAuditing Go: %s\n", goModFile.Path)
				}

				goResult := runner.RunGoAudit(goModFile.Path, string(goModFile.Type))

				if goResult.Error != nil {
					hasErrors = true
				}

				goAuditResults = append(goAuditResults, goResult)
				totalVulnerabilities += goResult.Summary.Total
			}
		}

		// Run Maven audits
		mavenAuditResults := make([]*audit.MavenAuditResult, 0)

		if hasMaven {
			// Get pom.xml files
			pomFiles := result.GetManifestsByType(scanner.PomXML)

			if len(pomFiles) > 0 && verbose && format == "table" {
				fmt.Printf("\nChecking %d Maven project file(s) for vulnerabilities using OSV API...\n", len(pomFiles))
			}

			for _, pomFile := range pomFiles {
				if verbose && format == "table" {
					fmt.Printf("\nAuditing Maven: %s\n", pomFile.Path)
				}

				mavenResult := runner.RunMavenAudit(pomFile.Path, string(pomFile.Type))

				if mavenResult.Error != nil {
					hasErrors = true
				}

				mavenAuditResults = append(mavenAuditResults, mavenResult)
				totalVulnerabilities += mavenResult.Summary.Total
			}
		}

		// Prepare output data
		output := &formatter.ScanOutput{
			Metadata: formatter.OutputMetadata{
				Timestamp:   time.Now(),
				Directory:   path,
				ToolName:    "Snoop",
				ToolVersion: version,
			},
			ScanResults:        result,
			AuditResults:       auditResults,
			PythonAuditResults: pythonAuditResults,
			GoAuditResults:     goAuditResults,
			MavenAuditResults:  mavenAuditResults,
			TotalVulns:         totalVulnerabilities,
			HasErrors:          hasErrors,
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
