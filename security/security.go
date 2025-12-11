package security

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Popular npm packages for typosquatting detection (top 100)
var popularPackages = []string{
	"react", "react-dom", "lodash", "express", "axios", "webpack", "typescript",
	"eslint", "prettier", "babel-core", "jest", "mocha", "chai", "request",
	"moment", "commander", "async", "underscore", "chalk", "debug",
	"npm", "yarn", "pnpm", "next", "vue", "angular", "jquery",
	"bootstrap", "tailwindcss", "sass", "less", "postcss",
	"webpack-cli", "webpack-dev-server", "babel-loader", "ts-loader",
	"dotenv", "cors", "body-parser", "mongoose", "sequelize",
	"redis", "pg", "mysql", "mongodb", "sqlite3",
	"passport", "bcrypt", "jsonwebtoken", "uuid", "validator",
	"nodemon", "pm2", "forever", "cross-env",
	"socket.io", "ws", "graphql", "apollo-server",
	"redux", "mobx", "zustand", "recoil",
	"react-router", "react-router-dom", "vue-router",
	"@types/node", "@types/react", "@types/express",
	"tslib", "core-js", "regenerator-runtime",
	"rimraf", "mkdirp", "glob", "minimatch",
	"semver", "yargs", "inquirer", "ora",
	"fs-extra", "path", "util", "stream",
	"bluebird", "q", "co", "rxjs",
	"date-fns", "dayjs", "luxon",
	"classnames", "clsx", "prop-types",
	"fast-glob", "chokidar", "nodemailer",
	"cheerio", "jsdom", "puppeteer", "playwright",
	"sharp", "jimp", "canvas",
	"compression", "helmet", "morgan",
}

// LevenshteinDistance calculates the edit distance between two strings
func LevenshteinDistance(s1, s2 string) int {
	s1Lower := strings.ToLower(s1)
	s2Lower := strings.ToLower(s2)

	if s1Lower == s2Lower {
		return 0
	}

	if len(s1Lower) == 0 {
		return len(s2Lower)
	}
	if len(s2Lower) == 0 {
		return len(s1Lower)
	}

	// Create matrix
	matrix := make([][]int, len(s1Lower)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2Lower)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(s1Lower); i++ {
		for j := 1; j <= len(s2Lower); j++ {
			cost := 0
			if s1Lower[i-1] != s2Lower[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1Lower)][len(s2Lower)]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// TyposquattingRisk represents a potential typosquatting risk
type TyposquattingRisk struct {
	PackageName    string
	SimilarTo      string
	Distance       int
	Confidence     string // "high", "medium", "low"
}

// CheckTyposquatting checks if a package name is similar to popular packages
func CheckTyposquatting(packageName string, threshold int) *TyposquattingRisk {
	if threshold <= 0 {
		threshold = 2 // Default threshold
	}

	bestMatch := ""
	minDistance := threshold + 1

	for _, popular := range popularPackages {
		distance := LevenshteinDistance(packageName, popular)

		// Skip exact matches
		if distance == 0 {
			return nil
		}

		if distance < minDistance {
			minDistance = distance
			bestMatch = popular
		}
	}

	if minDistance <= threshold {
		confidence := "high"
		if minDistance == 2 {
			confidence = "medium"
		} else if minDistance > 2 {
			confidence = "low"
		}

		return &TyposquattingRisk{
			PackageName: packageName,
			SimilarTo:   bestMatch,
			Distance:    minDistance,
			Confidence:  confidence,
		}
	}

	return nil
}

// PackageMetadata represents npm package metadata
type PackageMetadata struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Time         map[string]string      `json:"time"`
	Maintainers  []Maintainer           `json:"maintainers"`
	Repository   map[string]interface{} `json:"repository"`
	Downloads    int                    `json:"-"` // Fetched separately
	LastModified time.Time              `json:"-"`
}

// Maintainer represents a package maintainer
type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// PackageMetadataCache simple in-memory cache
var metadataCache = make(map[string]*PackageMetadata)

// FetchPackageMetadata fetches metadata from npm registry
func FetchPackageMetadata(packageName string) (*PackageMetadata, error) {
	// Check cache first
	if cached, ok := metadataCache[packageName]; ok {
		return cached, nil
	}

	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var metadata PackageMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	// Parse last modified time from time field
	if len(metadata.Time) > 0 {
		if modifiedStr, ok := metadata.Time["modified"]; ok {
			if t, err := time.Parse(time.RFC3339, modifiedStr); err == nil {
				metadata.LastModified = t
			}
		}
	}

	// Cache the result
	metadataCache[packageName] = &metadata

	return &metadata, nil
}

// MaintainerRisk represents risks related to package maintenance
type MaintainerRisk struct {
	PackageName      string
	Issues           []string
	RiskLevel        string // "high", "medium", "low"
	LastUpdate       time.Time
	MaintainerCount  int
}

// AnalyzeMaintainerRisk analyzes maintenance-related risks
func AnalyzeMaintainerRisk(metadata *PackageMetadata) *MaintainerRisk {
	risk := &MaintainerRisk{
		PackageName:     metadata.Name,
		Issues:          make([]string, 0),
		RiskLevel:       "low",
		LastUpdate:      metadata.LastModified,
		MaintainerCount: len(metadata.Maintainers),
	}

	// Check last update time
	if !metadata.LastModified.IsZero() {
		twoYearsAgo := time.Now().AddDate(-2, 0, 0)
		if metadata.LastModified.Before(twoYearsAgo) {
			risk.Issues = append(risk.Issues, fmt.Sprintf("Not updated in over 2 years (last: %s)", metadata.LastModified.Format("2006-01-02")))
			risk.RiskLevel = "medium"
		}
	}

	// Check maintainer count
	if len(metadata.Maintainers) == 1 {
		risk.Issues = append(risk.Issues, "Single maintainer")
		if risk.RiskLevel == "low" {
			risk.RiskLevel = "medium"
		}
	} else if len(metadata.Maintainers) == 0 {
		risk.Issues = append(risk.Issues, "No maintainers listed")
		risk.RiskLevel = "high"
	}

	if len(risk.Issues) == 0 {
		return nil // No risks found
	}

	return risk
}

// SuspiciousPattern represents a suspicious pattern in package.json
type SuspiciousPattern struct {
	PackageName  string
	ScriptType   string   // "install", "preinstall", "postinstall"
	ScriptContent string
	RiskLevel    string
}

// DetectSuspiciousPatterns checks for suspicious install scripts
func DetectSuspiciousPatterns(packageJSONPath string) ([]*SuspiciousPattern, error) {
	// Read package.json
	data, err := io.ReadAll(nil) // This will be properly implemented
	if err != nil {
		return nil, err
	}

	var pkgJSON map[string]interface{}
	if err := json.Unmarshal(data, &pkgJSON); err != nil {
		return nil, err
	}

	patterns := make([]*SuspiciousPattern, 0)

	// Check scripts
	if scripts, ok := pkgJSON["scripts"].(map[string]interface{}); ok {
		suspiciousScripts := []string{"install", "preinstall", "postinstall"}

		for _, scriptName := range suspiciousScripts {
			if scriptContent, ok := scripts[scriptName].(string); ok {
				pattern := &SuspiciousPattern{
					PackageName:   pkgJSON["name"].(string),
					ScriptType:    scriptName,
					ScriptContent: scriptContent,
					RiskLevel:     "medium",
				}

				// Higher risk if script downloads or executes external code
				if strings.Contains(scriptContent, "curl") ||
					strings.Contains(scriptContent, "wget") ||
					strings.Contains(scriptContent, "http") {
					pattern.RiskLevel = "high"
				}

				patterns = append(patterns, pattern)
			}
		}
	}

	return patterns, nil
}

// SecurityReport aggregates all security findings
type SecurityReport struct {
	PackageName        string
	TyposquattingRisk  *TyposquattingRisk
	MaintainerRisk     *MaintainerRisk
	SuspiciousPatterns []*SuspiciousPattern
	OverallRiskLevel   string
}

// GenerateSecurityReport creates a comprehensive security report
func GenerateSecurityReport(packageName string, packageJSONPath string) (*SecurityReport, error) {
	report := &SecurityReport{
		PackageName:        packageName,
		SuspiciousPatterns: make([]*SuspiciousPattern, 0),
		OverallRiskLevel:   "low",
	}

	// Check typosquatting
	report.TyposquattingRisk = CheckTyposquatting(packageName, 2)

	// Fetch metadata and analyze maintainer risk
	metadata, err := FetchPackageMetadata(packageName)
	if err == nil {
		report.MaintainerRisk = AnalyzeMaintainerRisk(metadata)
	}

	// Detect suspicious patterns
	patterns, err := DetectSuspiciousPatterns(packageJSONPath)
	if err == nil {
		report.SuspiciousPatterns = patterns
	}

	// Calculate overall risk level
	if report.TyposquattingRisk != nil && report.TyposquattingRisk.Confidence == "high" {
		report.OverallRiskLevel = "high"
	} else if report.MaintainerRisk != nil && report.MaintainerRisk.RiskLevel == "high" {
		report.OverallRiskLevel = "high"
	} else if len(report.SuspiciousPatterns) > 0 {
		for _, pattern := range report.SuspiciousPatterns {
			if pattern.RiskLevel == "high" {
				report.OverallRiskLevel = "high"
				break
			}
		}
		if report.OverallRiskLevel != "high" {
			report.OverallRiskLevel = "medium"
		}
	} else if report.TyposquattingRisk != nil || report.MaintainerRisk != nil {
		report.OverallRiskLevel = "medium"
	}

	return report, nil
}
