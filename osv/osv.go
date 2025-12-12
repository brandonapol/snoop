package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OSV API endpoint
const osvAPIURL = "https://api.osv.dev/v1/query"

// Ecosystem represents the package ecosystem
type Ecosystem string

const (
	PyPI  Ecosystem = "PyPI"
	Go    Ecosystem = "Go"
	NPM   Ecosystem = "npm"
	Maven Ecosystem = "Maven"
)

// Package represents a package to query
type Package struct {
	Name      string     `json:"name"`
	Version   string     `json:"version,omitempty"`
	Ecosystem Ecosystem  `json:"ecosystem"`
}

// QueryRequest represents the OSV API query request
type QueryRequest struct {
	Package Package `json:"package"`
}

// Severity represents vulnerability severity
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Reference represents a vulnerability reference
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected represents affected package versions
type Affected struct {
	Package           Package          `json:"package"`
	Ranges            []VersionRange   `json:"ranges,omitempty"`
	Versions          []string         `json:"versions,omitempty"`
	EcosystemSpecific map[string]any   `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any   `json:"database_specific,omitempty"`
}

// VersionRange represents a version range
type VersionRange struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event represents a version event (introduced/fixed)
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Vulnerability represents an OSV vulnerability
type Vulnerability struct {
	ID         string      `json:"id"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Aliases    []string    `json:"aliases,omitempty"`
	Modified   string      `json:"modified"`
	Published  string      `json:"published"`
	References []Reference `json:"references,omitempty"`
	Severity   []Severity  `json:"severity,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
}

// QueryResponse represents the OSV API query response
type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

// Client represents an OSV API client
type Client struct {
	httpClient *http.Client
	apiURL     string
}

// NewClient creates a new OSV API client
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiURL: osvAPIURL,
	}
}

// QueryPackage queries the OSV API for vulnerabilities in a package
func (c *Client) QueryPackage(pkg Package) (*QueryResponse, error) {
	request := QueryRequest{
		Package: pkg,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response QueryResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// GetSeverityScore extracts a severity score from vulnerability
func (v *Vulnerability) GetSeverityScore() string {
	if len(v.Severity) > 0 {
		return v.Severity[0].Score
	}
	return "unknown"
}

// GetSeverityLevel returns a simplified severity level
func (v *Vulnerability) GetSeverityLevel() string {
	// Check aliases for CVE severity indicators
	for _, alias := range v.Aliases {
		if len(alias) > 0 {
			// Most vulnerabilities are at least "high" if they have a CVE
			return "high"
		}
	}

	// Default to high for any vulnerability
	return "high"
}

// GetCVEs returns all CVE identifiers for this vulnerability
func (v *Vulnerability) GetCVEs() []string {
	var cves []string
	for _, alias := range v.Aliases {
		if len(alias) > 4 && alias[:4] == "CVE-" {
			cves = append(cves, alias)
		}
	}
	return cves
}
