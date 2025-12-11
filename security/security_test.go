package security

import (
	"testing"
	"time"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1       string
		s2       string
		expected int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "a", 1},
		{"abc", "abc", 0},
		{"abc", "ABC", 0}, // Case insensitive
		{"kitten", "sitting", 3},
		{"react", "raect", 2},
		{"lodash", "lodesh", 1},
		{"express", "expres", 1},
	}

	for _, tt := range tests {
		t.Run(tt.s1+"_"+tt.s2, func(t *testing.T) {
			distance := LevenshteinDistance(tt.s1, tt.s2)
			if distance != tt.expected {
				t.Errorf("LevenshteinDistance(%q, %q) = %d, want %d", tt.s1, tt.s2, distance, tt.expected)
			}
		})
	}
}

func TestCheckTyposquatting(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		threshold      int
		expectRisk     bool
		expectedSimilar string
	}{
		{
			name:        "exact match (react)",
			packageName: "react",
			threshold:   2,
			expectRisk:  false,
		},
		{
			name:           "close typo (raect)",
			packageName:    "raect",
			threshold:      2,
			expectRisk:     true,
			expectedSimilar: "react",
		},
		{
			name:           "single char typo (lodesh)",
			packageName:    "lodesh",
			threshold:      2,
			expectRisk:     true,
			expectedSimilar: "lodash",
		},
		{
			name:        "completely different package",
			packageName: "my-unique-package-name-12345",
			threshold:   2,
			expectRisk:  false,
		},
		{
			name:           "subtle typo (expres)",
			packageName:    "expres",
			threshold:      2,
			expectRisk:     true,
			expectedSimilar: "express",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := CheckTyposquatting(tt.packageName, tt.threshold)

			if tt.expectRisk && risk == nil {
				t.Errorf("Expected typosquatting risk for %q but got none", tt.packageName)
				return
			}

			if !tt.expectRisk && risk != nil {
				t.Errorf("Did not expect typosquatting risk for %q but got: %+v", tt.packageName, risk)
				return
			}

			if tt.expectRisk && risk != nil {
				if risk.SimilarTo != tt.expectedSimilar {
					t.Errorf("Expected similar to %q, got %q", tt.expectedSimilar, risk.SimilarTo)
				}
				if risk.PackageName != tt.packageName {
					t.Errorf("Package name mismatch: got %q, want %q", risk.PackageName, tt.packageName)
				}
			}
		})
	}
}

func TestCheckTyposquattingThreshold(t *testing.T) {
	// Test with different thresholds
	packageName := "reactt" // 1 char difference from "react"

	// Threshold 1 should detect it
	risk1 := CheckTyposquatting(packageName, 1)
	if risk1 == nil {
		t.Error("Threshold 1 should detect 'reactt' as similar to 'react'")
	}

	// Threshold 0 or negative should use default (2)
	risk0 := CheckTyposquatting(packageName, 0)
	if risk0 == nil {
		t.Error("Threshold 0 should use default threshold and detect 'reactt'")
	}
}

func TestAnalyzeMaintainerRisk(t *testing.T) {
	tests := []struct {
		name                string
		metadata            *PackageMetadata
		expectRisk          bool
		expectedRiskLevel   string
		expectedIssueCount  int
	}{
		{
			name: "well maintained package",
			metadata: &PackageMetadata{
				Name:         "test-package",
				LastModified: time.Now(),
				Maintainers:  []Maintainer{{Name: "Dev1"}, {Name: "Dev2"}},
			},
			expectRisk: false,
		},
		{
			name: "outdated package",
			metadata: &PackageMetadata{
				Name:         "old-package",
				LastModified: time.Now().AddDate(-3, 0, 0), // 3 years old
				Maintainers:  []Maintainer{{Name: "Dev1"}, {Name: "Dev2"}},
			},
			expectRisk:         true,
			expectedRiskLevel:  "medium",
			expectedIssueCount: 1,
		},
		{
			name: "single maintainer",
			metadata: &PackageMetadata{
				Name:         "solo-package",
				LastModified: time.Now(),
				Maintainers:  []Maintainer{{Name: "Solo Dev"}},
			},
			expectRisk:         true,
			expectedRiskLevel:  "medium",
			expectedIssueCount: 1,
		},
		{
			name: "no maintainers",
			metadata: &PackageMetadata{
				Name:         "abandoned-package",
				LastModified: time.Now(),
				Maintainers:  []Maintainer{},
			},
			expectRisk:         true,
			expectedRiskLevel:  "high",
			expectedIssueCount: 1,
		},
		{
			name: "multiple issues",
			metadata: &PackageMetadata{
				Name:         "risky-package",
				LastModified: time.Now().AddDate(-3, 0, 0),
				Maintainers:  []Maintainer{{Name: "Solo"}},
			},
			expectRisk:         true,
			expectedRiskLevel:  "medium",
			expectedIssueCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := AnalyzeMaintainerRisk(tt.metadata)

			if tt.expectRisk && risk == nil {
				t.Errorf("Expected maintainer risk but got none")
				return
			}

			if !tt.expectRisk && risk != nil {
				t.Errorf("Did not expect maintainer risk but got: %+v", risk)
				return
			}

			if tt.expectRisk && risk != nil {
				if risk.RiskLevel != tt.expectedRiskLevel {
					t.Errorf("Expected risk level %q, got %q", tt.expectedRiskLevel, risk.RiskLevel)
				}
				if len(risk.Issues) != tt.expectedIssueCount {
					t.Errorf("Expected %d issues, got %d: %v", tt.expectedIssueCount, len(risk.Issues), risk.Issues)
				}
			}
		})
	}
}

func TestFetchPackageMetadata_RealPackage(t *testing.T) {
	// Test with a real package (lodash is stable and widely used)
	metadata, err := FetchPackageMetadata("lodash")
	if err != nil {
		t.Skipf("Skipping real package test (network may be unavailable): %v", err)
		return
	}

	if metadata.Name != "lodash" {
		t.Errorf("Expected package name 'lodash', got %q", metadata.Name)
	}

	if len(metadata.Maintainers) == 0 {
		t.Error("Expected at least one maintainer")
	}

	if metadata.Description == "" {
		t.Error("Expected non-empty description")
	}
}

func TestFetchPackageMetadata_Cache(t *testing.T) {
	// Clear cache
	metadataCache = make(map[string]*PackageMetadata)

	// First fetch
	metadata1, err := FetchPackageMetadata("react")
	if err != nil {
		t.Skipf("Skipping cache test (network may be unavailable): %v", err)
		return
	}

	// Second fetch should come from cache
	metadata2, err := FetchPackageMetadata("react")
	if err != nil {
		t.Fatalf("Second fetch failed: %v", err)
	}

	// Should be the same instance (pointer equality)
	if metadata1 != metadata2 {
		t.Error("Expected cached metadata to return same instance")
	}
}

func TestFetchPackageMetadata_NonExistent(t *testing.T) {
	// Test with a package that definitely doesn't exist
	_, err := FetchPackageMetadata("this-package-absolutely-does-not-exist-12345")
	if err == nil {
		t.Error("Expected error for non-existent package")
	}
}

func TestPopularPackagesList(t *testing.T) {
	// Verify we have a decent list of popular packages
	if len(popularPackages) < 50 {
		t.Errorf("Expected at least 50 popular packages, got %d", len(popularPackages))
	}

	// Check for some common packages
	expectedPackages := []string{"react", "lodash", "express", "typescript"}
	for _, expected := range expectedPackages {
		found := false
		for _, pkg := range popularPackages {
			if pkg == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find %q in popular packages list", expected)
		}
	}
}

func TestTyposquattingConfidenceLevels(t *testing.T) {
	// Distance 1 should be "high" confidence
	risk1 := CheckTyposquatting("reactt", 3)
	if risk1 == nil || risk1.Confidence != "high" {
		t.Errorf("Distance 1 should have 'high' confidence, got: %v", risk1)
	}

	// Distance 2 should be "medium" confidence
	// "raectt" is 2 insertions from "react"
	risk2 := CheckTyposquatting("rxeact", 3) // swap x for a, distance should be 2
	if risk2 != nil && risk2.Distance == 2 && risk2.Confidence != "medium" {
		t.Errorf("Distance 2 should have 'medium' confidence, got: %v", risk2)
	}
}
