package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		verbose   bool
		wantErr   bool
		errMsg    string
	}{
		{
			name:    "valid directory",
			path:    ".",
			verbose: false,
			wantErr: false,
		},
		{
			name:    "non-existent directory",
			path:    "/nonexistent/directory/path",
			verbose: false,
			wantErr: true,
			errMsg:  "directory does not exist",
		},
		{
			name:    "file instead of directory",
			path:    "scanner.go",
			verbose: false,
			wantErr: true,
			errMsg:  "path is not a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New(tt.path, tt.verbose)
			if tt.wantErr {
				if err == nil {
					t.Errorf("New() expected error but got nil")
					return
				}
				if tt.errMsg != "" && err.Error() == "" {
					t.Errorf("New() error message is empty, expected to contain '%s'", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("New() unexpected error: %v", err)
					return
				}
				if scanner == nil {
					t.Errorf("New() returned nil scanner")
				}
			}
		})
	}
}

func TestScan(t *testing.T) {
	// Create a temporary directory structure for testing
	tmpDir := t.TempDir()

	// Create test manifest files
	testFiles := map[string]ManifestType{
		"package.json":      PackageJSON,
		"package-lock.json": PackageLockJSON,
		"yarn.lock":         YarnLock,
		"pnpm-lock.yaml":    PnpmLockYAML,
	}

	for filename := range testFiles {
		file := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(file, []byte("{}"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create a subdirectory with another package.json
	subdir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "package.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create subdirectory package.json: %v", err)
	}

	// Create node_modules directory (should be skipped)
	nodeModules := filepath.Join(tmpDir, "node_modules")
	if err := os.Mkdir(nodeModules, 0755); err != nil {
		t.Fatalf("Failed to create node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nodeModules, "package.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create node_modules package.json: %v", err)
	}

	// Run the scanner
	scanner, err := New(tmpDir, false)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	result, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}

	// Verify results
	if !result.HasManifests() {
		t.Error("Scan() expected to find manifests but found none")
	}

	// Check that we found all manifest types in the root
	foundTypes := make(map[ManifestType]int)
	for _, file := range result.Files {
		foundTypes[file.Type]++
	}

	// We expect 4 manifest types in root + 1 package.json in subdir = 5 total
	// node_modules should be skipped so that package.json shouldn't be counted
	expectedTotal := 5
	if len(result.Files) != expectedTotal {
		t.Errorf("Scan() found %d files, expected %d", len(result.Files), expectedTotal)
	}

	// Verify we have 2 package.json files (root + subdir, but not node_modules)
	if foundTypes[PackageJSON] != 2 {
		t.Errorf("Scan() found %d package.json files, expected 2", foundTypes[PackageJSON])
	}

	// Verify we have 1 of each other type
	for _, manifestType := range []ManifestType{PackageLockJSON, YarnLock, PnpmLockYAML} {
		if foundTypes[manifestType] != 1 {
			t.Errorf("Scan() found %d %s files, expected 1", foundTypes[manifestType], manifestType)
		}
	}

	// Verify node_modules was skipped - check that none of the found files are in node_modules
	for _, file := range result.Files {
		if filepath.Dir(file.Path) == nodeModules {
			t.Errorf("Scan() should have skipped node_modules but found file: %s", file.Path)
		}
	}
}

func TestGetManifestsByType(t *testing.T) {
	result := &ScanResult{
		Files: []DetectedFile{
			{Path: "/test/package.json", Type: PackageJSON},
			{Path: "/test/package-lock.json", Type: PackageLockJSON},
			{Path: "/test/yarn.lock", Type: YarnLock},
			{Path: "/test/sub/package.json", Type: PackageJSON},
		},
	}

	packageJSONs := result.GetManifestsByType(PackageJSON)
	if len(packageJSONs) != 2 {
		t.Errorf("GetManifestsByType() returned %d package.json files, expected 2", len(packageJSONs))
	}

	yarnLocks := result.GetManifestsByType(YarnLock)
	if len(yarnLocks) != 1 {
		t.Errorf("GetManifestsByType() returned %d yarn.lock files, expected 1", len(yarnLocks))
	}

	pnpmLocks := result.GetManifestsByType(PnpmLockYAML)
	if len(pnpmLocks) != 0 {
		t.Errorf("GetManifestsByType() returned %d pnpm-lock.yaml files, expected 0", len(pnpmLocks))
	}
}

func TestHasManifests(t *testing.T) {
	tests := []struct {
		name     string
		result   *ScanResult
		expected bool
	}{
		{
			name: "with manifests",
			result: &ScanResult{
				Files: []DetectedFile{
					{Path: "/test/package.json", Type: PackageJSON},
				},
			},
			expected: true,
		},
		{
			name: "without manifests",
			result: &ScanResult{
				Files: []DetectedFile{},
			},
			expected: false,
		},
		{
			name: "nil files",
			result: &ScanResult{
				Files: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasManifests(); got != tt.expected {
				t.Errorf("HasManifests() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	tests := []struct {
		name     string
		result   *ScanResult
		contains []string
	}{
		{
			name: "with manifests",
			result: &ScanResult{
				Files: []DetectedFile{
					{Path: "/test/package.json", Type: PackageJSON},
					{Path: "/test/package-lock.json", Type: PackageLockJSON},
					{Path: "/test/yarn.lock", Type: YarnLock},
				},
			},
			contains: []string{"Found 3 manifest", "package.json: 1", "package-lock.json: 1", "yarn.lock: 1"},
		},
		{
			name: "without manifests",
			result: &ScanResult{
				Files: []DetectedFile{},
			},
			contains: []string{"No Node.js package manifests found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := tt.result.Summary()
			if summary == "" {
				t.Errorf("Summary() returned empty string")
			}
		})
	}
}
