package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

// ManifestType represents the type of package manifest (Node.js or Python)
type ManifestType string

const (
	// Node.js manifest types
	PackageJSON     ManifestType = "package.json"
	PackageLockJSON ManifestType = "package-lock.json"
	YarnLock        ManifestType = "yarn.lock"
	PnpmLockYAML    ManifestType = "pnpm-lock.yaml"

	// Python manifest types
	RequirementsTxt ManifestType = "requirements.txt"
	Pipfile         ManifestType = "Pipfile"
	PipfileLock     ManifestType = "Pipfile.lock"
	PoetryLock      ManifestType = "poetry.lock"
	PyprojectTOML   ManifestType = "pyproject.toml"

	// Go manifest types
	GoMod ManifestType = "go.mod"
	GoSum ManifestType = "go.sum"

	// Maven/Java manifest types
	PomXML ManifestType = "pom.xml"
)

// DetectedFile represents a detected manifest file
type DetectedFile struct {
	Path string
	Type ManifestType
}

// ScanResult contains the results of scanning a directory
type ScanResult struct {
	Files  []DetectedFile
	Errors []error
}

// manifestFiles is the list of files we're looking for
var manifestFiles = []string{
	// Node.js manifests
	string(PackageJSON),
	string(PackageLockJSON),
	string(YarnLock),
	string(PnpmLockYAML),

	// Python manifests
	string(RequirementsTxt),
	string(Pipfile),
	string(PipfileLock),
	string(PoetryLock),
	string(PyprojectTOML),

	// Go manifests
	string(GoMod),
	string(GoSum),

	// Maven/Java manifests
	string(PomXML),
}

// Scanner handles directory scanning for Node.js, Python, Go, and Maven manifest files
type Scanner struct {
	rootPath string
	verbose  bool
}

// New creates a new Scanner instance
func New(rootPath string, verbose bool) (*Scanner, error) {
	// Verify the directory exists and is readable
	info, err := os.Stat(rootPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory does not exist: %s", rootPath)
		}
		return nil, fmt.Errorf("cannot access directory: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", rootPath)
	}

	return &Scanner{
		rootPath: rootPath,
		verbose:  verbose,
	}, nil
}

// Scan walks the directory tree and detects all Node.js, Python, Go, and Maven manifest files
func (s *Scanner) Scan() (*ScanResult, error) {
	result := &ScanResult{
		Files:  make([]DetectedFile, 0),
		Errors: make([]error, 0),
	}

	err := filepath.Walk(s.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Collect error but continue walking
			result.Errors = append(result.Errors, fmt.Errorf("error accessing %s: %w", path, err))
			return nil
		}

		// Skip directories
		if info.IsDir() {
			dirName := info.Name()

			// Skip node_modules directories to avoid deep recursion
			if dirName == "node_modules" {
				if s.verbose {
					fmt.Printf("Skipping node_modules: %s\n", path)
				}
				return filepath.SkipDir
			}

			// Skip Python virtual environment directories
			if dirName == "venv" || dirName == ".venv" || dirName == "env" || dirName == ".env" || dirName == "__pycache__" {
				if s.verbose {
					fmt.Printf("Skipping Python directory: %s\n", path)
				}
				return filepath.SkipDir
			}

			// Skip Go vendor directory
			if dirName == "vendor" {
				if s.verbose {
					fmt.Printf("Skipping vendor directory: %s\n", path)
				}
				return filepath.SkipDir
			}

			// Skip Maven target directory
			if dirName == "target" {
				if s.verbose {
					fmt.Printf("Skipping Maven target directory: %s\n", path)
				}
				return filepath.SkipDir
			}

			return nil
		}

		// Check if this file is one of our target manifests
		filename := info.Name()
		for _, manifestFile := range manifestFiles {
			if filename == manifestFile {
				detected := DetectedFile{
					Path: path,
					Type: ManifestType(manifestFile),
				}
				result.Files = append(result.Files, detected)

				if s.verbose {
					fmt.Printf("Found %s: %s\n", manifestFile, path)
				}
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return result, nil
}

// GetManifestsByType returns all detected files of a specific type
func (r *ScanResult) GetManifestsByType(manifestType ManifestType) []DetectedFile {
	var filtered []DetectedFile
	for _, file := range r.Files {
		if file.Type == manifestType {
			filtered = append(filtered, file)
		}
	}
	return filtered
}

// HasManifests returns true if any manifest files were found
func (r *ScanResult) HasManifests() bool {
	return len(r.Files) > 0
}

// Summary returns a summary of detected files
func (r *ScanResult) Summary() string {
	if len(r.Files) == 0 {
		return "No package manifests found"
	}

	counts := make(map[ManifestType]int)
	for _, file := range r.Files {
		counts[file.Type]++
	}

	summary := fmt.Sprintf("Found %d manifest file(s):\n", len(r.Files))
	for manifestType, count := range counts {
		summary += fmt.Sprintf("  - %s: %d\n", manifestType, count)
	}

	return summary
}

// IsNodeJSManifest returns true if the manifest type is for Node.js
func IsNodeJSManifest(t ManifestType) bool {
	return t == PackageJSON || t == PackageLockJSON || t == YarnLock || t == PnpmLockYAML
}

// IsPythonManifest returns true if the manifest type is for Python
func IsPythonManifest(t ManifestType) bool {
	return t == RequirementsTxt || t == Pipfile || t == PipfileLock || t == PoetryLock || t == PyprojectTOML
}

// IsGoManifest returns true if the manifest type is for Go
func IsGoManifest(t ManifestType) bool {
	return t == GoMod || t == GoSum
}

// IsMavenManifest returns true if the manifest type is for Maven/Java
func IsMavenManifest(t ManifestType) bool {
	return t == PomXML
}
