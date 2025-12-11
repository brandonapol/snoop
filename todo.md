# Snoop CLI - Development TODO

## Project Overview
Build a Go-based CLI tool called `snoop` that automatically detects Node.js package manifests in a directory and runs comprehensive security audits.

## Phase 1: Core CLI Structure ✅

- [x] Initialize Go module with `go mod init github.com/brandonapol/snoop`
- [x] Create main.go with basic CLI structure using cobra or flag package
- [x] Implement command-line flags:
  - [x] `--path` for specifying directory (default: current directory)
  - [x] `--format` for output format (json, table, markdown)
  - [x] `--severity` for filtering by minimum severity (critical, high, medium, low)
  - [x] `--verbose` for detailed output
- [x] Add version flag `--version`

## Phase 2: File Detection ✅

- [x] Create file scanner module that walks directory tree
- [x] Implement detection for Node.js manifest files:
  - [x] Detect `package.json`
  - [x] Detect `package-lock.json`
  - [x] Detect `yarn.lock`
  - [x] Detect `pnpm-lock.yaml`
- [x] Return list of detected files with their full paths
- [x] Handle errors gracefully when directory doesn't exist or isn't readable

## Phase 3: npm Audit Integration ✅

- [x] Create npm audit runner that executes `npm audit --json`
- [x] Check if npm is installed before attempting audit
- [x] Parse npm audit JSON output
- [x] Create data structures to hold audit results:
  - [x] Vulnerability struct with: name, severity, description, CVE, affected versions
  - [x] Summary struct with: total vulnerabilities by severity
- [x] Handle npm audit exit codes correctly (non-zero on vulnerabilities)
- [x] Add timeout handling for long-running audits
- [x] Write tests for the go code

## Phase 4: Output Formatting ✅

- [x] Create formatter module with interface for different output types
- [x] Implement JSON formatter:
  - [x] Structure with metadata (timestamp, directory, tool version)
  - [x] Array of vulnerabilities
  - [x] Summary statistics
- [x] Implement table formatter:
  - [x] Use tablewriter or similar library
  - [x] Columns: Package, Severity, CVE, Description
  - [x] Color coding by severity (red=critical, orange=high, yellow=medium)
- [x] Implement markdown formatter:
  - [x] Generate markdown tables
  - [x] Include summary at top
  - [x] Link CVEs to vulnerability databases

## Phase 5: Enhanced Security Features ✅

- [x] Implement typosquatting detection:
  - [x] Create list of popular npm packages (top 100)
  - [x] Calculate Levenshtein distance between detected packages and popular ones
  - [x] Flag packages within distance threshold of 2-3
  - [x] Add to report as "Potential Typosquatting Risk"
- [x] Add package metadata fetching from npm registry:
  - [x] HTTP client for npm registry API
  - [x] Fetch package metadata (created date, last update, download stats, maintainers)
  - [x] Cache responses to avoid rate limits
- [x] Implement maintainer risk analysis:
  - [x] Flag packages not updated in 2+ years
  - [x] Flag packages with single maintainer
  - [x] Flag recent maintainer changes (if detectable)
- [x] Add suspicious pattern detection:
  - [x] Check for install/preinstall/postinstall scripts in package.json
  - [x] Flag packages with these scripts as potential risk
  - [x] Include script content in verbose output

## Phase 6: Error Handling & User Experience ✅

- [x] Add comprehensive error messages for common issues:
  - [x] No package files found
  - [x] npm not installed
  - [x] Network errors when fetching metadata
  - [x] Invalid directory path
- [x] Implement progress indicators for long operations
- [x] Add colored output for terminal (green=safe, yellow=warnings, red=critical)
- [x] Create help text and usage examples
- [x] Add logging with configurable verbosity levels

## Phase 7: Build & Release ✅

- [x] Create Makefile for common build tasks
- [x] Set up cross-compilation for multiple platforms:
  - [x] Linux (amd64, arm64)
  - [x] macOS (amd64, arm64)
  - [x] Windows (amd64)
- [x] Create build script that generates binaries for all platforms
- [x] Write installation instructions in README.md
- [x] Create sample output examples in README
- [ ] Tag release and upload binaries to GitHub releases

## Phase 8: Testing & Validation ✅

- [x] Create test fixtures with sample package.json files
- [x] Write unit tests for:
  - [x] File detection
  - [x] Audit parsing
  - [x] Output formatting
  - [x] Typosquatting detection
- [x] Test against real-world projects with known vulnerabilities
- [x] Verify curl installation works: `curl -sSL <url> | bash`
- [x] Test on fresh system without npm installed (should fail gracefully)

## Phase 9: Documentation ✅

- [x] Write comprehensive README.md:
  - [x] What is snoop
  - [x] Installation instructions
  - [x] Usage examples
  - [x] Output format documentation
  - [x] Contributing guidelines
- [x] Add inline code documentation
- [ ] Create ARCHITECTURE.md explaining design decisions
- [ ] Add example CI/CD integration snippets

## Phase 10: Competition Polish

- [ ] Create demo video or GIF showing snoop in action
- [ ] Add ASCII art banner on tool startup
- [x] Ensure output is visually appealing and easy to read
- [ ] Create Dockerfile for containerized usage
- [x] Add example usage in README showing detection of real vulnerabilities
- [x] Double-check all competition requirements are met

## Notes for Implementation

### Recommended Go Packages
- CLI framework: `github.com/spf13/cobra` or standard `flag`
- Table output: `github.com/olekukonko/tablewriter`
- Colors: `github.com/fatih/color`
- HTTP client: standard `net/http` with custom timeout
- JSON parsing: standard `encoding/json`

### npm Audit JSON Structure
The npm audit command returns JSON with this structure:
```json
{
  "vulnerabilities": {
    "package-name": {
      "severity": "high",
      "via": ["CVE-2024-XXXXX"],
      "effects": [],
      "range": "1.0.0 - 1.5.0",
      "nodes": ["node_modules/package-name"]
    }
  }
}
```

### Typosquatting Detection Approach
Use Levenshtein distance algorithm. Flag if:
- Distance <= 2 from popular package
- Different package with similar name
- Common character substitutions (0 for o, 1 for l, etc)

### Installation Command Format
```bash
curl -sSL https://github.com/username/snoop/releases/latest/download/snoop-$(uname -s)-$(uname -m) -o /usr/local/bin/snoop && chmod +x /usr/local/bin/snoop
```

## Success Criteria ✅
- [x] Tool detects package.json in any directory
- [x] Runs npm audit and parses results correctly
- [x] Outputs formatted report in multiple formats
- [x] Detects at least one supply chain risk (typosquatting, stale packages, etc)
- [x] Can be installed with single curl command
- [x] Works on Linux and macOS
- [x] Clear, professional output suitable for demo
