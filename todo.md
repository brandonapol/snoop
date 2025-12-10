# Snoop CLI - Development TODO

## Project Overview
Build a Go-based CLI tool called `snoop` that automatically detects Node.js package manifests in a directory and runs comprehensive security audits.

## Phase 1: Core CLI Structure

- [ ] Initialize Go module with `go mod init github.com/brandonapol/snoop`
- [ ] Create main.go with basic CLI structure using cobra or flag package
- [ ] Implement command-line flags:
  - [ ] `--path` for specifying directory (default: current directory)
  - [ ] `--format` for output format (json, table, markdown)
  - [ ] `--severity` for filtering by minimum severity (critical, high, medium, low)
  - [ ] `--verbose` for detailed output
- [ ] Add version flag `--version`

## Phase 2: File Detection

- [ ] Create file scanner module that walks directory tree
- [ ] Implement detection for Node.js manifest files:
  - [ ] Detect `package.json`
  - [ ] Detect `package-lock.json`
  - [ ] Detect `yarn.lock`
  - [ ] Detect `pnpm-lock.yaml`
- [ ] Return list of detected files with their full paths
- [ ] Handle errors gracefully when directory doesn't exist or isn't readable

## Phase 3: npm Audit Integration

- [ ] Create npm audit runner that executes `npm audit --json`
- [ ] Check if npm is installed before attempting audit
- [ ] Parse npm audit JSON output
- [ ] Create data structures to hold audit results:
  - [ ] Vulnerability struct with: name, severity, description, CVE, affected versions
  - [ ] Summary struct with: total vulnerabilities by severity
- [ ] Handle npm audit exit codes correctly (non-zero on vulnerabilities)
- [ ] Add timeout handling for long-running audits

## Phase 4: Output Formatting

- [ ] Create formatter module with interface for different output types
- [ ] Implement JSON formatter:
  - [ ] Structure with metadata (timestamp, directory, tool version)
  - [ ] Array of vulnerabilities
  - [ ] Summary statistics
- [ ] Implement table formatter:
  - [ ] Use tablewriter or similar library
  - [ ] Columns: Package, Severity, CVE, Description
  - [ ] Color coding by severity (red=critical, orange=high, yellow=medium)
- [ ] Implement markdown formatter:
  - [ ] Generate markdown tables
  - [ ] Include summary at top
  - [ ] Link CVEs to vulnerability databases

## Phase 5: Enhanced Security Features

- [ ] Implement typosquatting detection:
  - [ ] Create list of popular npm packages (top 100-500)
  - [ ] Calculate Levenshtein distance between detected packages and popular ones
  - [ ] Flag packages within distance threshold of 2-3
  - [ ] Add to report as "Potential Typosquatting Risk"
- [ ] Add package metadata fetching from npm registry:
  - [ ] HTTP client for npm registry API
  - [ ] Fetch package metadata (created date, last update, download stats, maintainers)
  - [ ] Cache responses to avoid rate limits
- [ ] Implement maintainer risk analysis:
  - [ ] Flag packages not updated in 2+ years
  - [ ] Flag packages with single maintainer
  - [ ] Flag recent maintainer changes (if detectable)
- [ ] Add suspicious pattern detection:
  - [ ] Check for install/preinstall/postinstall scripts in package.json
  - [ ] Flag packages with these scripts as potential risk
  - [ ] Include script content in verbose output

## Phase 6: Error Handling & User Experience

- [ ] Add comprehensive error messages for common issues:
  - [ ] No package files found
  - [ ] npm not installed
  - [ ] Network errors when fetching metadata
  - [ ] Invalid directory path
- [ ] Implement progress indicators for long operations
- [ ] Add colored output for terminal (green=safe, yellow=warnings, red=critical)
- [ ] Create help text and usage examples
- [ ] Add logging with configurable verbosity levels

## Phase 7: Build & Release

- [ ] Create Makefile for common build tasks
- [ ] Set up cross-compilation for multiple platforms:
  - [ ] Linux (amd64, arm64)
  - [ ] macOS (amd64, arm64)
  - [ ] Windows (amd64)
- [ ] Create build script that generates binaries for all platforms
- [ ] Write installation instructions in README.md
- [ ] Create sample output examples in README
- [ ] Tag release and upload binaries to GitHub releases

## Phase 8: Testing & Validation

- [ ] Create test fixtures with sample package.json files
- [ ] Write unit tests for:
  - [ ] File detection
  - [ ] Audit parsing
  - [ ] Output formatting
  - [ ] Typosquatting detection
- [ ] Test against real-world projects with known vulnerabilities
- [ ] Verify curl installation works: `curl -sSL <url> | bash`
- [ ] Test on fresh system without npm installed (should fail gracefully)

## Phase 9: Documentation

- [ ] Write comprehensive README.md:
  - [ ] What is snoop
  - [ ] Installation instructions
  - [ ] Usage examples
  - [ ] Output format documentation
  - [ ] Contributing guidelines
- [ ] Add inline code documentation
- [ ] Create ARCHITECTURE.md explaining design decisions
- [ ] Add example CI/CD integration snippets

## Phase 10: Competition Polish

- [ ] Create demo video or GIF showing snoop in action
- [ ] Add ASCII art banner on tool startup
- [ ] Ensure output is visually appealing and easy to read
- [ ] Create Dockerfile for containerized usage
- [ ] Add example usage in README showing detection of real vulnerabilities
- [ ] Double-check all competition requirements are met

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

## Success Criteria
- [ ] Tool detects package.json in any directory
- [ ] Runs npm audit and parses results correctly
- [ ] Outputs formatted report in multiple formats
- [ ] Detects at least one supply chain risk (typosquatting, stale packages, etc)
- [ ] Can be installed with single curl command
- [ ] Works on Linux and macOS
- [ ] Clear, professional output suitable for demo
