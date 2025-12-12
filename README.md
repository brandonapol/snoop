# Snoop - Multi-Language Security Audit CLI

> **🏆 Vibelympics Coding Competition - Round 2 Submission**
>
> This project was created for the [Vibelympics coding competition](https://github.com/brandonapol/vibelympics). It is maintained as a git submodule at `/round_2` in the main vibelympics repository.
>
> **Why a submodule?** To keep Go module imports clean and properly scoped (e.g., `github.com/brandonapol/snoop/audit` instead of `github.com/brandonapol/vibelympics/round_2/snoop/audit`). This approach maintains proper Go module structure while allowing the competition repository to reference this work.
>
> **For Graders:** You can access this project at:
> - Main repository: https://github.com/brandonapol/snoop
> - As submodule: https://github.com/brandonapol/vibelympics/tree/main/round_2

---

A comprehensive command-line security audit tool for Node.js, Python, Go, and Maven/Java projects. Snoop automatically detects package manifests, runs security audits using built-in vulnerability databases, and identifies potential supply chain risks including typosquatting, outdated packages, and suspicious patterns.

## Features

### Multi-Language Support
- **Node.js Support**: Detects `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files
- **Python Support**: Detects `requirements.txt`, `Pipfile`, `pyproject.toml`, and `poetry.lock` files
- **Go Support**: Detects `go.mod` and `go.sum` files
- **Maven/Java Support**: Detects `pom.xml` files
- **Built-in Vulnerability Scanning**: Uses OSV (Open Source Vulnerabilities) database for Python, Go, and Maven - no external tools required!

### Security Features
- **npm Audit Integration**: Runs `npm audit` and parses vulnerabilities for Node.js packages
- **Native Python Scanning**: Built-in vulnerability checking using OSV API (no pip-audit required)
- **Native Go Scanning**: Built-in vulnerability checking using OSV API (no govulncheck required)
- **Native Maven Scanning**: Built-in vulnerability checking using OSV API (no external Maven plugins required)
- **Typosquatting Detection**: Uses Levenshtein distance to detect potential typosquatting attacks
- **Maintainer Risk Analysis**: Flags packages with single maintainers or outdated versions
- **Suspicious Pattern Detection**: Identifies risky install scripts
- **Multiple Output Formats**: JSON, table, and markdown formats
- **Severity Filtering**: Filter vulnerabilities by severity level
- **Comprehensive Testing**: Full unit and integration test coverage

## Installation

### From Source

```bash
git clone https://github.com/brandonapol/snoop.git
cd snoop
make install
```

### Using Go

```bash
go install github.com/brandonapol/snoop@latest
```

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/brandonapol/snoop/releases).

```bash
# Linux/macOS
curl -sSL https://github.com/brandonapol/snoop/releases/latest/download/snoop-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o /usr/local/bin/snoop
chmod +x /usr/local/bin/snoop
```

## Uninstallation

### Remove Installed Binary

```bash
# If installed via make install
make uninstall

# Or manually remove from /usr/local/bin
sudo rm /usr/local/bin/snoop

# If installed via go install
rm $(go env GOPATH)/bin/snoop

# Verify removal
which snoop  # Should return nothing
```

### Remove Source Directory

```bash
# If you cloned the repository
rm -rf /path/to/snoop
```

## Usage

### Basic Usage

```bash
# Scan current directory
snoop

# Scan specific directory
snoop --path /path/to/project

# Verbose output
snoop --verbose
```

### Output Formats

```bash
# Table format (default)
snoop

# JSON format
snoop --format json > security-report.json

# Markdown format
snoop --format markdown > SECURITY.md
```

### Severity Filtering

```bash
# Show only critical and high severity
snoop --severity high

# Show all vulnerabilities
snoop --severity low
```

### Examples

```bash
# Complete security scan with verbose output
snoop --path ./my-project --verbose --format markdown > security-report.md

# Quick scan for critical issues only
snoop --severity critical

# Generate JSON report for CI/CD
snoop --format json --severity high > audit.json
```

## Python Support

Snoop now supports Python projects in addition to Node.js! It will automatically detect Python manifest files and run `pip-audit` if available.

### Supported Python Manifest Files

- **requirements.txt**: Standard pip requirements file
- **Pipfile**: Pipenv dependency file
- **pyproject.toml**: Modern Python project configuration (PEP 518)
- **poetry.lock**: Poetry lock file (detection only, audited via pyproject.toml)
- **Pipfile.lock**: Pipenv lock file (detection only, audited via Pipfile)

### Installing pip-audit

```bash
# Install globally
pip install pip-audit

# Or with pipx (recommended)
pipx install pip-audit

# Verify installation
pip-audit --version
```

### Mixed Projects

Snoop can handle projects with both Node.js and Python dependencies:

```bash
# Scan a project with both package.json and requirements.txt
snoop --path ./my-full-stack-project

# Output will include both Node.js and Python vulnerabilities
```

### Python-Only Projects

```bash
# Scan a Python project
snoop --path ./my-python-project

# If npm is not installed, Snoop will skip Node.js audit
# Only pip-audit will run
```

### Notes

- Python virtual environments (venv, .venv, env, __pycache__) are automatically skipped during scanning
- Python vulnerability checking uses the built-in OSV API - no external tools required!

## Go Support

Snoop has built-in support for Go modules using the OSV (Open Source Vulnerabilities) API!

### Supported Go Files

- **go.mod**: Go module definition file (primary audit source)
- **go.sum**: Go checksums file (detected for completeness)

### Native Go Scanning

**No external tools required!** Snoop uses the OSV API directly to check Go modules for vulnerabilities.

```bash
# Scan a Go project
snoop --path ./my-go-project

# Both Node.js and Go in same project
snoop --path ./my-full-stack-project
```

### Example Output

```
Go Module: myproject/go.mod
Found 3 vulnerabilities:
  High: 3

Module                                   Version      Vulnerability ID     Fix Versions
-------------------------------------------------------------------------------------
golang.org/x/net                         v0.0.0-2019  GO-2020-0015        0.0.0-20200226101357, 0.0.0-20200226101357
github.com/gin-gonic/gin                 v1.6.0       GHSA-3vp4-m3rf-...   1.9.0
```

### Notes

- Go vendor directories are automatically skipped during scanning
- Only `go.mod` files are audited; `go.sum` is detected but not separately audited
- Uses the official Go vulnerability database via OSV API

## Maven/Java Support

Snoop has built-in support for Maven projects using the OSV (Open Source Vulnerabilities) API!

### Supported Maven Files

- **pom.xml**: Maven Project Object Model file (primary audit source)

### Native Maven Scanning

**No external tools required!** Snoop uses the OSV API directly to check Maven dependencies for vulnerabilities.

```bash
# Scan a Maven project
snoop --path ./my-java-project

# Mixed ecosystem project (Node.js, Python, Go, and Maven)
snoop --path ./my-full-stack-project
```

### Example Output

```
Maven Project: myproject/pom.xml
Found 7 vulnerabilities:
  High: 7

Dependency                               Version      Vulnerability ID     Fix Versions
-------------------------------------------------------------------------------------
org.apache.logging.log4j:log4j-core      2.14.1       GHSA-jfh8-c2jp-...   2.15.0, 2.3.1, 2.12.2
com.fasterxml.jackson.core:jackson-...   2.9.8        GHSA-57j2-w4cx-...   2.13.2.1, 2.12.6.1
org.springframework:spring-core          5.2.0.R...   GHSA-6gf2-pvqw-...   5.3.14, 5.2.19
```

### Notes

- Maven target directories are automatically skipped during scanning
- Only `pom.xml` files are audited
- Dependencies without explicit versions (managed by parent POMs or BOMs) are skipped
- Uses the official Maven vulnerability database via OSV API

## Output

### Table Format

```
Snoop Scan Results
================================================================================
Directory: /path/to/project
Timestamp: 2025-12-10T13:27:39-05:00

Found 4 manifest file(s)

Package: project/package.json
Found 18 vulnerabilities:
  High: 2
  Moderate: 16

Package                                  Severity     Range                Direct
-------------------------------------------------------------------------------------
braces                                   high         <3.0.3               No
micromatch                               high         <=4.0.7              No
...
```

### JSON Format

```json
{
  "metadata": {
    "timestamp": "2025-12-10T13:27:40Z",
    "directory": "/path/to/project",
    "toolName": "Snoop",
    "toolVersion": "0.1.0"
  },
  "manifestsFound": 4,
  "manifestFiles": [...],
  "audits": [...],
  "totalVulnerabilities": 18,
  "summary": {
    "critical": 0,
    "high": 2,
    "moderate": 16,
    "low": 0,
    "total": 18
  }
}
```

### Markdown Format

```markdown
# Snoop Scan Results

**Directory:** /path/to/project
**Timestamp:** 2025-12-10T13:27:41-05:00
**Version:** 0.1.0

## Manifest Files

Found **4** manifest file(s):
- `package.json` (package.json)
- `package-lock.json` (package-lock.json)
...
```

## Command-Line Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--path` | `-p` | Current directory | Directory to scan for package manifests |
| `--format` | `-f` | `table` | Output format: `json`, `table`, or `markdown` |
| `--severity` | `-s` | `low` | Minimum severity: `critical`, `high`, `moderate`, or `low` |
| `--verbose` | `-v` | `false` | Enable verbose output |
| `--version` | | | Display version information |
| `--help` | `-h` | | Display help message |

## Development

### Prerequisites

- Go 1.21 or later
- npm (for running Node.js audits only - Python, Go, and Maven use built-in vulnerability checking)
- make

**Note:** Python, Go, and Maven vulnerability scanning is built-in using the OSV API - no external tools required!

### Building from Source

```bash
# Clone the repository
git clone https://github.com/brandonapol/snoop.git
cd snoop

# Install dependencies
make deps

# Build
make build

# Run tests
make test

# Run with test coverage
make test-coverage
```

### Development Commands

```bash
make help            # Show all available commands
make build           # Build for current platform
make test            # Run all tests
make cross-compile   # Build for all platforms
make release         # Create release builds
make clean           # Clean build artifacts
make fmt             # Format code
make lint            # Run linter
```

### Cross-Platform Builds

```bash
# Build for all platforms
make cross-compile

# Creates binaries in build/:
# - snoop-linux-amd64
# - snoop-linux-arm64
# - snoop-darwin-amd64 (Intel Mac)
# - snoop-darwin-arm64 (Apple Silicon)
# - snoop-windows-amd64.exe
```

## Architecture

### Package Structure

```
snoop/
├── main.go              # CLI entry point
├── audit/              # npm audit integration
│   ├── audit.go
│   └── audit_test.go
├── scanner/            # File detection
│   ├── scanner.go
│   └── scanner_test.go
├── security/           # Enhanced security features
│   ├── security.go
│   └── security_test.go
├── formatter/          # Output formatting
│   └── formatter.go
└── integration_test.go # End-to-end tests
```

### Testing

Snoop includes comprehensive testing:

- **Unit Tests**: Test individual functions and modules
- **Integration Tests**: Test end-to-end CLI behavior
- **Requirement Tests**: Validate against project requirements

```bash
# Run all tests
go test ./...

# Run integration tests only
go test -v -run TestRequirement

# Run with coverage
make test-coverage
```

## Security Features

### Typosquatting Detection

Snoop compares package names against 100+ popular npm packages using Levenshtein distance to detect potential typosquatting attacks.

### Maintainer Risk Analysis

- Flags packages not updated in 2+ years
- Identifies packages with single maintainers
- Detects packages with no maintainers

### Suspicious Pattern Detection

- Checks for install/preinstall/postinstall scripts
- Flags scripts that download external code
- Includes script content in verbose output

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI
- Uses npm's security audit API for Node.js packages
- Uses [OSV (Open Source Vulnerabilities)](https://osv.dev) API for Python, Go, and Maven packages
- Inspired by the need for better supply chain security

## Support

For bugs, questions, and discussions please use the [GitHub Issues](https://github.com/brandonapol/snoop/issues).

---

**Made with ❤️ for secure software development**
