# Snoop - Node.js Security Audit CLI

A comprehensive command-line security audit tool for Node.js projects. Snoop automatically detects package manifests, runs security audits, and identifies potential supply chain risks including typosquatting, outdated packages, and suspicious patterns.

## Features

- **Automatic Package Detection**: Finds `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files
- **npm Audit Integration**: Runs `npm audit` and parses vulnerabilities
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
- npm (for running audits)
- make

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
- Uses npm's security audit API
- Inspired by the need for better supply chain security

## Support

For bugs, questions, and discussions please use the [GitHub Issues](https://github.com/brandonapol/snoop/issues).

---

**Made with ❤️ for secure Node.js development**
