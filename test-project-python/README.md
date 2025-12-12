# Test Project - Python

This directory contains Python dependency files with intentionally **vulnerable/outdated packages** for testing Snoop's Python auditing capabilities.

## ⚠️ WARNING

**DO NOT** install these dependencies in a production environment or use them in real projects. These packages contain known security vulnerabilities and are included here solely for testing purposes.

## Files

- **requirements.txt**: Standard pip requirements file with vulnerable packages
- **Pipfile**: Pipenv dependency file with vulnerable packages
- **pyproject.toml**: Modern Python project configuration with vulnerable packages

## Testing Snoop

From the snoop directory, run:

```bash
# Scan this test project
./snoop --path test-project-python

# Scan with verbose output
./snoop --path test-project-python --verbose

# Generate JSON report
./snoop --path test-project-python --format json > python-audit.json

# Generate Markdown report
./snoop --path test-project-python --format markdown > PYTHON-SECURITY.md
```

## Expected Results

Snoop should detect:
- 3 manifest files (requirements.txt, Pipfile, pyproject.toml)
- Multiple vulnerabilities in the listed packages
- Specific CVEs and vulnerability IDs from pip-audit

## Prerequisites

To test Python auditing, you need pip-audit installed:

```bash
pip install pip-audit
```

Or with pipx (recommended):

```bash
pipx install pip-audit
```
