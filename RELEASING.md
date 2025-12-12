# Release Process

This document describes how to create a new release of Snoop using the automated GitHub Actions workflow.

## Automated Release Process

Releases are fully automated using GitHub Actions. When you push a version tag, the workflow will:

1. Build binaries for all platforms (Linux, macOS, Windows)
2. Generate SHA256 checksums
3. Create a GitHub release with auto-generated release notes
4. Upload all binaries and checksums to the release

## Creating a New Release

### 1. Update Version

First, update the version in `main.go`:

```go
const version = "1.0.0"  // Update this
```

### 2. Update Documentation

Update any version-specific references in documentation:

- `README.md` - Update installation commands if needed
- Check that examples reference the correct version

### 3. Commit Changes

```bash
git add main.go README.md
git commit -m "chore: bump version to v1.0.0"
git push origin main
```

### 4. Create and Push Tag

```bash
# Create an annotated tag
git tag -a v1.0.0 -m "Release v1.0.0

Features:
- List key features
- Or changes in this release
- Can be bullet points

Fixes:
- Bug fixes if any
"

# Push the tag to trigger the release workflow
git push origin v1.0.0
```

### 5. Monitor Release

1. Go to: https://github.com/brandonapol/snoop/actions
2. Watch the "Release" workflow run
3. Once complete, check: https://github.com/brandonapol/snoop/releases

The release will be automatically created with:
- Pre-built binaries for all platforms
- SHA256 checksums
- Installation instructions
- Feature highlights

## What Happens Automatically

When you push a tag matching `v*.*.*`:

1. **GitHub Actions triggers** the release workflow
2. **Go 1.21 is set up** in the CI environment
3. **Binaries are built** for:
   - Linux (amd64, arm64)
   - macOS (amd64/Intel, arm64/Apple Silicon)
   - Windows (amd64)
4. **Version is injected** into the binary via `-ldflags`
5. **Checksums are generated** (SHA256)
6. **Release is created** on GitHub with:
   - All binaries attached
   - `checksums.txt` file
   - Auto-generated release notes
   - Installation instructions

## Manual Release (Not Recommended)

If you need to create a release manually:

```bash
# Build all binaries
make cross-compile

# Create checksums
cd build
sha256sum snoop-* > checksums.txt

# Manually create release on GitHub and upload files
```

## Testing Before Release

Before creating a release, ensure:

1. **Tests pass**: `make test`
2. **Build works**: `make build`
3. **Integration tests pass**: `make test-coverage`
4. **Binary runs**: `./snoop --version`

The CI workflow runs these checks on every commit, so green CI = ready to release.

## Versioning Scheme

Snoop follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (v1.0.0 → v2.0.0): Breaking changes
- **MINOR** (v1.0.0 → v1.1.0): New features, backwards compatible
- **PATCH** (v1.0.0 → v1.0.1): Bug fixes, backwards compatible

## Example Release Notes

When creating a tag, write meaningful release notes:

```bash
git tag -a v1.0.0 -m "Release v1.0.0 - Production Ready

New Features:
- Added SBOM (Software Bill of Materials) generation
- Added support for Gradle projects
- Improved vulnerability detection accuracy

Improvements:
- 30% faster scanning on large projects
- Better error messages
- Updated OSV API integration

Bug Fixes:
- Fixed crash when scanning empty directories
- Fixed parsing of complex pom.xml files
- Corrected severity classification for Python packages

Breaking Changes:
- Changed JSON output format (see migration guide)
- Removed deprecated --legacy flag
"
```

## Troubleshooting

### Workflow Fails to Build

Check the Actions tab for error messages. Common issues:
- Go module dependencies not resolving
- Test failures
- Build errors on specific platforms

### Release Not Created

Ensure:
- Tag matches pattern `v*.*.*` (e.g., `v1.0.0`)
- Tag is pushed to GitHub (`git push origin v1.0.0`)
- Repository has `GITHUB_TOKEN` secret (automatically provided)

### Binaries Not Uploaded

Check workflow logs. Ensure:
- Build step completed successfully
- All platforms built without errors
- No file size limits exceeded

## Support

For issues with the release process, check:
- [GitHub Actions documentation](https://docs.github.com/en/actions)
- [Release workflow](.github/workflows/release.yml)
- [CI workflow](.github/workflows/ci.yml)
