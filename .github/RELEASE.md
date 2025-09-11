# How to Create a Release

This repository has automated GitHub Actions workflows that handle building and releasing binaries.

## Automatic Release Process

1. **Tag a release**: Create and push a version tag
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically**:
   - Build binaries for all supported platforms:
     - Linux (x64, ARM64) - both glibc and musl
     - macOS (Intel, Apple Silicon) - including .app bundles
     - Windows (x64)
   - Create a GitHub release with all binaries attached
   - Generate release notes with download instructions

## Supported Platforms

- **macOS**: Intel and Apple Silicon (with .app bundles)
- **Linux**: x64 and ARM64 (glibc and musl static)
- **Windows**: x64

## Manual Release via GitHub UI

Alternatively, you can create a release directly in the GitHub UI:

1. Go to the "Releases" section of your repository
2. Click "Create a new release"
3. Create a new tag (e.g., `v1.0.0`)
4. Fill in the release title and description
5. Publish the release

The GitHub Actions will automatically build and attach the binaries.

## Version Numbering

Use semantic versioning: `vMAJOR.MINOR.PATCH`
- `v1.0.0` - Major release
- `v1.1.0` - Minor release (new features)
- `v1.1.1` - Patch release (bug fixes)