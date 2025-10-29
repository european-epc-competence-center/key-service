# Release Scripts

This directory contains scripts for managing releases of the key-service.

## Release Script

The `release.js` script automates the entire release process:

### What it does:

1. **Version Management**: Bumps version in `package.json` following semantic versioning
2. **Changelog**: Updates `CHANGELOG.md` with new version and changes
3. **Git Operations**: Creates commit and tag for the release
4. **Service Version**: Works with `SERVICE_VERSION` environment variable for API responses

### Usage

```bash
# Patch release (0.0.1 -> 0.0.2)
npm run release:patch

# Minor release (0.0.1 -> 0.1.0)
npm run release:minor

# Major release (0.0.1 -> 1.0.0)
npm run release:major

# Or directly with arguments
npm run release patch
npm run release minor
npm run release major

# Skip git operations (useful for testing)
npm run release patch --skip-git
```

### Interactive Process

The script will:

1. Show current and new version
2. Prompt for changelog entries in Keep a Changelog format
3. Update `package.json` and `CHANGELOG.md`
4. Create git commit and tag
5. Provide next steps for publishing

### Changelog Format

When prompted, enter changelog entries like:

```
### Added
- New feature description
- Another new feature

### Changed
- Modified existing feature
- Updated dependency

### Fixed
- Bug fix description
- Security issue fix

### Removed
- Deprecated feature removal
```

Press Enter twice to finish entering changelog entries.

## GitLab CI Integration

The release process integrates with GitLab CI:

- **Version Tags**: When you push a version tag (e.g., `v1.2.3`), GitLab CI will:

  - Build the Docker image
  - Tag it with the version number (`1.2.3`)
  - Tag it as `latest`
  - Push both tags to the registry

- **Main Branch**: Regular pushes to main still create development builds

### Complete Release Workflow

1. **Prepare Release**:

   ```bash
   npm run release:patch  # or minor/major
   ```

2. **Review Changes**:

   - Check `package.json` version
   - Review `CHANGELOG.md` entries
   - Verify git commit and tag

3. **Publish Release**:

   ```bash
   git push && git push --tags
   ```

4. **Deploy**:
   - GitLab CI will automatically build and push Docker images
   - Set `SERVICE_VERSION` environment variable in your deployment
   - The version will appear in API responses and health checks

## Service Version in API

The version is exposed in:

- **Error Responses**: Via `GlobalExceptionFilter` in the `version` field
- **Health Endpoints**: All health check endpoints now include service name and version

Example health response:

```json
{
  "status": "ok",
  "info": { "database": { "status": "up" } },
  "details": { "database": { "status": "up" } },
  "service": {
    "name": "key-service",
    "version": "1.2.3"
  }
}
```

## Environment Variables

Set in deployment:

```bash
export SERVICE_VERSION=1.2.3
```

This ensures the API responses reflect the deployed version.
