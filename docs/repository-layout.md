# Repository Layout

## Root

- `README.md`: repo entry point
- `CHANGELOG.md`: Beta-1 SDK release notes for this repo
- `CONTRIBUTING.md`: contribution rules
- `sdk-manifest.json`: version and package manifest
- `.github/workflows/hosted-mcp.yml`: Beta-1 hosted MCP validation and deployment workflow
- `scripts/deploy-hosted-mcp.sh`: server deployment helper for the hosted MCP service

## `packages`

- `packages/dotnet`: .NET package-facing materials and example
- `packages/npm`: Node/TypeScript Beta-1 package source
- `packages/java`: Java Beta-1 package source
- `packages/python`: Python Beta-1 package source
- `packages/go`: Go Beta-1 package source

## `examples`

- `examples/dotnet`: .NET sample consumer
- `examples/npm`: Node sample consumer

## `installers`

- `install-sdk.ps1`: wrapped PowerShell installer
- `install-sdk.sh`: wrapped shell installer

## `mcp`

- `package.json`: MCP package metadata
- `src/server.mjs`: Beta-1 stdio MCP server
- `src/hosted-server.mjs`: Beta-1 hosted HTTP MCP wrapper
- `tests/server.test.mjs`: MCP tool-contract tests
- `tests/hosted-server.test.mjs`: hosted MCP transport tests
