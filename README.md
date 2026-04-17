# Aegir SDK

`Aegir_SDK` is the standalone Beta-1 SDK repository for Aegir Security.

This repo contains only Beta-1 public SDK components:

- the public language SDKs for `.NET`, `Node`, `Java`, `Python`, and `Go`
- installation wrappers for local setup and CI bootstrap
- example consumers for `.NET` and `Node`
- a Beta-1 MCP server that exposes the hosted Aegir API surface through the SDK
- a Beta-1 hosted MCP service wrapper for Foxlin-managed shared access
- Beta-1 documentation for installation, integration, repository layout, and MCP usage

It does not include the private product runtime, Beta-2 work, or internal-only admin/product code.

## Beta-1 Scope

The SDK surface in this repo is limited to the current hosted/public Aegir Beta-1 operations:

- `scanIdentity`
- `getIdentityGraph`
- `getIdentityGraphJson`
- `getExposureSummary`
- `performAction`
- `reverseAction`
- `getActionHistory`

Beta-1 package helpers also include:

- safe envelopes
- budget envelopes
- minimal in-memory agent-to-agent protocol
- trust-core helper signing and verification utilities
- diagnostics hooks
- canonical error semantics

## Repo Layout

- [docs](./docs): Beta-1 SDK documentation
- [installers](./installers): wrapped installer scripts
- [packages](./packages): language SDK packages and package-facing materials
- [examples](./examples): small example consumers
- [mcp](./mcp): Beta-1 MCP server for Aegir

## Beta-1 Packages

- `.NET`: `Foxlin.Aegir.Security` version `0.1.0-Beta.1`
- `Node`: `@foxlin_industries/aegir-security` version `0.1.0-Beta.1`
- `Java`: `cloud.foxlin:aegir-security` version `0.1.0-Beta.1`
- `Python`: `foxlin-aegir-security` version `0.1.0-Beta.1`
- `Go`: module `foxlin/aegir-security-go`

## Wrapped Installers

- PowerShell: [install-sdk.ps1](./installers/install-sdk.ps1)
- Shell: [install-sdk.sh](./installers/install-sdk.sh)

These wrappers bootstrap only Beta-1 SDK components and the Beta-1 MCP server.

## MCP Server

The MCP server lives in [mcp](./mcp) and exposes the Beta-1 hosted operations through stdio tools:

- `scan_identity`
- `get_identity_graph`
- `get_identity_graph_json`
- `get_exposure_summary`
- `perform_action`
- `reverse_action`
- `get_action_history`

Configuration is environment-based:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

See [docs/mcp-server.md](./docs/mcp-server.md) for details.

## Quick Start

### PowerShell

```powershell
pwsh ./installers/install-sdk.ps1 -Node -DotNet -Mcp
```

### Bash

```bash
bash ./installers/install-sdk.sh --node --dotnet --mcp
```

## Beta-1 Documents

- [Beta-1 Scope](./docs/beta1-scope.md)
- [Repository Layout](./docs/repository-layout.md)
- [Installer Guide](./docs/installer.md)
- [MCP Server Guide](./docs/mcp-server.md)
- [Hosted MCP Guide](./docs/hosted-mcp.md)
- [Integration: .NET](./docs/integration-dotnet.md)
- [Integration: Node](./docs/integration-node.md)
- [Integration: Java](./docs/integration-java.md)
- [Integration: Python](./docs/integration-python.md)
- [Integration: Go](./docs/integration-go.md)
