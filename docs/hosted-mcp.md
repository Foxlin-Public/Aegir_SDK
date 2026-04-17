# Hosted MCP

The Beta-1 hosted MCP service is the network-facing wrapper for the Aegir SDK MCP package.

## Beta-1 Purpose

This hosted service exists so Foxlin can expose the current Beta-1 Aegir SDK tools at one managed address for:

- internal Foxlin testing
- partner/developer Beta-1 testing
- tool consumers that cannot launch a local stdio MCP process

## Transport Shape

Beta-1 uses a simple HTTP JSON-RPC wrapper around the same MCP tool handlers that the local stdio server uses.

Hosted routes:

- `GET /health`
- `GET /manifest`
- `POST /mcp`

## Environment

Required:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

Hosted-only:

- `AEGIR_MCP_HOST`
- `AEGIR_MCP_PORT`
- `AEGIR_MCP_BEARER_TOKEN`

## Authentication

If `AEGIR_MCP_BEARER_TOKEN` is present, callers must send:

```http
Authorization: Bearer <token>
```

If the token is omitted, the hosted service returns `401 unauthorized`.

## Default Local Address

Without a reverse proxy, the hosted service listens on:

- host: `0.0.0.0`
- port: `8788`
- MCP route: `http://<server>:8788/mcp`

## CI/CD Deployment Shape

Beta-1 deployment is designed for CI/CD:

1. validate the SDK/MCP package
2. upload the repo bundle to the target server
3. write the hosted MCP environment file
4. install/update the systemd service
5. restart the hosted MCP process

The deployment script for this flow is:

- `./scripts/deploy-hosted-mcp.sh`

The GitHub Actions workflow for this flow is:

- `./.github/workflows/hosted-mcp.yml`

## Scope

The hosted service exposes only the current Beta-1 SDK tools:

- `scan_identity`
- `get_identity_graph`
- `get_identity_graph_json`
- `get_exposure_summary`
- `perform_action`
- `reverse_action`
- `get_action_history`
