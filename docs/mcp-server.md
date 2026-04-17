# MCP Server

The Beta-1 MCP server wraps the hosted Aegir SDK surface.

Beta-1 supports two transports:

- `stdio` for local MCP clients
- hosted HTTP JSON-RPC for Foxlin-managed deployment

## Location

- package: `./mcp`
- stdio entrypoint: `./mcp/src/server.mjs`
- hosted entrypoint: `./mcp/src/hosted-server.mjs`

## Configuration

Both transports read:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

The hosted transport also reads:

- `AEGIR_MCP_HOST`
- `AEGIR_MCP_PORT`
- `AEGIR_MCP_BEARER_TOKEN`

## Tools

- `scan_identity`
- `get_identity_graph`
- `get_identity_graph_json`
- `get_exposure_summary`
- `perform_action`
- `reverse_action`
- `get_action_history`

## Local MCP Example Configuration

```json
{
  "command": "node",
  "args": ["C:/path/to/Aegir_SDK/mcp/src/server.mjs"],
  "env": {
    "AEGIR_BASE_URL": "https://systems.foxlinindustries.cloud/apis",
    "AEGIR_CONFIG_KEY": "set-me",
    "AEGIR_DEVELOPER_KEY": "set-me"
  }
}
```

## Hosted Beta-1 Endpoints

The hosted transport exposes:

- `GET /health`
- `GET /manifest`
- `POST /mcp`

The `POST /mcp` route accepts one JSON-RPC message per HTTP request and returns one JSON-RPC response body.

If `AEGIR_MCP_BEARER_TOKEN` is set, requests must send:

```http
Authorization: Bearer <token>
```

## Hosted Example

```bash
AEGIR_BASE_URL=https://systems.foxlinindustries.cloud/apis \
AEGIR_CONFIG_KEY=set-me \
AEGIR_DEVELOPER_KEY=set-me \
AEGIR_MCP_BEARER_TOKEN=set-me \
node ./mcp/src/hosted-server.mjs
```

Then call:

```http
POST http://localhost:8788/mcp
Content-Type: application/json
Authorization: Bearer set-me
```

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "tools/call",
  "params": {
    "name": "scan_identity",
    "arguments": {
      "subjectId": "developer:dev_123"
    }
  }
}
```

## Scope

This server exposes only the current Beta-1 hosted operations. It does not add any Beta-2 tools or unpublished product internals.
