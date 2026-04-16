# MCP Server

The Beta-1 MCP server is a stdio server that wraps the hosted Aegir SDK surface.

## Location

- package: `./mcp`
- entrypoint: `./mcp/src/server.mjs`

## Configuration

The server reads:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

## Tools

- `scan_identity`
- `get_identity_graph`
- `get_identity_graph_json`
- `get_exposure_summary`
- `perform_action`
- `reverse_action`
- `get_action_history`

## Example Configuration

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

## Scope

This server exposes only the current Beta-1 hosted operations. It does not add any Beta-2 tools or unpublished product internals.

