# Aegir SDK MCP

This is the Beta-1 MCP server for Aegir Security.

It exposes the hosted/public Aegir operations in two Beta-1 transports:

- `stdio` for local MCP clients that spawn a process directly
- hosted HTTP JSON-RPC for Foxlin-managed deployment and shared developer access

Configuration:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`
- `AEGIR_MCP_HOST`
- `AEGIR_MCP_PORT`
- `AEGIR_MCP_BEARER_TOKEN`

Commands:

- local stdio: `npm start`
- hosted HTTP: `npm run start:hosted`
