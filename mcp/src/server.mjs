import { stdin, stdout } from "node:process";
import { AegirSecurityClient } from "../../packages/npm/dist/esm/index.js";

function createClient() {
  const baseUrl = process.env.AEGIR_BASE_URL;
  if (!baseUrl) {
    throw new Error("AEGIR_BASE_URL is required.");
  }

  return new AegirSecurityClient({
    baseUrl,
    configKey: process.env.AEGIR_CONFIG_KEY,
    developerKey: process.env.AEGIR_DEVELOPER_KEY
  });
}

export async function handleMessage(client, message) {
  switch (message.method) {
    case "initialize":
      return {
        protocolVersion: "2025-03-26",
        serverInfo: { name: "aegir-sdk-mcp", version: "0.1.0-Beta.1" },
        capabilities: { tools: {} }
      };
    case "tools/list":
      return {
        tools: [
          tool("scan_identity", "Scan an identity subject.", { subjectId: "string" }),
          tool("get_identity_graph", "Get an identity graph snapshot.", { subjectId: "string" }),
          tool("get_identity_graph_json", "Get an identity graph snapshot as JSON.", { subjectId: "string" }),
          tool("get_exposure_summary", "Get an exposure summary.", { subjectId: "string" }),
          tool("perform_action", "Perform an identity action.", {
            subjectId: "string",
            actionType: "string",
            targetNodeId: "string?",
            reason: "string?"
          }),
          tool("reverse_action", "Reverse an identity action.", {
            actionId: "string",
            reason: "string?"
          }),
          tool("get_action_history", "Get the action history for a subject.", { subjectId: "string" })
        ]
      };
    case "tools/call":
      return await handleToolCall(client, message.params ?? {});
    default:
      throw new Error(`Unsupported method '${message.method}'.`);
  }
}

function tool(name, description, inputShape) {
  return {
    name,
    description,
    inputSchema: {
      type: "object",
      properties: Object.fromEntries(
        Object.entries(inputShape).map(([key, value]) => [
          key,
          { type: value.startsWith("string") ? "string" : "object" }
        ])
      )
    }
  };
}

async function handleToolCall(client, params) {
  const name = params.name;
  const args = params.arguments ?? {};
  let result;

  switch (name) {
    case "scan_identity":
      result = await client.scanIdentity(args.subjectId);
      break;
    case "get_identity_graph":
      result = await client.getIdentityGraph(args.subjectId);
      break;
    case "get_identity_graph_json":
      result = await client.getIdentityGraphJson(args.subjectId);
      break;
    case "get_exposure_summary":
      result = await client.getExposureSummary(args.subjectId);
      break;
    case "perform_action":
      result = await client.performAction(args);
      break;
    case "reverse_action":
      result = await client.reverseAction(args.actionId, args.reason);
      break;
    case "get_action_history":
      result = await client.getActionHistory(args.subjectId);
      break;
    default:
      throw new Error(`Unsupported tool '${name}'.`);
  }

  return {
    content: [
      {
        type: "text",
        text: typeof result === "string" ? result : JSON.stringify(result, null, 2)
      }
    ]
  };
}

async function main() {
  const client = createClient();
  let buffer = "";

  stdin.setEncoding("utf8");
  stdin.on("data", async (chunk) => {
    buffer += chunk;
    let newlineIndex = buffer.indexOf("\n");

    while (newlineIndex >= 0) {
      const raw = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      newlineIndex = buffer.indexOf("\n");

      if (!raw) {
        continue;
      }

      const message = JSON.parse(raw);

      try {
        const result = await handleMessage(client, message);
        stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n`);
      } catch (error) {
        stdout.write(`${JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32000, message: error instanceof Error ? error.message : "Unknown error" }
        })}\n`);
      }
    }
  });
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  main();
}

