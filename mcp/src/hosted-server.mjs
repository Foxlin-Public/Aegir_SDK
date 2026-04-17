import http from "node:http";
import { createClient, createJsonRpcError, createJsonRpcSuccess, getToolDescriptors, handleMessage } from "./core.mjs";

const DEFAULT_PORT = Number.parseInt(process.env.AEGIR_MCP_PORT ?? "8788", 10);
const DEFAULT_HOST = process.env.AEGIR_MCP_HOST ?? "0.0.0.0";
const REQUIRED_BEARER_TOKEN = process.env.AEGIR_MCP_BEARER_TOKEN;

export function createHostedServer({
  client = createClient(),
  port = DEFAULT_PORT,
  host = DEFAULT_HOST,
  bearerToken = REQUIRED_BEARER_TOKEN
} = {}) {
  const server = http.createServer(async (request, response) => {
    try {
      setCorsHeaders(response);

      if (request.method === "OPTIONS") {
        response.writeHead(204);
        response.end();
        return;
      }

      if (!authorize(request, response, bearerToken)) {
        return;
      }

      if (request.method === "GET" && request.url === "/health") {
        writeJson(response, 200, {
          status: "ok",
          service: "aegir-sdk-mcp-host",
          version: "0.1.0-Beta.1"
        });
        return;
      }

      if (request.method === "GET" && request.url === "/manifest") {
        writeJson(response, 200, {
          name: "aegir-sdk-mcp",
          version: "0.1.0-Beta.1",
          transport: "http-jsonrpc",
          endpoint: "/mcp",
          tools: getToolDescriptors()
        });
        return;
      }

      if (request.method === "POST" && request.url === "/mcp") {
        const rawBody = await readBody(request);
        const message = rawBody ? JSON.parse(rawBody) : {};
        const id = message.id ?? null;

        try {
          const result = await handleMessage(client, message);
          writeJson(response, 200, createJsonRpcSuccess(id, result));
        } catch (error) {
          writeJson(response, 500, createJsonRpcError(id, error));
        }

        return;
      }

      writeJson(response, 404, {
        error: "not_found",
        message: "Use GET /health, GET /manifest, or POST /mcp."
      });
    } catch (error) {
      writeJson(response, 500, {
        error: "internal_error",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });

  return {
    server,
    async listen() {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve();
        });
      });

      return server.address();
    },
    async close() {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }

          resolve();
        });
      });
    }
  };
}

async function readBody(request) {
  let body = "";

  for await (const chunk of request) {
    body += chunk;
  }

  return body;
}

function authorize(request, response, bearerToken) {
  if (!bearerToken) {
    return true;
  }

  const header = request.headers.authorization;
  if (header === `Bearer ${bearerToken}`) {
    return true;
  }

  writeJson(response, 401, {
    error: "unauthorized",
    message: "A valid bearer token is required."
  });
  return false;
}

function setCorsHeaders(response) {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function writeJson(response, statusCode, payload) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload));
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  const hosted = createHostedServer();
  hosted.listen().then((address) => {
    const resolvedPort = typeof address === "object" && address ? address.port : DEFAULT_PORT;
    console.log(`Aegir SDK hosted MCP listening on ${DEFAULT_HOST}:${resolvedPort}`);
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
