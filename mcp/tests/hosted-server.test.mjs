import assert from "node:assert/strict";
import { createHostedServer } from "../src/hosted-server.mjs";

const calls = [];
const client = {
  async scanIdentity(subjectId) {
    calls.push(["scanIdentity", subjectId]);
    return { subjectId };
  },
  async getIdentityGraph(subjectId) {
    calls.push(["getIdentityGraph", subjectId]);
    return { graphId: `graph:${subjectId}` };
  },
  async getIdentityGraphJson(subjectId) {
    calls.push(["getIdentityGraphJson", subjectId]);
    return JSON.stringify({ graphId: `graph:${subjectId}` });
  },
  async getExposureSummary(subjectId) {
    calls.push(["getExposureSummary", subjectId]);
    return { graphId: `graph:${subjectId}` };
  },
  async performAction(request) {
    calls.push(["performAction", request.subjectId]);
    return { actionId: "action_001", subjectId: request.subjectId };
  },
  async reverseAction(actionId, reason) {
    calls.push(["reverseAction", actionId, reason]);
    return { actionId, reason };
  },
  async getActionHistory(subjectId) {
    calls.push(["getActionHistory", subjectId]);
    return [{ subjectId }];
  }
};

const hosted = createHostedServer({
  client,
  host: "127.0.0.1",
  port: 0,
  bearerToken: "beta1-secret"
});

const address = await hosted.listen();
const baseUrl = `http://127.0.0.1:${address.port}`;

try {
  const unauthorized = await fetch(`${baseUrl}/health`);
  assert.equal(unauthorized.status, 401);

  const health = await fetch(`${baseUrl}/health`, {
    headers: { Authorization: "Bearer beta1-secret" }
  });
  assert.equal(health.status, 200);
  const healthBody = await health.json();
  assert.equal(healthBody.status, "ok");

  const manifest = await fetch(`${baseUrl}/manifest`, {
    headers: { Authorization: "Bearer beta1-secret" }
  });
  assert.equal(manifest.status, 200);
  const manifestBody = await manifest.json();
  assert.equal(Array.isArray(manifestBody.tools), true);
  assert.equal(manifestBody.tools.some((tool) => tool.name === "scan_identity"), true);

  const toolCall = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Authorization: "Bearer beta1-secret",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "msg-1",
      method: "tools/call",
      params: {
        name: "scan_identity",
        arguments: {
          subjectId: "developer:dev_456"
        }
      }
    })
  });

  assert.equal(toolCall.status, 200);
  const toolBody = await toolCall.json();
  assert.equal(toolBody.result.content[0].text.includes("developer:dev_456"), true);
  assert.deepEqual(calls[0], ["scanIdentity", "developer:dev_456"]);
} finally {
  await hosted.close();
}
