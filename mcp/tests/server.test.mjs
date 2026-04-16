import assert from "node:assert/strict";
import { handleMessage } from "../src/server.mjs";

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

const init = await handleMessage(client, { method: "initialize" });
assert.equal(init.serverInfo.name, "aegir-sdk-mcp");

const listed = await handleMessage(client, { method: "tools/list" });
assert.equal(Array.isArray(listed.tools), true);
assert.equal(listed.tools.some((tool) => tool.name === "scan_identity"), true);

const scanned = await handleMessage(client, {
  method: "tools/call",
  params: { name: "scan_identity", arguments: { subjectId: "developer:dev_123" } }
});
assert.equal(scanned.content[0].text.includes("developer:dev_123"), true);

const reversed = await handleMessage(client, {
  method: "tools/call",
  params: { name: "reverse_action", arguments: { actionId: "action_001", reason: "test" } }
});
assert.equal(reversed.content[0].text.includes("action_001"), true);

assert.deepEqual(calls[0], ["scanIdentity", "developer:dev_123"]);

