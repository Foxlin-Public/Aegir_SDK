# Aegir Security NPM Package

`@foxlin_industries/aegir-security` is the Phase 1 TypeScript client for Aegir Security.

It currently provides a typed client for:

- identity scanning
- identity graph retrieval
- deterministic graph JSON retrieval
- exposure summary retrieval
- reversible action execution
- action reversal
- action history lookup

## Install

```bash
npm install @foxlin_industries/aegir-security
```

## Example

```ts
import {
  AegirSecurityClient,
  type PerformIdentityActionRequest
} from "@foxlin_industries/aegir-security";

const client = new AegirSecurityClient({
  baseUrl: "https://systems.foxlinindustries.cloud/apis",
  configKey: process.env.AEGIR_CONFIG_KEY,
  developerKey: process.env.AEGIR_DEVELOPER_KEY
});

const scan = await client.scanIdentity("developer:dev_123");
const exposure = await client.getExposureSummary("developer:dev_123");

const actionRequest: PerformIdentityActionRequest = {
  subjectId: "developer:dev_123",
  actionType: "LockIdentity",
  reason: "Manual containment review."
};

const action = await client.performAction(actionRequest);
const reversed = await client.reverseAction(action.actionId, "Validation complete.");
const history = await client.getActionHistory("developer:dev_123");
```

## Current Beta-1 Surface

Primary package-facing class:

- `AegirSecurityClient`

Core methods:

- `scanIdentity(subjectId)`
- `getIdentityGraph(subjectId)`
- `getIdentityGraphJson(subjectId)`
- `getExposureSummary(subjectId)`
- `performAction(request)`
- `reverseAction(actionId, reason?)`
- `getActionHistory(subjectId)`

Error model:

- unsuccessful responses throw `AegirSecurityError`
- `AegirSecurityError.status` contains the HTTP status
- `AegirSecurityError.code` contains the canonical Aegir error code
- `AegirSecurityError.correlationId` contains the response correlation id when present
- `AegirSecurityError.body` contains the parsed JSON body when possible

## Diagnostics Hooks

`AegirSecurityClient` accepts `diagnosticsHooks` with:

- `log(entry)`
- `metric(event)`
- `trace(event)`

## Safe Envelopes

The NPM package includes the Beta-1 portable safe-envelope helpers:

- `createSafeEnvelope(payloadType, canonicalPayload, signatureEnvelope?)`
- `validateSafeEnvelope(envelope)`
- `SafeEnvelopeRecord`
- `SafeEnvelopeValidationResult`
- `TrustCoreSignatureEnvelope`

## Trust-Core Signatures

The NPM package includes the Beta-1 hybrid trust-core helper surface:

- `signChallengePayload(payload)`
- `verifyChallengePayload(payload, signature)`
- `signProofReceiptPayload(payload)`
- `verifyProofReceiptPayload(payload, signature)`
- `signIdentityTokenPayload(payload)`
- `verifyIdentityTokenPayload(payload, signature)`

## Agent-to-Agent Protocol

The NPM package includes the same minimal Beta-1 A2A runtime shape:

- `InMemoryAgentToAgentProtocol`
- `send(...)`
- `getInbox(...)`
- `receive(...)`

The NPM A2A path returns the same Beta-1 validation reasons:

- `accepted`
- `message_not_found`
- `payload_hash_mismatch`
- `signature_missing`

## Budget Envelopes

The NPM package includes the same Beta-1 in-memory budgeting shape:

- `InMemoryBudgetEnvelopeService`
- `BudgetEnvelope`
- `BudgetExhaustedError`

## Local Validation

Current local package validation uses:

- package tests in `src/Foxlin.Aegir.Npm/tests/client.test.mjs`
- the local tarball output from `npm run pack:local`
- the runnable sample in `samples/NpmConsumer`

Typical local validation flow:

```bash
npm test
npm run pack:local
npm --prefix ../../samples/NpmConsumer install
npm --prefix ../../samples/NpmConsumer run start
```

## Phase 1 Notes

- This package targets the Aegir Phase 1 internal security API surface.
- It can attach `X-Aegir-Config-Key` and `X-Aegir-Developer-Key` headers when provided.
- The local consumer sample executes mocked calls through the packaged client surface.
- Additional package ecosystems are tracked in `Docs/package-ecosystem-matrix.md`.
- The NPM package is an active Phase 1 deliverable.
