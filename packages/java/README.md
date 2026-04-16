# Aegir Security Java Package

`cloud.foxlin:aegir-security` is the Beta-1 Java client for Aegir Security.

It provides the same hosted security surface as the existing NPM client:

- `scanIdentity(subjectId)`
- `getIdentityGraph(subjectId)`
- `getIdentityGraphJson(subjectId)`
- `getExposureSummary(subjectId)`
- `performAction(request)`
- `reverseAction(actionId, reason)`
- `getActionHistory(subjectId)`

## Error Model

- unsuccessful responses throw `AegirSecurityError`
- `getStatus()` returns the HTTP status
- `getCode()` returns the canonical Aegir error code
- `getCorrelationId()` returns the response correlation id when present
- `getBody()` returns the parsed payload

## Diagnostics Hooks

`AegirSecurityClient` accepts `AegirDiagnosticsHooks` for:

- log events
- metric events
- trace events

## Safe Envelopes

The Java package includes the Beta-1 portable safe-envelope helpers in `PortableSecurity`:

- `createSafeEnvelope(...)`
- `validateSafeEnvelope(...)`
- `PortableSecurity.SafeEnvelopeRecord`
- `PortableSecurity.SafeEnvelopeValidationResult`
- `PortableSecurity.TrustCoreSignatureEnvelope`

## Trust-Core Signatures

The Java package includes the Beta-1 hybrid trust-core helper surface in `PortableSecurity`:

- `signChallengePayload(payload)`
- `verifyChallengePayload(payload, signature)`
- `signProofReceiptPayload(payload)`
- `verifyProofReceiptPayload(payload, signature)`
- `signIdentityTokenPayload(payload)`
- `verifyIdentityTokenPayload(payload, signature)`

## Agent-to-Agent Protocol

The Java package includes the same minimal Beta-1 A2A runtime shape in `PortableSecurity`:

- `PortableSecurity.InMemoryAgentToAgentProtocol`
- `send(...)`
- `getInbox(...)`
- `receive(...)`

The Java A2A path returns the same Beta-1 validation reasons:

- `accepted`
- `message_not_found`
- `payload_hash_mismatch`
- `signature_missing`

## Budget Envelopes

The Java package includes the same Beta-1 in-memory budgeting shape in `PortableSecurity`:

- `PortableSecurity.InMemoryBudgetEnvelopeService`
- `PortableSecurity.BudgetEnvelope`
- `PortableSecurity.BudgetExhaustedError`
