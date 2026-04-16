# Aegir Security Go Package

`foxlin/aegir-security-go` is the Beta-1 Go client for Aegir Security.

It provides the same hosted security surface as the existing NPM client:

- `ScanIdentity`
- `GetIdentityGraph`
- `GetIdentityGraphJSON`
- `GetExposureSummary`
- `PerformAction`
- `ReverseAction`
- `GetActionHistory`

## Error Model

- unsuccessful responses return `*AegirSecurityError`
- `Status` contains the HTTP status
- `Code` contains the canonical Aegir error code
- `CorrelationID` contains the response correlation id when present
- `Body` contains the raw response payload

## Diagnostics Hooks

`NewAegirSecurityClientWithOptions(...)` accepts `DiagnosticsHooks` for:

- log events
- metric events
- trace events

## Safe Envelopes

The Go package includes the same Beta-1 safe-envelope contract used by the core runtime:

- `CreateSafeEnvelope(...)`
- `ValidateSafeEnvelope(...)`
- `SafeEnvelopeRecord`
- `SafeEnvelopeValidationResult`
- `TrustCoreSignatureEnvelope`

## Trust-Core Signatures

The Go package includes the Beta-1 hybrid trust-core helper surface:

- `SignChallengePayload(payload)`
- `VerifyChallengePayload(payload, signature)`
- `SignProofReceiptPayload(payload)`
- `VerifyProofReceiptPayload(payload, signature)`
- `SignIdentityTokenPayload(payload)`
- `VerifyIdentityTokenPayload(payload, signature)`

## Agent-to-Agent Protocol

The Go package includes the same minimal Beta-1 agent-to-agent runtime shape:

- `NewInMemoryAgentToAgentProtocol()`
- `Send(...)`
- `GetInbox(...)`
- `Receive(...)`

The Go A2A path uses the safe-envelope contract for message integrity and returns the same Beta-1 validation reasons:

- `accepted`
- `message_not_found`
- `payload_hash_mismatch`
- `signature_missing`

## Budget Envelopes

The Go package includes the same Beta-1 in-memory budgeting shape:

- `NewInMemoryBudgetEnvelopeService()`
- `GetEnvelope(...)`
- `Consume(...)`
- `BudgetEnvelope`
- `BudgetExhaustedError`
