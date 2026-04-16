# Aegir Security Python Package

`foxlin-aegir-security` is the Beta-1 Python client for Aegir Security.

It provides the same hosted security surface as the existing NPM client:

- `scanIdentity(subjectId)`
- `getIdentityGraph(subjectId)`
- `getIdentityGraphJson(subjectId)`
- `getExposureSummary(subjectId)`
- `performAction(request)`
- `reverseAction(actionId, reason=None)`
- `getActionHistory(subjectId)`

## Error Model

- unsuccessful responses raise `AegirSecurityError`
- `AegirSecurityError.status` contains the HTTP status
- `AegirSecurityError.code` contains the canonical Aegir error code
- `AegirSecurityError.correlationId` contains the response correlation id when present
- `AegirSecurityError.body` contains the parsed response payload

## Diagnostics Hooks

`AegirSecurityClient` accepts `AegirDiagnosticsHooks` with:

- `log(entry)`
- `metric(event)`
- `trace(event)`

## Safe Envelopes

The Python package includes the Beta-1 safe-envelope helpers:

- `create_safe_envelope(payload_type, canonical_payload, signature_envelope=None)`
- `validate_safe_envelope(envelope)`
- `SafeEnvelopeRecord`
- `SafeEnvelopeValidationResult`
- `TrustCoreSignatureEnvelope`

## Trust-Core Signatures

The Python package includes the Beta-1 hybrid trust-core helper surface:

- `sign_challenge_payload(payload)`
- `verify_challenge_payload(payload, signature)`
- `sign_proof_receipt_payload(payload)`
- `verify_proof_receipt_payload(payload, signature)`
- `sign_identity_token_payload(payload)`
- `verify_identity_token_payload(payload, signature)`

## Agent-to-Agent Protocol

The Python package includes the same minimal Beta-1 A2A runtime shape:

- `InMemoryAgentToAgentProtocol`
- `send(...)`
- `get_inbox(...)`
- `receive(...)`

The Python A2A path returns the same Beta-1 validation reasons:

- `accepted`
- `message_not_found`
- `payload_hash_mismatch`
- `signature_missing`

## Budget Envelopes

The Python package includes the same Beta-1 in-memory budgeting shape:

- `InMemoryBudgetEnvelopeService`
- `BudgetEnvelope`
- `BudgetExhaustedError`

## Install

```bash
python -m pip install .
```

## Example

```python
from foxlin_aegir_security import AegirSecurityClient, PerformIdentityActionRequest

client = AegirSecurityClient(
    base_url="https://systems.foxlinindustries.cloud/apis",
    config_key="sample-config-key",
    developer_key="sample-developer-key",
)

scan = client.scanIdentity("developer:dev_123")
exposure = client.getExposureSummary("developer:dev_123")
action = client.performAction(
    PerformIdentityActionRequest(
        subjectId="developer:dev_123",
        actionType="VerifyConnection",
        targetNodeId="application:app_portal",
        reason="Python sample validation.",
    )
)
```
