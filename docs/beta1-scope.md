# Beta-1 Scope

This repository contains only the Beta-1 public SDK scope.

## Included

- hosted API clients for `.NET`, `Node`, `Java`, `Python`, and `Go`
- public Beta-1 operations:
  - `scanIdentity`
  - `getIdentityGraph`
  - `getIdentityGraphJson`
  - `getExposureSummary`
  - `performAction`
  - `reverseAction`
  - `getActionHistory`
- safe-envelope helpers
- diagnostics hooks
- canonical error semantics
- trust-core helper signing and verification utilities
- budget envelope helpers
- minimal in-memory agent-to-agent protocol
- Beta-1 MCP server over the hosted SDK surface

## Excluded

- Beta-2 browser-extension work
- Beta-2 provider expansion
- Beta-2 KYC redesign work
- product-admin/runtime internals that are not part of the public SDK contract

