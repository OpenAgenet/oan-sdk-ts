<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# Homepage Integration Guide

This guide describes how `oan-sdk-ts` should be used by browser-facing OAN
products such as the official homepage.

The guide is intentionally limited to SDK and browser integration boundaries.
It does not change Root, Registrar, Discovery, CDN, or trust-indexer protocol
semantics.

## Public Endpoint Profile

The official homepage deployment uses:

```text
Homepage:       https://openagenet.xyz
Homepage API:   https://api.openagenet.xyz
Root:           https://root.openagenet.xyz
Registrar:      https://registrar.openagenet.xyz
Discovery:      https://discovery.openagenet.xyz
Trust indexer:  https://trust.openagenet.xyz
CDN:            https://cdn.openagenet.xyz
```

CDN may be configured for advanced diagnostics. Ordinary registration and
discovery UX should not require users to understand CDN.

## Browser-Facing Responsibilities

Use SDK helpers for:

- DID and resource-type shape checks
- DID Document draft validation
- registration submission preparation
- Registrar client calls
- Discovery query construction
- discovery result trust summaries
- lifecycle observation after registration

Do not duplicate protocol validation in product UI code when an SDK helper is
available.

## Local Identity Boundary

Browser-facing products may generate or import local identity material, but the
private-key boundary must remain explicit:

- private keys stay local
- local identity backups require deliberate user export
- imported identity backups require deliberate user action
- homepage backend must not receive raw private keys
- Registrar, Discovery, Root, and CDN must not receive raw private keys

Product copy should use user-facing terms such as "local identity", "backup",
"import", and "export". The `.oan-dids` convention is useful for CLI, tests,
and advanced tooling, but should not be forced into beginner-facing UX.

## Registration UX Semantics

A successful Registrar submission does not mean immediate Discovery visibility.

Use lifecycle language that distinguishes:

- submitted to Registrar
- accepted by Root
- published/distributed by OAN
- visible in Discovery

Errors should be categorized where possible:

- validation failure
- rejected by Registrar
- busy or retry later
- endpoint unavailable
- lifecycle pending

## Test Portability

SDK tests must not hard-code a developer workstation path. When genesis-based
identity material is needed for tests, prefer:

1. an explicit environment variable such as `OAN_GENESIS_REGISTRAR_DIR`
2. a repository-relative path in the checked-out workspace

This keeps the SDK usable across local machines, CI, and future release
automation.
