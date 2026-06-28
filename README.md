<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN SDK TypeScript

TypeScript SDKs for OpenAgenet clients, Discovery access, and developer tools.

The active SDK surface is resource-oriented and uses `did:oan` identifiers.
Client code should discover and verify Resource packages for Agent Service,
Skill, MCP Server, and Tool/API resources instead of using legacy Agent-only
routes.

## Packages

- `packages/protocol-types`: shared TypeScript protocol types for `did:oan`
  DID Documents, Resource packages, Root proofs, and Discovery responses.
- `packages/client-ts`: HTTP client for Registrar, Root, CDN, and Discovery
  resource workflows, including registration, discovery, package lookup, and
  lifecycle observation helpers.
- `packages/sdk-ts`: SDK core helpers for DID shape checks, resource package
  binding checks, exact-version checks, lifecycle checks, and artifact reference
  extraction.
- `packages/governance-ts`: governance-facing SDK helpers built around current
  trust-indexer read APIs and future chain-governance integration.

Discovery returns verified resource metadata and artifact references. It is not
treated as a download proxy for external Skill files or other artifacts.

## License

This SDK repository is licensed under `Apache-2.0` to keep developer adoption
and ecosystem integration low-friction. Brand and official OpenAgenet / OAN
identity rights are reserved separately.

## Resource Draft Helpers

`packages/sdk-ts` exposes convenience helpers for the four initial OAN resource forms:

- `createAgentServiceDraft`
- `createSkillDraft`
- `createMcpServerDraft`
- `createToolApiDraft`

These helpers generate DID Document drafts with `oanMetadata`, resource descriptions, service endpoints where appropriate, protocol bindings, package metadata, and artifact references. They enforce DID subject-code and `resourceType` consistency before returning a draft.

## Layering With Skills

`oan-sdk-ts` should remain the reusable TypeScript foundation.

It owns:

- protocol types
- endpoint clients
- verification helpers
- lifecycle observation helpers
- governance-facing read/write SDK surfaces

It now also covers current live operational inspection helpers, including:

- Registrar capability-tag suggestion
- Registrar Root-authorization inspection
- Discovery query explanation
- Discovery authorized-domain inspection
- Root resource-version inspection

It now additionally provides browser- and portal-friendly helper surfaces for:

- DID Document draft validation reports
- normalized discovery query construction
- concise trust summary derivation for packages and discovery results
- lifecycle polling until discovery visibility

This makes `oan-sdk-ts` suitable not only for developer tools and
`oan-community-skill`, but also as the preferred protocol-facing client layer
for future browser products such as `oan-homepage`.

`oan-community-skill` is expected to build community-facing AI workflows on top
of this SDK layer rather than duplicating raw HTTP, type, or
trust-verification logic. Official deployment, benchmark, and governance
automation belongs in `oan-official-skill`.
