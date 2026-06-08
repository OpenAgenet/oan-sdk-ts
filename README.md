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
- `packages/client-ts`: small HTTP client for resource Discovery, Root version
  lookup, CDN resource index access, and Discovery sync.
- `packages/sdk-ts`: SDK core helpers for DID shape checks, resource package
  binding checks, exact-version checks, lifecycle checks, and artifact reference
  extraction.

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
