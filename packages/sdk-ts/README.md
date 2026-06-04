<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# sdk-ts

TypeScript SDK for OAN clients.


## did:oan Resource Helpers

This package contains SDK core helpers for did:oan resource registration, discovery, and verification.

Draft helpers:

- `createAgentServiceDraft`
- `createSkillDraft`
- `createMcpServerDraft`
- `createToolApiDraft`

Verification helpers check DID shape, DID subject-code/resourceType consistency, Root package binding, lifecycle state, exact-version requests, and artifact hash presence. Discovery is not treated as a file host for external Skill or API artifacts.
