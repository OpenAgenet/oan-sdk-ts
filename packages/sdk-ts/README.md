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

The package now also includes:

- draft validation reports for browser and skill flows
- normalized discovery query builders
- concise trust summaries for resource packages and discovery candidates
- display-friendly discovery result summaries
- local identity helpers for subject / agent DID material generation
- reusable identity-bundle helpers that can back `.oan-dids` style local stores

For product UX, the recommended pattern is:

- hide filesystem details from beginner users
- expose local identity creation, backup export, and backup import as product actions
- keep the `.oan-dids` directory convention as a technical/runtime detail for SDK, skill, CLI, and advanced settings

This package should remain transport-agnostic. Raw HTTP access belongs in
`client-ts`, while AI-facing workflow orchestration belongs in `oan-skill`.
