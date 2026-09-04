<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN SDK TypeScript

TypeScript SDK for OpenAgenet (OAN), an open infrastructure project for the
Internet of Agents (IoA). The SDK gives applications, skills, and developer
tools a typed way to work with DID-based OAN resource registration, semantic
discovery, lifecycle checks, and verification before invocation.

The active SDK surface is resource-oriented and uses `did:oan` identifiers.
Client code should discover and verify Resource packages for Agent Service,
Skill, MCP Server, and Tool/API resources instead of using legacy Agent-only
routes.

Published package:

```powershell
npm install @openagenet/oan-sdk-ts
```

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

## Typical Use Cases

Use this SDK when you need a typed client layer for OAN rather than raw HTTP
calls. Common scenarios include:

- a backend service that registers an Agent Service, Skill, MCP Server, or
  Tool/API resource through the official gateway
- a CLI or internal tool that checks whether a resource is already visible in
  Discovery before an operator publishes it downstream
- a browser or portal feature that needs to query resource summaries, status,
  or trust evidence from the same origin as the official website
- a governance or operations tool that inspects Root, Registrar, Discovery, or
  Trust Indexer read surfaces without reimplementing request shapes

The usual flow is:

1. create an `OanClient`
2. point it at the official gateway or a custom topology
3. call the resource or status method you need
4. inspect the returned DID Document, resource package, or trust summary

For example, a community app can use the SDK to submit a registration draft for
the OAN community skill resource, then verify discovery visibility and inspect
why a query matched:

```ts
import { OanClient } from "@openagenet/oan-sdk-ts/client";

const client = new OanClient({ baseUrl: "https://www.openagenet.xyz" });

const submission = {
  resourceDid: "did:oan:SKexamplecommunityskill001",
  resourceType: "skill",
  packageVersion: "1.0.0",
  metadataHash: "sha256:community-skill-metadata",
  packageHash: "sha256:community-skill-package",
  hashAlgorithm: "sha-256",
  didDocument: {
    id: "did:oan:SKexamplecommunityskill001",
    oanMetadata: {
      resourceType: "skill",
      subjectType: "skill",
      name: "OAN Community Skill",
      description: "A practical skill for OAN registration and discovery flows.",
      endpoint: "https://www.openagenet.xyz/register",
    },
  },
};

const registration = await client.registerResource(submission);
const discovery = await client.discoverResources({
  query: "I need a tool that can search code repositories and summarize the project structure.",
});
const explanation = await client.explainDiscoveryQuery({
  query: "I need a tool that can search code repositories and summarize the project structure.",
});
```

## Public Website Gateway

For browser-facing and community workflows, use the official public website as
the same-origin OAN gateway:

- Base URL: `https://www.openagenet.xyz`

The public gateway exposes the route shape used by the website and community
skill:

- `POST /resources/register`
- `POST /discovery/resources/query`
- `GET /registrar/status`
- `GET /discovery/status`
- `GET /root/status`
- `GET /cdn/status`
- `GET /trust/v1/status`

Pass that base URL explicitly when building public-client integrations:

```ts
import { OanClient } from "@openagenet/oan-sdk-ts/client";

const client = new OanClient({ baseUrl: "https://www.openagenet.xyz" });
```

Third-party operators can expose the same route shape behind their own base URL.
Advanced users and operators can still override individual Registrar,
Discovery, Root, CDN, or Trust Indexer endpoints when testing a custom topology.

## License

This SDK repository is licensed under `Apache-2.0` to keep developer adoption
and ecosystem integration low-friction. Brand and official OpenAgenet (OAN)
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
for browser products such as `oan-homepage`.

`oan-community-skill` is expected to build community-facing AI workflows on top
of this SDK layer rather than duplicating raw HTTP, type, or
trust-verification logic. Official deployment, benchmark, and governance
automation are maintained separately by official operators.
