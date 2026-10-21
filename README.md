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

For example, a community app can build a resource draft with the SDK, complete
the signing and hash material required by the selected registration workflow,
then submit that prepared submission and verify discovery visibility. The
following is intentionally a draft-oriented example; a hand-written partial
DID Document is not a valid registration submission:

```ts
import { createSkillDraft } from "@openagenet/oan-sdk-ts";
import { OanClient } from "@openagenet/oan-sdk-ts/client";

const client = new OanClient(); // uses DEFAULT_OAN_OFFICIAL_ENDPOINTS
const didDocument = createSkillDraft({
  resourceDid: "did:oan:<new-resource-routing-code>",
  name: "Example Skill",
  description: "A reviewed skill description.",
  version: "1.0.0",
  serviceEndpoint: "https://example.invalid/skill",
  protocol: "skill",
});

// The complete signed submission should normally be produced by the identity
// and registration-material helpers (or oan-community-skill), not assembled by
// copying this example. It must contain the final hashes and proofs.
// Pass this draft to an identity/signing workflow (for example
// oan-community-skill), which creates the complete submission.
console.log(didDocument);

// const registration = await client.registerResource(completeSignedSubmission);

const registration = await client.registerResource(submission);
const discovery = await client.discoverResources({
  query: "I need a tool that can search code repositories and summarize the project structure.",
});
const explanation = await client.explainDiscoveryQuery({
  query: "I need a tool that can search code repositories and summarize the project structure.",
});
```

## Official endpoints and website gateway

`OanClient` uses the official API topology by default:

- API base URL: `https://api.openagenet.xyz`
- Registrar: `https://registrar.openagenet.xyz`
- Discovery: `https://discovery.openagenet.xyz`
- Root: `https://root.openagenet.xyz`
- CDN: `https://cdn.openagenet.xyz`
- Trust Indexer: `https://trust.openagenet.xyz`

The website at `https://www.openagenet.xyz` is a browser-facing gateway and
may proxy the same route family. It is the default entry point for the
community Skill, while SDK applications should normally use the API defaults
above or explicitly configure a compatible custom topology.

The public gateway exposes the route shape used by the website and community
skill:

- `POST /resources/register`
- `POST /discovery/resources/query`
- `GET /registrar/status`
- `GET /discovery/status`
- `GET /root/status`
- `GET /cdn/status`
- `GET /trust/v1/status`

For a deployment that exposes the public website gateway as its API base, pass
it explicitly:

```ts
import { OanClient } from "@openagenet/oan-sdk-ts/client";

const client = new OanClient({ baseUrl: "https://www.openagenet.xyz" });
```

Third-party operators can expose the same route shape behind their own base URL.
Advanced users and operators can still override individual Registrar,
Discovery, Root, CDN, or Trust Indexer endpoints when testing a custom topology.

## Import paths and identity material

The package exposes these stable entry points:

- `@openagenet/oan-sdk-ts` — SDK core, draft, identity, signing and verification helpers
- `@openagenet/oan-sdk-ts/client` — HTTP client and official endpoint constants
- `@openagenet/oan-sdk-ts/governance` — governance and trust-indexer helpers
- `@openagenet/oan-sdk-ts/protocol-types` — shared protocol types
- `@openagenet/oan-sdk-ts/identity-store-node` — Node.js identity-store persistence helpers

Identity creation and registration-material helpers generate the DID Document,
OAN Identity record and signed registration material locally. Private keys stay
in the local identity store and are used for local signing; only the public DID
Document, proofs and registration data required by the protocol are submitted.
For an existing controller, use its stored identity record to create the
controller authorization proof rather than rewriting its registered DID
Document. A resource still owns its own signing key even when an external
controller is declared.

## License

This SDK repository is licensed under `Apache-2.0` to keep developer adoption
and ecosystem integration low-friction. Brand and official OpenAgenet (OAN)
identity rights are reserved separately.

## Resource Draft Helpers

`packages/sdk-ts` exposes convenience helpers for the four current OAN resource forms:

- `createAgentServiceDraft`
- `createSkillDraft`
- `createMcpServerDraft`
- `createToolApiDraft`

These helpers generate DID Document drafts with `oanMetadata`, resource descriptions, service endpoints where appropriate, protocol bindings, package metadata, and artifact references. They enforce DID subject-code and `resourceType` consistency before returning a draft.

The helpers create drafts; they do not by themselves register a resource. A
caller must finalize hashes, proofs and controller authorization (when needed),
then call `OanClient.registerResource()` with the complete submission. For a
turnkey community workflow, use `oan-community-skill`, which wraps these SDK
operations and persists receipts and identity materials.

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
