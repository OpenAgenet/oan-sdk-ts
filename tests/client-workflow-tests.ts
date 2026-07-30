// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { DEFAULT_OAN_OFFICIAL_ENDPOINTS, OanClient } from "../packages/client-ts/src/index.js";
import { GovernanceClient, subjectTypeCodeForRole } from "../packages/governance-ts/src/index.js";
import type { ResourceRegistrationSubmission } from "../packages/protocol-types/src/index.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function createFetchStub(
  routes: Record<string, { status?: number; body: unknown }>,
): typeof fetch {
  return (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const key = `${method} ${url}`;
    const match = routes[key];
    if (!match) {
      return new Response(JSON.stringify({ error: "not_found", key }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify(match.body), {
      status: match.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

const resourceDid = "did:oan:SKDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz";
const versionOnlyResourceDid = "did:oan:SKDM:9KvVersionOnlyRoot2WfHa4Cd5Ej8LgNz";
const submission: ResourceRegistrationSubmission = {
  resourceDid,
  resourceType: "skill",
  didDocument: {
    id: resourceDid,
    oanMetadata: {
      subjectType: "skill",
      resourceType: "skill",
    },
  },
  packageVersion: "1.0.0",
  metadataHash: "sha256:metadata",
  packageHash: "sha256:package",
  hashAlgorithm: "sha256",
};

const fetchStub = createFetchStub({
  [`GET ${DEFAULT_OAN_OFFICIAL_ENDPOINTS.baseUrl}/registrar/status`]: {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
    },
  },
  [`GET ${DEFAULT_OAN_OFFICIAL_ENDPOINTS.baseUrl}/discovery/status`]: {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
    },
  },
  "GET https://gateway.example/registrar/status": {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
    },
  },
  "GET https://gateway.example/discovery/status": {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
    },
  },
  "GET https://gateway.example/root/status": {
    body: {
      status: "ok",
      latestVersionCount: 0,
    },
  },
  "GET https://gateway.example/cdn/status": {
    body: {
      status: "ok",
      resourceCount: 0,
    },
  },
  "GET https://override-registrar.example/registrar/status": {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
      endpoint: "override",
    },
  },
  "POST https://registrar.example/resources/register": {
    body: {
      status: "submitted",
      resourceDid,
      resourceType: "skill",
    },
  },
  "GET https://registrar.example/registrar/status": {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
    },
  },
  "GET https://registrar.example/registrar/root-authorization": {
    body: {
      registrarDid: "did:oan:INRG:test",
      rootReachable: true,
      authorization: { status: "authorized" },
    },
  },
  "POST https://registrar.example/capability-tags/suggest": {
    body: {
      suggestions: ["protocol.mcp"],
    },
  },
  "POST https://registrar.example/capability-tags/normalize": {
    body: {
      tags: ["protocol.mcp", "security.audit"],
      capabilityTags: ["protocol.mcp", "security.audit"],
    },
  },
  "GET https://registrar.example/registration/domain-catalog": {
    body: {
      registrarDid: "did:oan:INRG:test",
      authorizedDomains: ["legal"],
      domains: [{ id: "legal.contract_law", label: "Contract Law", selectable: true }],
    },
  },
  "POST https://registrar.example/registration/suggestions": {
    body: {
      authorizedDomains: [{ id: "legal.contract_law", label: "Contract Law", score: 0.9, covered: true, reason: "matched" }],
      outOfScopeDomainHints: [],
      capabilityTags: [{ value: "contract-law.force-majeure", score: 0.8, reason: "matched" }],
      resourceTypeHints: [{ value: "skill", score: 0.7, reason: "matched" }],
      protocolHints: [{ value: "https", score: 0.6, reason: "matched" }],
      warnings: [],
    },
  },
  [`GET https://registrar.example/resources/${encodeURIComponent(resourceDid)}`]: {
    body: {
      resourceDid,
      record: {
        resourceDid,
        status: "submitted",
      },
    },
  },
  "GET https://root.example/root/status": {
    body: {
      status: "ok",
      latestVersionCount: 1,
      cdnReadyQueueCount: 0,
    },
  },
  [`GET https://root.example/root/resources/${encodeURIComponent(resourceDid)}`]: {
    body: {
      resourceDid,
      package: {
        resourceDid,
        packageVersion: "1.0.0",
      },
    },
  },
  [`GET https://root.example/root/resources/${encodeURIComponent(resourceDid)}/versions`]: {
    body: {
      did: resourceDid,
      items: [{ packageVersion: "1.0.0", didDocumentHash: "sha256:did" }],
    },
  },
  [`GET https://root.example/root/resources/${encodeURIComponent(versionOnlyResourceDid)}`]: {
    body: {
      resourceDid: versionOnlyResourceDid,
      package: null,
    },
  },
  [`GET https://root.example/root/resources/${encodeURIComponent(versionOnlyResourceDid)}/versions`]: {
    body: {
      did: versionOnlyResourceDid,
      items: [{ packageVersion: "1.0.0", didDocumentHash: "sha256:did" }],
    },
  },
  "GET https://cdn.example/cdn/status": {
    body: {
      status: "ok",
      resourceCount: 1,
    },
  },
  [`GET https://cdn.example/cdn/resources/${encodeURIComponent(resourceDid)}`]: {
    body: {
      resourceDid,
      resourceType: "skill",
      packageVersion: "1.0.0",
      didDocument: { id: resourceDid },
      didDocumentHash: "sha256:did",
      metadataHash: "sha256:metadata",
      packageHash: "sha256:package",
      hashAlgorithm: "sha256",
      metadata: {
        resourceDid,
        resourceType: "skill",
        subjectType: "skill",
        name: "Skill",
        lifecycleState: "active",
        packageVersion: "1.0.0",
        packageHash: "sha256:package",
        metadataHash: "sha256:metadata",
        hashAlgorithm: "sha256",
        updatedAt: "2026-06-23T00:00:00Z",
      },
      rootProof: { rootDid: "did:oan:AGRT:test" },
      createdAt: "2026-06-23T00:00:00Z",
    },
  },
  "GET https://discovery.example/discovery/status": {
    body: {
      status: "ok",
      rootAuthorizationStatus: "authorized",
    },
  },
  "GET https://discovery.example/discovery/root-authorization": {
    body: {
      discoveryDid: "did:oan:INDS:test",
      rootReachable: true,
      status: "authorized",
      authorizedDomains: ["openagenet.local"],
    },
  },
  "GET https://discovery.example/discovery/authorized-domains": {
    body: {
      discoveryDid: "did:oan:INDS:test",
      authorizedDomains: ["openagenet.local"],
    },
  },
  "POST https://discovery.example/discovery/resources/query": {
    body: {
      discoveryDid: "did:oan:INDS:test",
      candidates: [{ resourceDid, resourceType: "skill", score: 1 }],
      createdAt: "2026-06-23T00:00:00Z",
    },
  },
  "POST https://discovery.example/discovery/index/resources/visibility": {
    body: {
      resourceDids: [resourceDid],
      visible: [resourceDid, versionOnlyResourceDid],
    },
  },
  "POST https://discovery.example/discovery/query/explain": {
    body: {
      query: { resourceType: "skill", limit: 5 },
      items: [{ resourceDid, resourceType: "skill", matched: true, score: 1 }],
      candidateCount: 1,
      usedIndexedPrefilter: true,
    },
  },
  "POST https://discovery.example/discovery/query/suggestions": {
    body: {
      queryRewrite: null,
      capabilityTags: [{ value: "cross-cutting.audit", score: 0.8, reason: "matched" }],
      resourceTypes: [{ value: "mcp_server", score: 0.7, reason: "matched" }],
      protocols: [{ value: "mcp", score: 0.9, reason: "matched" }],
      authorizedDomainHints: [{ id: "technology.security", label: "Security", score: 0.7, covered: true, reason: "matched" }],
      warnings: [],
    },
  },
  "GET https://indexer.example/v1/summary": {
    body: {
      active_registrar_count: 1,
      active_discovery_count: 1,
    },
  },
  "GET https://indexer.example/v1/status": {
    body: {
      last_processed_checkpoint: 123,
    },
  },
  "GET https://indexer.example/v1/registrars?status=active": {
    body: {
      subjects: [{ subject_did: "did:oan:INRG:test" }],
    },
  },
  "GET https://indexer.example/v1/discoveries?status=active&domain=openagenet.local": {
    body: {
      subjects: [{ subject_did: "did:oan:INDS:test" }],
    },
  },
  "GET https://indexer.example/v1/vc-issuers?status=active": {
    body: {
      subjects: [{ subject_did: "did:oan:INVC:test" }],
    },
  },
  "GET https://indexer.example/v1/subjects/2/did%3Aoan%3AINDS%3Atest/governance-active": {
    body: {
      governance_active: true,
      authorized: true,
      subject_type: "discovery",
      subject_type_code: 2,
      subject_did: "did:oan:INDS:test",
      status: "active",
      scope: "chain_governance_state_only",
    },
  },
});

const officialDefaultClient = new OanClient({ fetchImpl: fetchStub });
const officialRegistrarStatus = await officialDefaultClient.getRegistrarStatus();
assert(officialRegistrarStatus.status === "ok", "default official registrar endpoint mismatch");
const officialDiscoveryStatus = await officialDefaultClient.getDiscoveryStatus();
assert(officialDiscoveryStatus.status === "ok", "default official discovery endpoint mismatch");

const gatewayClient = new OanClient({
  baseUrl: "https://gateway.example/",
  fetchImpl: fetchStub,
});
const gatewayRegistrarStatus = await gatewayClient.getRegistrarStatus();
assert(gatewayRegistrarStatus.status === "ok", "baseUrl registrar endpoint mismatch");
const gatewayDiscoveryStatus = await gatewayClient.getDiscoveryStatus();
assert(gatewayDiscoveryStatus.status === "ok", "baseUrl discovery endpoint mismatch");
const gatewayRootStatus = await gatewayClient.getRootStatus();
assert(gatewayRootStatus.status === "ok", "baseUrl root endpoint mismatch");
const gatewayCdnStatus = await gatewayClient.getCdnStatus();
assert(gatewayCdnStatus.status === "ok", "baseUrl cdn endpoint mismatch");

const endpointOverrideClient = new OanClient({
  baseUrl: "https://gateway.example",
  registrarEndpoint: "https://override-registrar.example",
  fetchImpl: fetchStub,
});
const overrideRegistrarStatus = await endpointOverrideClient.getRegistrarStatus();
assert(
  (overrideRegistrarStatus as { endpoint?: string }).endpoint === "override",
  "explicit registrar endpoint should override baseUrl",
);
const overrideDiscoveryStatus = await endpointOverrideClient.getDiscoveryStatus();
assert(overrideDiscoveryStatus.status === "ok", "baseUrl should still supply non-overridden endpoints");

const client = new OanClient({
  registrarEndpoint: "https://registrar.example",
  rootEndpoint: "https://root.example",
  cdnEndpoint: "https://cdn.example",
  discoveryEndpoint: "https://discovery.example",
  fetchImpl: fetchStub,
});

const registered = await client.registerResource(submission);
assert(registered.status === "submitted", "registration should return submitted");

const discovery = await client.discoverResources({ resourceType: "skill", limit: 5 });
assert(discovery.candidates.length === 1, "discovery should return candidate");

const explanation = await client.explainDiscoveryQuery({ resourceType: "skill", limit: 5 });
assert(explanation.candidateCount === 1, "discovery explanation should return candidate count");

const tagSuggestions = await client.suggestCapabilityTags({ query: "mcp server" });
assert(tagSuggestions.suggestions?.[0] === "protocol.mcp", "capability suggestion mismatch");

const normalizedTags = await client.normalizeCapabilityTags([" Protocol MCP ", "security audit"]);
assert(normalizedTags.tags[0] === "protocol.mcp", "capability tag normalization mismatch");

const domainCatalog = await client.getRegistrationDomainCatalog();
assert(domainCatalog.domains?.[0]?.id === "legal.contract_law", "registration domain catalog mismatch");

const registrationSuggestions = await client.suggestRegistrationMetadata({
  resourceType: "skill",
  name: "Contract review",
  description: "Review contract risk",
});
assert(
  registrationSuggestions.capabilityTags[0]?.value === "contract-law.force-majeure",
  "registration suggestion mismatch",
);

const discoverySuggestions = await client.suggestDiscoveryQuery({
  query: "Find an MCP server for security audit",
});
assert(discoverySuggestions.protocols[0]?.value === "mcp", "discovery suggestion mismatch");

const registrarRootAuthorization = await client.getRegistrarRootAuthorization();
assert(registrarRootAuthorization.rootReachable, "registrar root authorization reachability mismatch");

const discoveryDomains = await client.getDiscoveryAuthorizedDomains();
assert(discoveryDomains.authorizedDomains?.[0] === "openagenet.local", "discovery authorized domains mismatch");

const snapshot = await client.observeLifecycle(resourceDid);
assert(snapshot.registrarAccepted, "registrar should observe record");
assert(snapshot.rootObserved, "root should observe resource");
assert(snapshot.cdnObserved, "cdn should observe package");
assert(snapshot.discoveryVisible, "discovery should observe visibility");
assert(snapshot.stage === "visible-in-discovery", "stage should normalize to visible-in-discovery");

const versionOnlySnapshot = await client.observeLifecycle(versionOnlyResourceDid);
assert(versionOnlySnapshot.rootObserved, "root version history should count as root observation");
assert(
  versionOnlySnapshot.observations?.includes("root version history exists"),
  "root version observation should be recorded",
);

const polledStages: string[] = [];
const visibleSnapshot = await client.observeLifecycleUntilVisible(resourceDid, {
  intervalMs: 5,
  timeoutMs: 100,
  onPoll: (value) => {
    polledStages.push(value.stage);
  },
});
assert(visibleSnapshot.discoveryVisible, "observeLifecycleUntilVisible should resolve visible snapshot");
assert(polledStages.length >= 1, "observeLifecycleUntilVisible should poll at least once");

const governance = new GovernanceClient({
  trustIndexerEndpoint: "https://indexer.example",
  fetchImpl: fetchStub,
});

const summary = await governance.getSummary();
assert(summary.active_registrar_count === 1, "governance summary mismatch");

const registrars = await governance.listRegistrars({ status: "active" });
assert((registrars.subjects ?? []).length === 1, "registrars query mismatch");

const discoveries = await governance.listDiscoveries({ status: "active", domain: "openagenet.local" });
assert((discoveries.subjects ?? []).length === 1, "discoveries query mismatch");

const vcIssuers = await governance.listVcIssuers({ status: "active" });
assert((vcIssuers.subjects ?? []).length === 1, "vc issuers query mismatch");

const roleCode = subjectTypeCodeForRole("discovery");
assert(roleCode === 2, "discovery subject type code mismatch");

const decision = await governance.getGovernanceDecision(roleCode!, "did:oan:INDS:test");
assert(decision.authorized, "governance decision mismatch");
assert(decision.subjectType === "discovery", "governance subject type mismatch");
assert(
  decision.interpretation?.includes("does not by itself prove current Root-issued operational authorization"),
  "governance interpretation mismatch",
);

console.log("client workflow tests passed");
