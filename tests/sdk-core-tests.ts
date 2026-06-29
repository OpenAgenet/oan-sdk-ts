// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import {
  assertDidOan,
  assertUsableLifecycle,
  buildDiscoveryQuery,
  createAgentIdentity,
  createAgentServiceDraft,
  createDefaultSubjectIdentity,
  createEmptyIdentityStoreSnapshot,
  createMcpServerDraft,
  createRegistrationSubmissionFromIdentity,
  createSkillDraft,
  createToolApiDraft,
  exportIdentityBundle,
  getArtifactReferences,
  inferResourceTypeFromDidOan,
  importIdentityBundle,
  normalizeDidDocumentForOan,
  normalizeDidOan,
  normalizeRegistrationSubmissionForOan,
  OanVerificationError,
  summarizeDiscoveryCandidate,
  summarizeLifecycleSnapshot,
  summarizeTrustFromPackage,
  upsertIdentityRecord,
  validateDidDocumentDraft,
  verifyArtifactReferenceMaterial,
  verifyCandidateMatchesPackage,
  hasDidOanSemanticConflict,
  verifyResourcePackageShape,
} from "../packages/sdk-ts/src/index.js";
import type { ResourceDiscoveryCandidate, ResourcePackage } from "../packages/protocol-types/src/index.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function expectNoThrow(fn: () => void): void {
  fn();
}

function expectVerificationCode(fn: () => void, code: string): void {
  try {
    fn();
  } catch (error) {
    if (error instanceof OanVerificationError && error.code === code) {
      return;
    }
    throw error;
  }
  throw new Error(`expected verification error: ${code}`);
}

function samplePackage(): ResourcePackage {
  const resourceDid = "did:oan:AGBM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz";
  return {
    packageVersion: "1.0.0",
    resourceDid,
    resourceType: "agent_service",
    didDocument: {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/oan/v1"],
      id: resourceDid,
      service: [
        {
          id: `${resourceDid}#service`,
          type: "AgentService",
          serviceEndpoint: "https://example.org/agent/invoke",
          protocol: "https",
        },
      ],
      oanMetadata: {
        subjectType: "agent_service",
        resourceType: "agent_service",
        resourceDescription: {
          name: "Fixture Agent",
          description: "Test agent service",
          capabilityTags: ["test.agent"],
        },
        authorizedDomains: ["legal"],
        packageInfo: {
          manifestUrl: "https://example.org/agent/manifest.json",
          packageHash: "sha256:package",
          hashAlgorithm: "sha256",
          version: "1.0.0",
        },
      },
    },
    didDocumentHash: "sha256:did",
    metadataHash: "sha256:metadata",
    packageHash: "sha256:package",
    hashAlgorithm: "sha256",
    metadata: {
      resourceDid,
      resourceType: "agent_service",
      subjectType: "agent_service",
      subjectDid: resourceDid,
      name: "Fixture Agent",
      description: "Test agent service",
      capabilityTags: ["test.agent"],
      authorizedDomains: ["legal"],
      protocolBindings: [],
      services: [],
      lifecycleState: "active",
      packageVersion: "1.0.0",
      packageHash: "sha256:package",
      metadataHash: "sha256:metadata",
      hashAlgorithm: "sha256",
      updatedAt: "2026-06-04T00:00:00Z",
    },
    rootProof: {
      rootDid: "did:oan:INRT:8YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
      packageClaims: {
        resourceDid,
        resourceType: "agent_service",
        version: "1.0.0",
        didDocumentHash: "sha256:did",
        metadataHash: "sha256:metadata",
        packageHash: "sha256:package",
        hashAlgorithm: "sha256",
        lifecycleState: "active",
        authorizedDomains: ["legal"],
      },
    },
    createdAt: "2026-06-04T00:00:00Z",
  };
}

const pkg = samplePackage();
expectNoThrow(() => assertDidOan(pkg.resourceDid));
assert(normalizeDidOan("did:oan:agbm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz") === pkg.resourceDid, "did normalization mismatch");
assert(inferResourceTypeFromDidOan(pkg.resourceDid) === "agent_service", "inferred resource type mismatch");
expectNoThrow(() => verifyResourcePackageShape(pkg));
expectNoThrow(() => assertUsableLifecycle(pkg));

const candidate: ResourceDiscoveryCandidate = {
  resourceDid: pkg.resourceDid,
  resourceType: "agent_service",
  score: 1,
  version: "1.0.0",
  lifecycleState: "active",
};
expectNoThrow(() =>
  verifyCandidateMatchesPackage(candidate, pkg, { versionMode: "exact", version: "1.0.0" }),
);

expectVerificationCode(
  () => verifyCandidateMatchesPackage(candidate, pkg, { versionMode: "exact", version: "2.0.0" }),
  "exact_version_mismatch",
);

const tampered = samplePackage();
tampered.rootProof.packageClaims!.metadataHash = "sha256:evil";
expectVerificationCode(
  () => verifyResourcePackageShape(tampered),
  "root_claim_mismatch",
);

const tamperedDomains = samplePackage();
tamperedDomains.rootProof.packageClaims!.authorizedDomains = ["finance"];
expectVerificationCode(
  () => verifyResourcePackageShape(tamperedDomains),
  "root_claim_mismatch",
);

const wrongSubject = samplePackage();
wrongSubject.resourceType = "skill";
wrongSubject.metadata.resourceType = "skill";
wrongSubject.metadata.subjectType = "skill";
wrongSubject.rootProof.packageClaims!.resourceType = "skill";
expectVerificationCode(
  () => verifyResourcePackageShape(wrongSubject),
  "did_subject_resource_type_mismatch",
);
assert(
  hasDidOanSemanticConflict(pkg.resourceDid, { subjectType: "skill", resourceType: "skill" }),
  "semantic conflict should be detected",
);

const packageInfo = getArtifactReferences(pkg);
assert(packageInfo.manifestUrl === "https://example.org/agent/manifest.json", "manifest url mismatch");
expectNoThrow(() => verifyArtifactReferenceMaterial(packageInfo));
expectVerificationCode(
  () => verifyArtifactReferenceMaterial({ manifestUrl: "https://example.org/skill.json" }),
  "artifact_hash_missing",
);

const skillDraft = createSkillDraft({
  resourceDid: "did:oan:SKDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Contract Review Skill",
  description: "Review contracts and flag legal risks.",
  capabilityTags: ["legal.contract-review"],
  authorizedDomains: ["legal"],
  manifestUrl: "https://example.org/skills/contract-review.json",
  packageHash: "sha256:skill-package",
});
assert(skillDraft.oanMetadata?.resourceType === "skill", "skill draft resource type mismatch");
assert(skillDraft.oanMetadata?.authorizedDomains?.[0] === "legal", "skill draft authorized domain mismatch");
assert(skillDraft.service?.[0]?.type === "OANSkillManifest", "skill draft service type mismatch");
assert(
  skillDraft.oanMetadata?.packageInfo?.manifestUrl === "https://example.org/skills/contract-review.json",
  "skill manifest url mismatch",
);

const portableSkill = createSkillDraft({
  resourceDid: "did:oan:SKDM:8YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Portable Skill",
  packageHash: "sha256:portable-skill",
});
assert((portableSkill.service ?? []).length === 0, "portable skill should not require a service endpoint");
const portableSkillReport = validateDidDocumentDraft(portableSkill, {
  resourceDid: portableSkill.id,
  resourceType: "skill",
});
assert(portableSkillReport.ok, "portable skill draft should validate cleanly");

const mcpDraft = createMcpServerDraft({
  resourceDid: "did:oan:MCDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Legal MCP Server",
  serviceEndpoint: "https://example.org/mcp",
});
assert(mcpDraft.service?.[0]?.type === "OANMCPServer", "mcp draft service type mismatch");

const apiDraft = createToolApiDraft({
  resourceDid: "did:oan:TLDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Risk API",
  serviceEndpoint: "https://example.org/openapi.json",
});
assert(apiDraft.service?.[0]?.type === "OANToolAPI", "tool api draft service type mismatch");

const agentDraft = createAgentServiceDraft({
  resourceDid: "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Risk Agent",
  serviceEndpoint: "https://example.org/agent/invoke",
});
assert(agentDraft.oanMetadata?.resourceType === "agent_service", "agent draft resource type mismatch");

const normalizedSubmission = normalizeRegistrationSubmissionForOan({
  resourceDid: "did:oan:agdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  resourceType: "agent_service",
  didDocument: {
    id: "did:oan:agdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    controller: "did:oan:agdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    verificationMethod: [
      {
        id: "did:oan:agdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:oan:agdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
      },
    ],
    oanMetadata: {
      subjectType: "agent_service",
      resourceType: "agent_service",
      controllerDid: "did:oan:agdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    },
  },
  packageVersion: "1.0.0",
  metadataHash: "sha256:metadata",
  packageHash: "sha256:package",
  hashAlgorithm: "sha256",
});
assert(
  normalizedSubmission.resourceDid === "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  "submission did normalization mismatch",
);
assert(
  normalizedSubmission.didDocument.verificationMethod?.[0]?.controller ===
    "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  "verification method controller normalization mismatch",
);

const normalizedDocument = normalizeDidDocumentForOan({
  id: "did:oan:skdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  service: [
    {
      id: "did:oan:skdm:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#manifest",
      type: "OANSkillManifest",
      serviceEndpoint: "https://example.org/skill.json",
    },
  ],
  oanMetadata: {
    subjectType: "skill",
    resourceType: "skill",
  },
});
assert(normalizedDocument.id === "did:oan:SKDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz", "document did normalization mismatch");
assert(
  normalizedDocument.service?.[0]?.id === "did:oan:SKDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#manifest",
  "service id normalization mismatch",
);

expectVerificationCode(
  () =>
    createSkillDraft({
      resourceDid: "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
      name: "Wrong Skill",
    }),
  "did_subject_resource_type_mismatch",
);

const invalidReport = validateDidDocumentDraft({
  id: "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  service: [{ id: "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#svc", type: "Svc", serviceEndpoint: "https://x" }],
  oanMetadata: {
    subjectType: "agent_service",
    resourceType: "agent_service",
    protocolBindings: [{ id: "b1", protocol: "https", serviceRef: "#missing" }],
    packageInfo: { manifestUrl: "https://example.org/agent.json" },
  },
}, {
  resourceDid: "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  resourceType: "agent_service",
});
assert(!invalidReport.ok, "invalid draft report should fail");
assert(invalidReport.issues.length >= 2, "invalid draft report should contain multiple issues");

const builtQuery = buildDiscoveryQuery({
  query: "  legal skill  ",
  capabilityTags: [" legal.contract-review ", ""],
  resourceType: "skill",
  limit: 10,
});
assert(builtQuery.query === "legal skill", "query should be trimmed");
assert(builtQuery.capabilityTags?.[0] === "legal.contract-review", "capability tag should be normalized");

const trustSummary = summarizeTrustFromPackage(pkg);
assert(trustSummary.level === "verified", "package trust summary should be verified");
assert(trustSummary.checks.includes("package binding verified"), "trust summary should include binding verification");

const discoverySummary = summarizeDiscoveryCandidate(candidate, pkg);
assert(discoverySummary.resourceDid === pkg.resourceDid, "discovery summary did mismatch");
assert(discoverySummary.authorizedDomains[0] === "legal", "discovery summary authorized domain mismatch");
assert(discoverySummary.primaryEndpoint === "https://example.org/agent/invoke", "discovery summary endpoint mismatch");
assert(discoverySummary.trust.level === "verified", "discovery summary trust level mismatch");

const lifecycleSummary = summarizeLifecycleSnapshot({
  stage: "published-to-cdn",
  registrarAccepted: true,
  rootObserved: true,
  cdnObserved: true,
  discoveryVisible: false,
  observations: ["root package exists"],
});
assert(lifecycleSummary.level === "warning", "lifecycle summary should be warning before discovery visibility");
assert(lifecycleSummary.warnings.some((item) => item.includes("published-to-cdn")), "lifecycle warning should include stage");

const subjectIdentity = await createDefaultSubjectIdentity("SDK Test Subject");
const agentIdentity = await createAgentIdentity("SDK Test Skill", "skill", subjectIdentity.did, {
  description: "Generated identity-backed skill",
  capabilityTags: ["sdk.identity"],
  authorizedDomains: ["legal"],
  manifestUrl: "https://example.org/skills/sdk-test.json",
});
const identitySubmission = createRegistrationSubmissionFromIdentity(agentIdentity, {
  manifestUrl: "https://example.org/skills/sdk-test.json",
  packageHash: "sha256:sdk-test-package",
  metadataHash: "sha256:sdk-test-metadata",
});
assert(identitySubmission.resourceDid === agentIdentity.did, "identity-backed submission did mismatch");
assert(
  identitySubmission.didDocument.oanMetadata?.authorizedDomains?.[0] === "legal",
  "identity-backed submission authorized domain mismatch",
);
assert(identitySubmission.didDocument.verificationMethod?.[0]?.publicKeyJwk, "identity-backed draft should carry publicKeyJwk");

let identityStore = createEmptyIdentityStoreSnapshot();
identityStore = upsertIdentityRecord(identityStore, subjectIdentity);
identityStore = upsertIdentityRecord(identityStore, agentIdentity);
const exportedBundle = exportIdentityBundle(identityStore);
const importedBundle = importIdentityBundle(exportedBundle);
assert(importedBundle.subjects.length === 1, "imported bundle subject count mismatch");
assert(importedBundle.agents.length === 1, "imported bundle agent count mismatch");

console.log("sdk core tests passed");
