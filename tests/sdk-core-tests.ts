// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import {
  assertDidOan,
  assertUsableLifecycle,
  createAgentServiceDraft,
  createMcpServerDraft,
  createSkillDraft,
  createToolApiDraft,
  getArtifactReferences,
  OanVerificationError,
  verifyArtifactReferenceMaterial,
  verifyCandidateMatchesPackage,
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
      },
    },
    createdAt: "2026-06-04T00:00:00Z",
  };
}

const pkg = samplePackage();
expectNoThrow(() => assertDidOan(pkg.resourceDid));
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

const wrongSubject = samplePackage();
wrongSubject.resourceType = "skill";
wrongSubject.metadata.resourceType = "skill";
wrongSubject.metadata.subjectType = "skill";
wrongSubject.rootProof.packageClaims!.resourceType = "skill";
expectVerificationCode(
  () => verifyResourcePackageShape(wrongSubject),
  "did_subject_resource_type_mismatch",
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
  manifestUrl: "https://example.org/skills/contract-review.json",
  packageHash: "sha256:skill-package",
});
assert(skillDraft.oanMetadata?.resourceType === "skill", "skill draft resource type mismatch");
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

expectVerificationCode(
  () =>
    createSkillDraft({
      resourceDid: "did:oan:AGDM:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
      name: "Wrong Skill",
    }),
  "did_subject_resource_type_mismatch",
);

console.log("sdk core tests passed");
