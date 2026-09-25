// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import {
  assertDidOan,
  assertUsableLifecycle,
  buildRegistrationCredentialExternalIdentifiers,
  buildDiscoveryQuery,
  createAgentIdentity,
  createAgentServiceDraft,
  attachControllerAuthorizationProof,
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
  canonicalJson,
  createMinimalVerifiablePresentation,
  hashRegistrationPackageBinding,
  hashDidDocumentWithProof,
  didDocumentSignatureInput,
  finalizeRegistrationSubmissionWithProof,
  getRegistrationExternalIdentifierIds,
  parseDidOan,
  parseMinimalVerifiablePresentation,
  signDidDocumentProof,
  verifyResourcePackageShape,
} from "../packages/sdk-ts/src/index.js";
import type { ResourceDiscoveryCandidate, ResourcePackage } from "../packages/protocol-types/src/index.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

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

function expectThrow(fn: () => void, message: string): void {
  try {
    fn();
  } catch {
    return;
  }
  throw new Error(message);
}

function samplePackage(): ResourcePackage {
  const resourceDid = "did:oan:K7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz";
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
      rootDid: "did:oan:P9aBc:8YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
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
assert(normalizeDidOan(pkg.resourceDid) === pkg.resourceDid, "did normalization mismatch");
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

assert(!hasDidOanSemanticConflict(pkg.resourceDid, { subjectType: "skill", resourceType: "skill" }), "DID must not encode resource type");

const profileV2Vector = JSON.parse(
  readFileSync(
    resolve("../oan-protocol-common/test-fixtures/did-oan-profile-v2-cross-language.json"),
    "utf8",
  ),
) as {
  did: { value: string; routingCode: string; suffixCode: string };
  didCases: Array<{
    id: string;
    did: string;
    expected: "valid" | "invalid";
    routingCode?: string;
    suffixCode?: string;
  }>;
  canonicalJsonCase: { value: unknown; canonical: string };
  documentWithoutProof: Record<string, unknown>;
  proof: Record<string, unknown>;
  signatureInputCanonical: string;
  completeDocumentHashSha256: string;
  proofMutationHashSha256: string;
  externalIdentifierMutationHashSha256: string;
};
assertDidOan(profileV2Vector.did.value);
const parsedProfileDid = parseDidOan(profileV2Vector.did.value);
assert(parsedProfileDid.routingCode === profileV2Vector.did.routingCode, "parseDidOan routingCode mismatch");
assert(parsedProfileDid.suffixCode === profileV2Vector.did.suffixCode, "parseDidOan suffixCode mismatch");
assert(parsedProfileDid.registrarCode === parsedProfileDid.routingCode, "legacy registrarCode alias mismatch");
assert(parsedProfileDid.resourceSuffix === parsedProfileDid.suffixCode, "legacy resourceSuffix alias mismatch");
const [, , vectorRoutingCode, vectorSuffixCode] = profileV2Vector.did.value.split(":");
assert(vectorRoutingCode === profileV2Vector.did.routingCode, "routing-code parse mismatch");
assert(vectorSuffixCode === profileV2Vector.did.suffixCode, "suffix-code parse mismatch");
const normalizedDidUrlDocument = normalizeRegistrationSubmissionForOan({
  resourceDid: profileV2Vector.did.value,
  resourceType: "skill",
  didDocument: {
    id: profileV2Vector.did.value,
    controller: `${profileV2Vector.did.value}#controller`,
    verificationMethod: [
      {
        id: `${profileV2Vector.did.value}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: `${profileV2Vector.did.value}#controller`,
        publicKeyMultibase: "zReplaceWithPublicKey",
      },
    ],
    authentication: [`${profileV2Vector.did.value}#key-1`],
    assertionMethod: [`${profileV2Vector.did.value}#key-1`],
    oanMetadata: {
      subjectType: "skill",
      resourceType: "skill",
      controllerDid: `${profileV2Vector.did.value}#controller`,
    },
  },
  packageVersion: "1.0.0",
  metadataHash: "sha256:metadata",
  packageHash: "sha256:package",
  hashAlgorithm: "sha256",
});
assert(
  normalizedDidUrlDocument.didDocument.controller === `${profileV2Vector.did.value}#controller`,
  "DID URL controller reference should retain fragment",
);
assert(
  normalizedDidUrlDocument.didDocument.verificationMethod?.[0]?.controller ===
    `${profileV2Vector.did.value}#controller`,
  "verificationMethod controller DID URL should retain fragment",
);
for (const didCase of profileV2Vector.didCases) {
  if (didCase.expected === "valid") {
    assertDidOan(didCase.did);
    const [, , routingCode, suffixCode] = didCase.did.split(":");
    assert(routingCode === didCase.routingCode, `${didCase.id} routing-code mismatch`);
    assert(suffixCode === didCase.suffixCode, `${didCase.id} suffix-code mismatch`);
  } else {
    expectThrow(() => assertDidOan(didCase.did), `${didCase.id} should be rejected`);
  }
}
assert(canonicalJson(profileV2Vector.canonicalJsonCase.value) === profileV2Vector.canonicalJsonCase.canonical, "canonical JSON vector mismatch");
assert(
  new TextDecoder().decode(didDocumentSignatureInput(profileV2Vector.documentWithoutProof as any)) ===
    profileV2Vector.signatureInputCanonical,
  "DID document signature input vector mismatch",
);
const completeVectorDocument = {
  ...profileV2Vector.documentWithoutProof,
  proof: profileV2Vector.proof,
};
assert(
  new TextDecoder().decode(didDocumentSignatureInput(completeVectorDocument as any)) ===
    profileV2Vector.signatureInputCanonical,
  "DID document proof must be excluded from signature input",
);
assert(
  await hashDidDocumentWithProof(completeVectorDocument as any) === profileV2Vector.completeDocumentHashSha256,
  "DID document final hash vector mismatch",
);
assert(
  await hashDidDocumentWithProof({
    ...completeVectorDocument,
    proof: { ...profileV2Vector.proof, proofValue: "fixture-proof-value-mutated" },
  } as any) === profileV2Vector.proofMutationHashSha256,
  "proof mutation hash vector mismatch",
);
const externalIdentifierMutationDocument = structuredClone(completeVectorDocument) as any;
externalIdentifierMutationDocument.oanMetadata.externalIdentifiers[0].id = "urn:example:skill:changed";
assert(
  await hashDidDocumentWithProof(externalIdentifierMutationDocument) === profileV2Vector.externalIdentifierMutationHashSha256,
  "external identifier mutation hash vector mismatch",
);

const packageInfo = getArtifactReferences(pkg);
assert(packageInfo.manifestUrl === "https://example.org/agent/manifest.json", "manifest url mismatch");
expectNoThrow(() => verifyArtifactReferenceMaterial(packageInfo));
expectVerificationCode(
  () => verifyArtifactReferenceMaterial({ manifestUrl: "https://example.org/skill.json" }),
  "artifact_hash_missing",
);

const skillDraft = createSkillDraft({
  resourceDid: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
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
  resourceDid: "did:oan:K7mQ9:8YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
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
  resourceDid: "did:oan:K7mQ9:9YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Legal MCP Server",
  serviceEndpoint: "https://example.org/mcp",
});
assert(mcpDraft.service?.[0]?.type === "OANMCPServer", "mcp draft service type mismatch");

const apiDraft = createToolApiDraft({
  resourceDid: "did:oan:K7mQ9:AYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Risk API",
  serviceEndpoint: "https://example.org/openapi.json",
});
assert(apiDraft.service?.[0]?.type === "OANToolAPI", "tool api draft service type mismatch");

const agentDraft = createAgentServiceDraft({
  resourceDid: "did:oan:K7mQ9:BYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "Risk Agent",
  serviceEndpoint: "https://example.org/agent/invoke",
});
assert(agentDraft.oanMetadata?.resourceType === "agent_service", "agent draft resource type mismatch");
assert(agentDraft.controller === agentDraft.id, "agent draft controller should default to subject DID");

const normalizedSubmission = normalizeRegistrationSubmissionForOan({
  resourceDid: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  resourceType: "agent_service",
  didDocument: {
    id: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    controller: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    verificationMethod: [
      {
        id: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#key-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
      },
    ],
    oanMetadata: {
      subjectType: "agent_service",
      resourceType: "agent_service",
      controllerDid: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    },
  },
  packageVersion: "1.0.0",
  metadataHash: "sha256:metadata",
  packageHash: "sha256:package",
  hashAlgorithm: "sha256",
});
assert(
  normalizedSubmission.resourceDid === "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  "submission did normalization mismatch",
);
assert(
  normalizedSubmission.didDocument.verificationMethod?.[0]?.controller ===
    "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  "verification method controller normalization mismatch",
);

const normalizedDocument = normalizeDidDocumentForOan({
  id: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  service: [
    {
      id: "did:oan:k7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#manifest",
      type: "OANSkillManifest",
      serviceEndpoint: "https://example.org/skill.json",
    },
  ],
  oanMetadata: {
    subjectType: "skill",
    resourceType: "skill",
  },
});
assert(normalizedDocument.id === "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz", "document did normalization mismatch");
assert(
  normalizedDocument.service?.[0]?.id === "did:oan:k7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#manifest",
  "service id normalization mismatch",
);

expectNoThrow(() =>
  createSkillDraft({
    resourceDid: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
    name: "Skill with registrar-routed DID",
  }),
);

const invalidReport = validateDidDocumentDraft({
  id: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  service: [{ id: "did:oan:k7mQ9:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz#svc", type: "Svc", serviceEndpoint: "https://x" }],
  oanMetadata: {
    subjectType: "agent_service",
    resourceType: "agent_service",
    protocolBindings: [{ id: "b1", protocol: "https", serviceRef: "#missing" }],
    packageInfo: { manifestUrl: "https://example.org/agent.json" },
  },
}, {
  resourceDid: "did:oan:k7mQ9:CYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
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
const queryWithoutResourceType = buildDiscoveryQuery({
  query: "legal skill",
  resourceType: "" as any,
});
assert(
  queryWithoutResourceType.resourceType === undefined,
  "empty resource type should be omitted",
);

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
const signedDocument = await signDidDocumentProof(subjectIdentity.didDocument, subjectIdentity);
assert(signedDocument.proof?.hashAlgorithm === "sha256", "DID proof hash algorithm mismatch");
assert(new TextDecoder().decode(didDocumentSignatureInput(signedDocument)) === new TextDecoder().decode(didDocumentSignatureInput({ ...signedDocument, proof: undefined })), "DID signature input mismatch");
const documentHash = await hashDidDocumentWithProof(signedDocument);
assert(/^[0-9a-f]{64}$/.test(documentHash), "DID document hash format mismatch");
const tamperedSignedDocument = {
  ...signedDocument,
  oanMetadata: {
    ...(signedDocument.oanMetadata ?? {
      subjectType: "developer",
      resourceType: "developer",
    }),
    lifecycleState: "tampered",
  },
};
assert(
  await hashDidDocumentWithProof(tamperedSignedDocument) !== documentHash,
  "DID document hash should change after post-proof field mutation",
);
const externalIdDocument = createSkillDraft({
  resourceDid: "did:oan:K7mQ9:DYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "External ID Skill",
  externalIdentifiers: [{ id: "urn:example:skill", resolutionServiceEndpoint: "https://resolver.example/skill" }],
});
assert(getRegistrationExternalIdentifierIds(externalIdDocument)[0] === "urn:example:skill", "external identifier id missing");
assert(
  JSON.stringify(buildRegistrationCredentialExternalIdentifiers(externalIdDocument)) ===
    JSON.stringify([{ id: "urn:example:skill" }]),
  "registration credential external identifiers must omit resolution endpoints",
);
const noExternalIdDocument = createSkillDraft({
  resourceDid: "did:oan:K7mQ9:EYpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  name: "No External ID Skill",
});
assert(
  getRegistrationExternalIdentifierIds(noExternalIdDocument).length === 0,
  "external identifiers should remain optional",
);
const presentation = createMinimalVerifiablePresentation({
  holder: subjectIdentity.did,
  verifiableCredential: [
    {
      type: ["VerifiableCredential", "OANRegistrationCredential"],
      credentialSubject: { id: agentIdentity.did },
    },
  ],
});
assert(parseMinimalVerifiablePresentation(presentation).holder === subjectIdentity.did, "VP holder mismatch");
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
assert(
  identitySubmission.didDocument.verificationMethod?.[0]?.cryptoSuite === "ed25519-sha256",
  "identity-backed draft should carry explicit cryptoSuite",
);
identitySubmission.didDocumentHash = "sha256:sdk-test-did-document";
await attachControllerAuthorizationProof(identitySubmission, {
  controllerIdentity: subjectIdentity,
  registrarDid: "did:oan:P9aBc:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
});
const controllerProof = identitySubmission.controllerAuthorizationProof;
assert(controllerProof, "controllerAuthorizationProof should be attached");
assert(
  controllerProof.challenge.controllerDid === subjectIdentity.did,
  "controller proof should bind subject identity as controller",
);
assert(
  controllerProof.challenge.resourceDid === agentIdentity.did,
  "controller proof should bind resource DID",
);
assert(
  !JSON.stringify(identitySubmission).includes("privateKeyJwk"),
  "controller proof submission should not contain privateKeyJwk",
);
assert(
  controllerProof.controllerDidDocument.verificationMethod?.[0]?.cryptoSuite === "ed25519-sha256",
  "controller DID document should declare the proof crypto suite",
);
const verifyKey = await globalThis.crypto.subtle.importKey(
  "jwk",
  subjectIdentity.publicKeyJwk as JsonWebKey,
  { name: "Ed25519" },
  false,
  ["verify"],
);
const signature = base64UrlToBytes(controllerProof.proof.proofValue);
const verified = await globalThis.crypto.subtle.verify(
  { name: "Ed25519" },
  verifyKey,
  signature.buffer as ArrayBuffer,
  new TextEncoder().encode(testCanonicalJson(controllerProof.challenge)),
);
assert(verified, "controllerAuthorizationProof signature should verify");
const finalizedIdentitySubmission = await finalizeRegistrationSubmissionWithProof(
  createRegistrationSubmissionFromIdentity(agentIdentity, {
    manifestUrl: "https://example.org/skills/sdk-test.json",
    packageHash: "sha256:sdk-test-package",
    metadataHash: "sha256:sdk-test-metadata",
  }),
  {
    controllerIdentity: subjectIdentity,
    registrarDid: "did:oan:P9aBc:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  },
);
assert(
  /^sha256:[0-9a-f]{64}$/.test(finalizedIdentitySubmission.didDocumentHash ?? ""),
  "finalized submission didDocumentHash should keep hash algorithm prefix",
);
assert(
  finalizedIdentitySubmission.controllerAuthorizationProof?.challenge.didDocumentHash ===
    finalizedIdentitySubmission.didDocumentHash,
  "controller authorization challenge should bind prefixed didDocumentHash",
);
assert(
  finalizedIdentitySubmission.packageHash ===
    `sha256:${await hashRegistrationPackageBinding(finalizedIdentitySubmission)}`,
  "finalized submission packageHash should bind final didDocumentHash",
);
const mismatchedSubmission = createRegistrationSubmissionFromIdentity(agentIdentity, {
  manifestUrl: "https://example.org/skills/sdk-test.json",
  packageHash: "sha256:sdk-test-package",
  metadataHash: "sha256:sdk-test-metadata",
});
mismatchedSubmission.didDocumentHash = "sha256:sdk-test-did-document";
mismatchedSubmission.didDocument.oanMetadata = {
  ...(mismatchedSubmission.didDocument.oanMetadata ?? {
    subjectType: "skill",
    resourceType: "skill",
  }),
  controllerDid: "did:oan:QwErT:11111111111111111111111111111111",
};
let mismatchRejected = false;
try {
  await attachControllerAuthorizationProof(mismatchedSubmission, {
    controllerIdentity: subjectIdentity,
    registrarDid: "did:oan:P9aBc:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz",
  });
} catch (error) {
  mismatchRejected = error instanceof Error && error.message === "controller_identity_mismatch";
}
assert(mismatchRejected, "controller DID mismatch should be rejected before signing");

let identityStore = createEmptyIdentityStoreSnapshot();
identityStore = upsertIdentityRecord(identityStore, subjectIdentity);
identityStore = upsertIdentityRecord(identityStore, agentIdentity);
const exportedBundle = exportIdentityBundle(identityStore);
const importedBundle = importIdentityBundle(exportedBundle);
assert(importedBundle.subjects.length === 1, "imported bundle subject count mismatch");
assert(importedBundle.agents.length === 1, "imported bundle agent count mismatch");

console.log("sdk core tests passed");

function testCanonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(testCanonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${testCanonicalJson(entryValue)}`).join(",")}}`;
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(globalThis.atob(base64), (char) => char.charCodeAt(0));
}
