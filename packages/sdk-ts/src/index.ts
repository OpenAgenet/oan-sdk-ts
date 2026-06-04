// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  PackageInfo,
  ResourceDiscoveryCandidate,
  ResourcePackage,
  ResourceType,
  VersionMode,
} from "../../protocol-types/src/index";

export type OanVerificationCode =
  | "did_method_mismatch"
  | "resource_type_mismatch"
  | "did_subject_resource_type_mismatch"
  | "package_version_mismatch"
  | "metadata_binding_mismatch"
  | "root_claim_mismatch"
  | "lifecycle_state_not_usable"
  | "artifact_hash_missing"
  | "exact_version_mismatch";

export class OanVerificationError extends Error {
  constructor(
    public readonly code: OanVerificationCode,
    message = code,
  ) {
    super(message);
    this.name = "OanVerificationError";
  }
}

export function assertDidOan(value: string): void {
  if (!/^did:oan:[A-Z0-9]{4}:[1-9A-HJ-NP-Za-km-z]{32}$/.test(value)) {
    throw new OanVerificationError("did_method_mismatch");
  }
}

export function assertDidSubjectMatchesResourceType(resourceDid: string, resourceType: ResourceType): void {
  assertDidOan(resourceDid);
  const semanticCode = resourceDid.split(":")[2] ?? "";
  const subjectCode = semanticCode.slice(0, 2);
  const expected: Partial<Record<string, ResourceType>> = {
    AG: "agent_service",
    SK: "skill",
    MC: "mcp_server",
    TL: "tool_api",
    IN: "infrastructure_node",
    OR: "organization",
    DV: "developer",
  };
  if (expected[subjectCode] !== resourceType) {
    throw new OanVerificationError("did_subject_resource_type_mismatch");
  }
}

export function verifyResourcePackageShape(resourcePackage: ResourcePackage): void {
  assertDidOan(resourcePackage.resourceDid);
  assertDidSubjectMatchesResourceType(resourcePackage.resourceDid, resourcePackage.resourceType);
  const metadata = resourcePackage.metadata;
  if (
    metadata.resourceDid !== resourcePackage.resourceDid ||
    metadata.resourceType !== resourcePackage.resourceType ||
    metadata.subjectType !== resourcePackage.resourceType
  ) {
    throw new OanVerificationError("resource_type_mismatch");
  }
  if (
    metadata.packageVersion !== resourcePackage.packageVersion ||
    metadata.packageHash !== resourcePackage.packageHash ||
    metadata.metadataHash !== resourcePackage.metadataHash ||
    metadata.hashAlgorithm !== resourcePackage.hashAlgorithm
  ) {
    throw new OanVerificationError("metadata_binding_mismatch");
  }
  const claims = resourcePackage.rootProof?.packageClaims;
  if (
    !claims ||
    claims.resourceDid !== resourcePackage.resourceDid ||
    claims.resourceType !== resourcePackage.resourceType ||
    claims.version !== resourcePackage.packageVersion ||
    claims.didDocumentHash !== resourcePackage.didDocumentHash ||
    claims.metadataHash !== resourcePackage.metadataHash ||
    claims.packageHash !== resourcePackage.packageHash ||
    claims.hashAlgorithm !== resourcePackage.hashAlgorithm ||
    claims.lifecycleState !== resourcePackage.metadata.lifecycleState
  ) {
    throw new OanVerificationError("root_claim_mismatch");
  }
}

export function assertUsableLifecycle(resourcePackage: ResourcePackage): void {
  if (resourcePackage.metadata.lifecycleState !== "active") {
    throw new OanVerificationError("lifecycle_state_not_usable");
  }
}

export function verifyCandidateMatchesPackage(
  candidate: ResourceDiscoveryCandidate,
  resourcePackage: ResourcePackage,
  options: { versionMode?: VersionMode; version?: string; resourceType?: ResourceType } = {},
): void {
  verifyResourcePackageShape(resourcePackage);
  if (
    candidate.resourceDid !== resourcePackage.resourceDid ||
    candidate.resourceType !== resourcePackage.resourceType
  ) {
    throw new OanVerificationError("resource_type_mismatch");
  }
  if (options.resourceType && resourcePackage.resourceType !== options.resourceType) {
    throw new OanVerificationError("resource_type_mismatch");
  }
  if (options.versionMode === "exact" && options.version && resourcePackage.packageVersion !== options.version) {
    throw new OanVerificationError("exact_version_mismatch");
  }
  if (candidate.version && candidate.version !== resourcePackage.packageVersion) {
    throw new OanVerificationError("package_version_mismatch");
  }
}

export function getArtifactReferences(resourcePackage: ResourcePackage): PackageInfo {
  const packageInfo = resourcePackage.didDocument.oanMetadata?.packageInfo;
  if (!packageInfo) {
    return {};
  }
  return packageInfo;
}

export function verifyArtifactReferenceMaterial(packageInfo: PackageInfo): void {
  if ((packageInfo.manifestUrl || packageInfo.downloadUrl) && !packageInfo.packageHash) {
    throw new OanVerificationError("artifact_hash_missing");
  }
}

export function selectLatestCandidate(candidates: ResourceDiscoveryCandidate[]): ResourceDiscoveryCandidate | undefined {
  return candidates.find((candidate) => candidate.lifecycleState === "active") ?? candidates[0];
}
