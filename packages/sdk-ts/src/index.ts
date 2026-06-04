// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  DidDocument,
  PackageInfo,
  ProtocolBinding,
  ResourceDiscoveryCandidate,
  ResourcePackage,
  ResourceDescription,
  ServiceEndpoint,
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

export interface ResourceDraftOptions {
  resourceDid: string;
  resourceType: ResourceType;
  name: string;
  description?: string;
  capabilityTags?: string[];
  version?: string;
  versionScheme?: string;
  serviceEndpoint?: string;
  protocol?: string;
  serviceType?: string;
  manifestUrl?: string;
  downloadUrl?: string;
  schemaUrl?: string;
  packageHash?: string;
  metadataHash?: string;
  hashAlgorithm?: string;
  publisherDid?: string;
  controllerDid?: string;
  verificationMethodType?: string;
  publicKeyMultibase?: string;
  protocolBindings?: ProtocolBinding[];
  resourceDescription?: Partial<ResourceDescription>;
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

export function createResourceDidDocumentDraft(options: ResourceDraftOptions): DidDocument {
  assertDidSubjectMatchesResourceType(options.resourceDid, options.resourceType);
  const version = options.version ?? "1.0.0";
  const hashAlgorithm = options.hashAlgorithm ?? "sha256";
  const keyId = `${options.resourceDid}#key-1`;
  const service = buildDefaultService(options, version);
  const serviceRef = service?.id ? `#${service.id.split("#").at(-1)}` : undefined;
  const protocolBindings =
    options.protocolBindings ??
    (options.protocol
      ? [
          {
            id: `${options.resourceDid}#binding-1`,
            protocol: options.protocol,
            version,
            serviceRef,
            schemaRef: options.schemaUrl,
          },
        ]
      : []);
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/oan/v1"],
    id: options.resourceDid,
    controller: options.controllerDid ?? options.publisherDid,
    verificationMethod: [
      {
        id: keyId,
        type: options.verificationMethodType ?? "Ed25519VerificationKey2020",
        controller: options.resourceDid,
        publicKeyMultibase: options.publicKeyMultibase ?? "zReplaceWithPublicKey",
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    service: service ? [service] : [],
    oanMetadata: {
      subjectType: options.resourceType,
      resourceType: options.resourceType,
      publisherDid: options.publisherDid,
      controllerDid: options.controllerDid,
      resourceDescription: {
        name: options.name,
        description: options.description,
        capabilityTags: options.capabilityTags,
        version,
        ...options.resourceDescription,
      },
      capabilityTags: options.capabilityTags,
      protocolBindings,
      packageInfo: {
        manifestUrl: options.manifestUrl,
        downloadUrl: options.downloadUrl,
        schemaUrl: options.schemaUrl,
        packageHash: options.packageHash,
        metadataHash: options.metadataHash,
        hashAlgorithm,
        version,
        versionScheme: options.versionScheme ?? "semver",
      },
    },
  };
}

export function createAgentServiceDraft(options: Omit<ResourceDraftOptions, "resourceType">): DidDocument {
  return createResourceDidDocumentDraft({
    protocol: "https",
    serviceType: "OANAgentService",
    ...options,
    resourceType: "agent_service",
  });
}

export function createSkillDraft(options: Omit<ResourceDraftOptions, "resourceType">): DidDocument {
  return createResourceDidDocumentDraft({
    serviceType: "OANSkillManifest",
    manifestUrl: options.manifestUrl ?? options.serviceEndpoint,
    ...options,
    resourceType: "skill",
  });
}

export function createMcpServerDraft(options: Omit<ResourceDraftOptions, "resourceType">): DidDocument {
  return createResourceDidDocumentDraft({
    protocol: "mcp",
    serviceType: "OANMCPServer",
    ...options,
    resourceType: "mcp_server",
  });
}

export function createToolApiDraft(options: Omit<ResourceDraftOptions, "resourceType">): DidDocument {
  return createResourceDidDocumentDraft({
    protocol: "https",
    serviceType: "OANToolAPI",
    schemaUrl: options.schemaUrl ?? options.serviceEndpoint,
    ...options,
    resourceType: "tool_api",
  });
}

function buildDefaultService(options: ResourceDraftOptions, version: string): ServiceEndpoint | undefined {
  const endpoint = options.serviceEndpoint ?? options.manifestUrl ?? options.schemaUrl;
  if (!endpoint) return undefined;
  const fragment =
    options.resourceType === "skill"
      ? "manifest"
      : options.resourceType === "mcp_server"
        ? "mcp"
        : options.resourceType === "tool_api"
          ? "api"
          : "service";
  return {
    id: `${options.resourceDid}#${fragment}`,
    type: options.serviceType ?? defaultServiceType(options.resourceType),
    serviceEndpoint: endpoint,
    protocol: options.protocol,
    version,
  };
}

function defaultServiceType(resourceType: ResourceType): string {
  switch (resourceType) {
    case "agent_service":
      return "OANAgentService";
    case "skill":
      return "OANSkillManifest";
    case "mcp_server":
      return "OANMCPServer";
    case "tool_api":
      return "OANToolAPI";
    default:
      return "OANResourcePackage";
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
