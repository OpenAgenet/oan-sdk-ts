// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  DidDocument,
  PackageInfo,
  ProtocolBinding,
  ResourceDiscoveryQuery,
  ResourceDiscoveryCandidate,
  ResourcePackage,
  ResourceDescription,
  ServiceEndpoint,
  ResourceType,
  VersionMode,
} from "../../protocol-types/src/index.js";
import {
  hasDidOanSemanticConflict,
  inferResourceTypeFromDidOan,
  normalizeDidOan,
  OAN_DID_CONTEXT,
} from "./did-oan.js";

export type OanVerificationCode =
  | "did_method_mismatch"
  | "resource_type_mismatch"
  | "did_subject_resource_type_mismatch"
  | "unsupported_resource_type"
  | "package_version_mismatch"
  | "metadata_binding_mismatch"
  | "root_claim_mismatch"
  | "lifecycle_state_not_usable"
  | "artifact_hash_missing"
  | "exact_version_mismatch"
  | "service_binding_mismatch"
  | "hash_format_mismatch";

export interface OanValidationIssue {
  code: OanVerificationCode;
  message: string;
  field?: string;
}

export interface OanDraftValidationReport {
  ok: boolean;
  resourceDid?: string;
  resourceType?: ResourceType;
  issues: OanValidationIssue[];
}

export interface OanTrustSummary {
  level: "verified" | "warning" | "unverified";
  checks: string[];
  warnings: string[];
}

export interface OanDiscoveryResultSummary {
  resourceDid: string;
  resourceType: ResourceType;
  version?: string;
  lifecycleState?: string;
  title?: string;
  description?: string;
  capabilityTags: string[];
  authorizedDomains: string[];
  protocols: string[];
  primaryEndpoint?: string;
  trust: OanTrustSummary;
}

export class OanVerificationError extends Error {
  constructor(
    public readonly code: OanVerificationCode,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "OanVerificationError";
  }
}

export interface ResourceDraftOptions {
  resourceDid: string;
  resourceType: ResourceType;
  name: string;
  description?: string;
  capabilityTags?: string[];
  authorizedDomains?: string[];
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
  normalizeDidOan(value);
}

export function assertDidSubjectMatchesResourceType(resourceDid: string, resourceType: ResourceType): void {
  assertDidOan(resourceDid);
  if (inferResourceTypeFromDidOan(resourceDid) !== resourceType) {
    throw new OanVerificationError("did_subject_resource_type_mismatch");
  }
}

export function assertSupportedInitialResourceType(resourceType: ResourceType): void {
  if (!["agent_service", "skill", "mcp_server", "tool_api"].includes(resourceType)) {
    throw new OanVerificationError("unsupported_resource_type");
  }
}

export function createResourceDidDocumentDraft(options: ResourceDraftOptions): DidDocument {
  assertDidSubjectMatchesResourceType(options.resourceDid, options.resourceType);
  const normalizedDid = normalizeDidOan(options.resourceDid);
  const version = options.version ?? "1.0.0";
  const hashAlgorithm = options.hashAlgorithm ?? "sha256";
  const packageHash =
    options.packageHash ??
    (options.resourceType === "skill" && (options.manifestUrl || options.downloadUrl)
      ? "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      : undefined);
  const keyId = `${normalizedDid}#key-1`;
  const normalizedOptions = { ...options, resourceDid: normalizedDid };
  const service = buildDefaultService(normalizedOptions, version);
  const serviceRef = service?.id ? `#${service.id.split("#").at(-1)}` : undefined;
  const protocolBindings =
    options.protocolBindings ??
    (options.protocol
      ? [
          {
            id: `${normalizedDid}#binding-1`,
            protocol: options.protocol,
            version,
            serviceRef,
            schemaRef: options.schemaUrl,
          },
        ]
      : []);
  return {
    "@context": [...OAN_DID_CONTEXT],
    id: normalizedDid,
    controller: options.controllerDid ?? options.publisherDid,
    verificationMethod: [
      {
        id: keyId,
        type: options.verificationMethodType ?? "Ed25519VerificationKey2020",
        controller: normalizedDid,
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
      authorizedDomains: options.authorizedDomains,
      protocolBindings,
      packageInfo: {
        manifestUrl: options.manifestUrl,
        downloadUrl: options.downloadUrl,
        schemaUrl: options.schemaUrl,
        packageHash,
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
  if (hasDidOanSemanticConflict(resourcePackage.resourceDid, resourcePackage.didDocument.oanMetadata)) {
    throw new OanVerificationError("did_subject_resource_type_mismatch");
  }
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
  const didDocumentAuthorizedDomains = resourcePackage.didDocument.oanMetadata?.authorizedDomains;
  if (
    Array.isArray(didDocumentAuthorizedDomains) &&
    !sameStringList(metadata.authorizedDomains ?? [], didDocumentAuthorizedDomains)
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
    claims.lifecycleState !== resourcePackage.metadata.lifecycleState ||
    (Array.isArray(claims.authorizedDomains) &&
      !sameStringList(claims.authorizedDomains, resourcePackage.metadata.authorizedDomains ?? []))
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

export function validateDidDocumentDraft(
  document: DidDocument,
  options: { resourceDid?: string; resourceType?: ResourceType } = {},
): OanDraftValidationReport {
  const issues: OanValidationIssue[] = [];
  const effectiveDid = options.resourceDid ?? document.id;
  const effectiveType = options.resourceType ?? document.oanMetadata?.resourceType;

  try {
    assertDidOan(effectiveDid);
  } catch (error) {
    issues.push(issueFromError(error, "resourceDid"));
  }

  if (effectiveType) {
    try {
      assertDidSubjectMatchesResourceType(effectiveDid, effectiveType);
    } catch (error) {
      issues.push(issueFromError(error, "resourceType"));
    }
  }

  try {
    verifyDidDocumentServiceBindings(document);
  } catch (error) {
    issues.push(issueFromError(error, "protocolBindings"));
  }

  const packageInfo = document.oanMetadata?.packageInfo;
  if (packageInfo) {
    try {
      verifyArtifactReferenceMaterial(packageInfo);
    } catch (error) {
      issues.push(issueFromError(error, "packageInfo"));
    }
    if (typeof packageInfo.packageHash === "string") {
      try {
        verifyHashLike(packageInfo.packageHash, "packageHash");
      } catch (error) {
        issues.push(issueFromError(error, "packageInfo.packageHash"));
      }
    }
    if (typeof packageInfo.metadataHash === "string") {
      try {
        verifyHashLike(packageInfo.metadataHash, "metadataHash");
      } catch (error) {
        issues.push(issueFromError(error, "packageInfo.metadataHash"));
      }
    }
  }

  return {
    ok: issues.length === 0,
    resourceDid: effectiveDid,
    resourceType: effectiveType,
    issues,
  };
}

export function buildDiscoveryQuery(
  input: ResourceDiscoveryQuery & {
    capabilityTags?: string[];
  },
): ResourceDiscoveryQuery {
  const query = typeof input.query === "string" ? input.query.trim() : undefined;
  const capabilityTags = Array.isArray(input.capabilityTags)
    ? input.capabilityTags.map((tag) => tag.trim()).filter((tag) => tag.length > 0)
    : undefined;
  return {
    query: query && query.length > 0 ? query : undefined,
    resourceType:
      typeof input.resourceType === "string" && input.resourceType.trim()
        ? input.resourceType
        : undefined,
    capabilityTags: capabilityTags && capabilityTags.length > 0 ? capabilityTags : undefined,
    protocol: typeof input.protocol === "string" && input.protocol.trim() ? input.protocol.trim() : undefined,
    version: typeof input.version === "string" && input.version.trim() ? input.version.trim() : undefined,
    versionMode: input.versionMode,
    limit: typeof input.limit === "number" && Number.isFinite(input.limit) ? input.limit : undefined,
  };
}

export function summarizeTrustFromPackage(resourcePackage: ResourcePackage): OanTrustSummary {
  const checks: string[] = [];
  const warnings: string[] = [];

  try {
    verifyResourcePackageShape(resourcePackage);
    checks.push("package binding verified");
  } catch (error) {
    warnings.push(issueFromError(error).message);
  }

  if (resourcePackage.rootProof?.rootDid) {
    checks.push("root proof present");
  } else {
    warnings.push("root proof missing");
  }

  if (resourcePackage.metadata.lifecycleState === "active") {
    checks.push("active lifecycle state");
  } else {
    warnings.push(`lifecycle state is ${resourcePackage.metadata.lifecycleState}`);
  }

  return {
    level: warnings.length === 0 ? "verified" : checks.length > 0 ? "warning" : "unverified",
    checks,
    warnings,
  };
}

export function summarizeLifecycleSnapshot(snapshot: {
  stage: VersionMode | string;
  registrarAccepted?: boolean;
  rootObserved?: boolean;
  cdnObserved?: boolean;
  discoveryVisible?: boolean;
  observations?: string[];
}): OanTrustSummary {
  const checks: string[] = [];
  const warnings: string[] = [];
  if (snapshot.registrarAccepted) checks.push("accepted by registrar");
  if (snapshot.rootObserved) checks.push("observed at root");
  if (snapshot.cdnObserved) checks.push("published to CDN");
  if (snapshot.discoveryVisible) checks.push("visible in discovery");
  if (!snapshot.discoveryVisible) warnings.push(`current stage: ${snapshot.stage}`);
  for (const item of snapshot.observations ?? []) {
    if (!checks.includes(item) && !warnings.includes(item)) {
      checks.push(item);
    }
  }
  return {
    level: snapshot.discoveryVisible ? "verified" : checks.length > 0 ? "warning" : "unverified",
    checks,
    warnings,
  };
}

export function summarizeDiscoveryCandidate(
  candidate: ResourceDiscoveryCandidate,
  resourcePackage?: ResourcePackage,
): OanDiscoveryResultSummary {
  const metadata = resourcePackage?.metadata;
  const description = resourcePackage?.didDocument?.oanMetadata?.resourceDescription;
  const capabilityTags = uniqueStrings([
    ...(candidate.capabilityTags ?? []),
    ...(metadata?.capabilityTags ?? []),
    ...(description?.capabilityTags ?? []),
  ]);
  const authorizedDomains = uniqueStrings([
    ...(candidate.authorizedDomains ?? []),
    ...(metadata?.authorizedDomains ?? []),
    ...(resourcePackage?.didDocument?.oanMetadata?.authorizedDomains ?? []),
  ]);
  const protocols = uniqueStrings([
    ...extractProtocolsFromBindings(candidate.protocolBindings),
    ...extractProtocolsFromBindings(metadata?.protocolBindings),
    ...extractProtocolsFromBindings(resourcePackage?.didDocument?.oanMetadata?.protocolBindings),
  ]);
  return {
    resourceDid: candidate.resourceDid,
    resourceType: candidate.resourceType,
    version: candidate.version ?? resourcePackage?.packageVersion,
    lifecycleState: candidate.lifecycleState ?? metadata?.lifecycleState,
    title: description?.name ?? metadata?.name,
    description: description?.description ?? metadata?.description,
    capabilityTags,
    authorizedDomains,
    protocols,
    primaryEndpoint: extractPrimaryEndpoint(candidate, resourcePackage),
    trust: resourcePackage
      ? summarizeTrustFromPackage(resourcePackage)
      : {
          level: candidate.rootProof ? "warning" : "unverified",
          checks: candidate.rootProof ? ["discovery candidate carries root-proof material"] : [],
          warnings: candidate.rootProof ? [] : ["package-level trust detail not loaded"],
        },
  };
}

export function verifyHashLike(value: string, fieldName = "hash"): void {
  if (!/^[a-zA-Z0-9_-]+:.+/.test(value)) {
    throw new OanVerificationError("hash_format_mismatch", `${fieldName} must use algorithm:value shape`);
  }
}

export function verifyDidDocumentServiceBindings(document: DidDocument): void {
  const metadata = document.oanMetadata;
  const bindings = metadata?.protocolBindings ?? [];
  const services = document.service ?? [];
  for (const binding of bindings) {
    const serviceRef = binding.serviceRef;
    if (!serviceRef) {
      continue;
    }
    const matched = services.some((service) => {
      if (serviceRef.startsWith("#")) {
        return service.id === `${document.id}${serviceRef}` || service.id.endsWith(serviceRef);
      }
      return service.id === serviceRef;
    });
    if (!matched) {
      throw new OanVerificationError("service_binding_mismatch");
    }
  }
}

export function selectLatestCandidate(candidates: ResourceDiscoveryCandidate[]): ResourceDiscoveryCandidate | undefined {
  return candidates.find((candidate) => candidate.lifecycleState === "active") ?? candidates[0];
}

function issueFromError(error: unknown, field?: string): OanValidationIssue {
  if (error instanceof OanVerificationError) {
    return {
      code: error.code,
      message: error.message,
      field,
    };
  }
  return {
    code: "hash_format_mismatch",
    message: error instanceof Error ? error.message : "unknown validation error",
    field,
  };
}

function extractPrimaryEndpoint(
  candidate: ResourceDiscoveryCandidate,
  resourcePackage?: ResourcePackage,
): string | undefined {
  const candidateService = candidate.services?.find((service) => typeof service.serviceEndpoint === "string");
  if (candidateService?.serviceEndpoint) {
    return candidateService.serviceEndpoint;
  }
  const packageService = resourcePackage?.didDocument?.service?.find((service) => typeof service.serviceEndpoint === "string");
  if (packageService?.serviceEndpoint) {
    return packageService.serviceEndpoint;
  }
  const packageInfo = resourcePackage?.didDocument?.oanMetadata?.packageInfo ?? candidate.packageInfo;
  return (
    (typeof packageInfo?.manifestUrl === "string" && packageInfo.manifestUrl) ||
    (typeof packageInfo?.downloadUrl === "string" && packageInfo.downloadUrl) ||
    undefined
  );
}

function extractProtocolsFromBindings(bindings: unknown): string[] {
  if (!Array.isArray(bindings)) {
    return [];
  }
  return bindings
    .map((binding) =>
      binding && typeof binding === "object" && typeof (binding as ProtocolBinding).protocol === "string"
        ? (binding as ProtocolBinding).protocol
        : undefined,
    )
    .filter((value): value is string => typeof value === "string" && value.length > 0);
}

function sameStringList(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length > 0))];
}

export * from "./did-oan.js";
export * from "./identity.js";
