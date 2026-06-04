// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

export type ResourceType =
  | "agent_service"
  | "skill"
  | "mcp_server"
  | "tool_api"
  | "infrastructure_node"
  | "organization"
  | "developer";

export type VersionMode = "latest" | "exact" | "constraint" | "any-retained";

export interface DidDocument {
  "@context"?: string | string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  service?: ServiceEndpoint[];
  oanMetadata?: OanMetadata;
  [key: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  cryptoSuite?: "Ed25519Sha256" | "Sm2Sm3" | "Ed25519Sha256Legacy" | string;
  publicKeyFormat?: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
  version?: string;
  protocol?: string;
  serverType?: string;
  port?: number;
  [key: string]: unknown;
}

export interface OanMetadata {
  subjectType: ResourceType;
  resourceType: ResourceType;
  nodeRole?: string;
  identityType?: string;
  controllerDid?: string;
  publisherDid?: string;
  issuerDid?: string;
  ttl?: number;
  resourceDescription?: ResourceDescription;
  capabilityTags?: string[];
  protocolBindings?: ProtocolBinding[];
  implementationLinks?: ImplementationLink[];
  credentialRequirements?: CredentialRequirement[];
  packageInfo?: PackageInfo;
  lifecycleState?: string;
  [key: string]: unknown;
}

export interface ResourceDescription {
  name?: string;
  description?: string;
  capabilityTags?: string[];
  useCaseExamples?: string[];
  [key: string]: unknown;
}

export interface ProtocolBinding {
  id: string;
  protocol: string;
  version?: string;
  transport?: string;
  serviceRef?: string;
  schemaRef?: string;
  [key: string]: unknown;
}

export interface ImplementationLink {
  relation: string;
  targetDid?: string;
  targetType?: ResourceType;
  targetService?: string;
  versionConstraint?: string;
  [key: string]: unknown;
}

export interface CredentialRequirement {
  type: string;
  issuerDid?: string;
  purpose?: string;
  [key: string]: unknown;
}

export interface PackageInfo {
  manifestUrl?: string;
  downloadUrl?: string;
  packageHash?: string;
  hashAlgorithm?: string;
  version?: string;
  versionScheme?: string;
  previousVersion?: string;
  rootProofRef?: string;
  [key: string]: unknown;
}

export interface DataIntegrityProof {
  type: string;
  creator?: string;
  verificationMethod?: string;
  created?: string;
  proofPurpose?: string;
  proofValue: string;
  cryptoSuite?: string;
  hashAlgorithm?: string;
  [key: string]: unknown;
}

export interface ResourceMetadata {
  resourceDid: string;
  resourceType: ResourceType;
  subjectType: ResourceType;
  publisherDid?: string;
  subjectDid?: string;
  name: string;
  description?: string;
  capabilityTags?: string[];
  protocolBindings?: unknown[];
  services?: ServiceEndpoint[];
  lifecycleState: string;
  packageVersion: string;
  packageHash: string;
  metadataHash: string;
  hashAlgorithm: string;
  updatedAt: string;
}

export interface RootProof {
  rootDid: string;
  bulletinEventHash?: string | null;
  signature?: string | null;
  packageClaims?: ResourcePackageClaims;
  proof?: DataIntegrityProof;
  cryptoSuite?: string;
  hashAlgorithm?: string;
}

export interface ResourcePackageClaims {
  resourceDid: string;
  resourceType: ResourceType;
  version: string;
  didDocumentHash: string;
  metadataHash: string;
  packageHash: string;
  hashAlgorithm: string;
  lifecycleState: string;
  bulletinRef?: string;
}

export interface ResourcePackage {
  packageVersion: string;
  resourceDid: string;
  resourceType: ResourceType;
  didDocument: DidDocument;
  didDocumentHash: string;
  metadataHash: string;
  packageHash: string;
  hashAlgorithm: string;
  metadata: ResourceMetadata;
  rootProof: RootProof;
  createdAt: string;
}

export interface ResourceDiscoveryQuery {
  query?: string;
  resourceType?: ResourceType;
  capabilityTags?: string[];
  protocol?: string;
  version?: string;
  versionMode?: VersionMode;
  limit?: number;
}

export interface ResourceDiscoveryCandidate {
  resourceDid: string;
  resourceType: ResourceType;
  score: number;
  version?: string;
  lifecycleState?: string;
  capabilityTags?: string[];
  services?: ServiceEndpoint[];
  protocolBindings?: unknown[];
  packageInfo?: PackageInfo;
  rootProof?: RootProof | unknown;
}

export interface ResourceDiscoveryResponse {
  discoveryDid: string;
  candidates: ResourceDiscoveryCandidate[];
  createdAt: string;
  proof?: DataIntegrityProof | null;
}
