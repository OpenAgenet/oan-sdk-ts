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
  authorizedDomains?: string[];
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
  authorizedDomains?: string[];
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
  authorizedDomains?: string[];
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
  authorizedDomains?: string[];
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

export interface ResourceDiscoveryExplainItem {
  resourceDid: string;
  resourceType: ResourceType;
  matched: boolean;
  score: number;
  textMatched?: boolean | null;
  capabilityTagOverlap?: string[];
  resourceTypeMatched?: boolean | null;
  protocolMatched?: boolean | null;
  [key: string]: unknown;
}

export interface ResourceDiscoveryExplainResponse {
  query: ResourceDiscoveryQuery;
  items: ResourceDiscoveryExplainItem[];
  candidateCount: number;
  usedIndexedPrefilter?: boolean;
  [key: string]: unknown;
}

export interface ResourceRegistrationSubmission {
  resourceDid: string;
  resourceType: ResourceType;
  didDocument: DidDocument;
  packageVersion: string;
  metadataHash: string;
  packageHash: string;
  hashAlgorithm: string;
  registrationCredential?: unknown;
  [key: string]: unknown;
}

export interface ResourceRegistrationResponse {
  status: string;
  resourceDid: string;
  resourceType?: ResourceType;
  registrationCredential?: unknown;
  rootResponse?: unknown;
}

export interface RecommendationEvidence {
  kind: string;
  term: string;
  matchedProfile: string;
}

export interface DomainCandidate {
  id: string;
  label: string;
  score: number;
  covered: boolean;
  reason: string;
  evidence?: RecommendationEvidence[];
}

export interface ValueCandidate {
  value: string;
  score: number;
  reason: string;
  evidence?: RecommendationEvidence[];
}

export interface RegistrationSuggestionInput {
  resourceType?: ResourceType | null;
  name: string;
  description: string;
  endpoint?: string | null;
  manifestText?: string | null;
  schemaText?: string | null;
  locale?: string | null;
}

export interface RegistrationSuggestionResult {
  authorizedDomains: DomainCandidate[];
  outOfScopeDomainHints: DomainCandidate[];
  capabilityTags: ValueCandidate[];
  resourceTypeHints: ValueCandidate[];
  protocolHints: ValueCandidate[];
  warnings?: string[];
}

export interface RegistrationDomainCatalogEntry {
  id: string;
  label: string;
  aliases?: string[];
  selectable?: boolean;
  [key: string]: unknown;
}

export interface RegistrationDomainCatalogResponse {
  registrarDid?: string;
  authorizedDomains?: string[];
  catalogVersion?: number;
  snapshotHash?: string | null;
  domains?: RegistrationDomainCatalogEntry[];
  [key: string]: unknown;
}

export interface RegistrarStatusResponse {
  status?: string;
  did?: string;
  registrarDid?: string;
  rootEndpoint?: string;
  resourceRecordCount?: number;
  protocolVersion?: string;
  rootAuthorizationStatus?: string;
  [key: string]: unknown;
}

export interface RootAuthorizationInspection {
  registrarDid?: string;
  discoveryDid?: string;
  rootEndpoint?: string;
  rootReachable?: boolean;
  status?: string;
  authorization?: unknown;
  authorizedDomains?: string[];
  rootStatusCode?: number;
  error?: string;
  [key: string]: unknown;
}

export interface RootStatusResponse {
  status?: string;
  latestVersionCount?: number;
  cdnQueueCount?: number;
  cdnReadyQueueCount?: number;
  cdnActiveQueueCount?: number;
  discoveryQueueCount?: number;
  discoveryReadyQueueCount?: number;
  discoveryPendingQueueCount?: number;
  workerRuntime?: Record<string, unknown>;
  eventRuntime?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface CdnStatusResponse {
  status?: string;
  resourceCount?: number;
  [key: string]: unknown;
}

export interface DiscoveryStatusResponse {
  status?: string;
  did?: string;
  discoveryDid?: string;
  rootEndpoint?: string | null;
  cdnEndpoint?: string | null;
  rootAuthorizationStatus?: string;
  indexedResourceCount?: number;
  lastSync?: unknown;
  [key: string]: unknown;
}

export interface DiscoveryVisibilityRequest {
  resourceDids: string[];
}

export interface DiscoveryVisibilityResponse {
  resourceDids?: string[];
  visible?: string[];
  visibleCount?: number;
  [key: string]: unknown;
}

export interface DiscoveryAuthorizedDomainsResponse {
  discoveryDid?: string;
  authorizedDomains?: string[];
  [key: string]: unknown;
}

export interface CapabilityTagSuggestionResponse {
  suggestions?: string[];
  capabilityTags?: ValueCandidate[];
  [key: string]: unknown;
}

export interface CapabilityTagNormalizeRequest {
  tags: string[];
}

export interface CapabilityTagNormalizeResponse {
  tags: string[];
  capabilityTags?: string[];
  [key: string]: unknown;
}

export interface DiscoverySuggestionInput {
  query: string;
  currentResourceType?: ResourceType | null;
  currentProtocol?: string | null;
  currentCapabilityTags?: string[];
  locale?: string | null;
}

export interface DiscoverySuggestionResult {
  queryRewrite?: string | null;
  capabilityTags: ValueCandidate[];
  resourceTypes: ValueCandidate[];
  protocols: ValueCandidate[];
  authorizedDomainHints: DomainCandidate[];
  warnings?: string[];
}

export interface RootResourceVersionListResponse {
  did: string;
  items: Array<Record<string, unknown>>;
}

export type OanWorkflowStage =
  | "draft-prepared"
  | "submitted-to-registrar"
  | "accepted-by-registrar"
  | "queued-at-root"
  | "accepted-by-root"
  | "published-to-cdn"
  | "visible-in-discovery"
  | "failed-validation"
  | "failed-submission"
  | "visibility-pending";

export interface OanLifecycleSnapshot {
  resourceDid: string;
  registrarAccepted: boolean;
  rootObserved: boolean;
  cdnObserved: boolean;
  discoveryVisible: boolean;
  stage: OanWorkflowStage;
  registrarRecord?: unknown;
  rootResource?: unknown;
  rootVersions?: RootResourceVersionListResponse;
  cdnPackage?: ResourcePackage | null;
  discoveryVisibility?: DiscoveryVisibilityResponse;
  registrarStatus?: RegistrarStatusResponse;
  rootStatus?: RootStatusResponse;
  cdnStatus?: CdnStatusResponse;
  discoveryStatus?: DiscoveryStatusResponse;
  observations?: string[];
}
