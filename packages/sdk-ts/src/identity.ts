// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  ControllerAuthorizationProofBundle,
  DataIntegrityProof,
  DidDocument,
  ResourceRegistrationSubmission,
  ResourceType,
} from "../../protocol-types/src/index.js";
import { createResourceDidDocumentDraft } from "./index.js";

export type OanIdentityKind = "subject" | "agent" | "node";

export interface OanIdentityProfile {
  label: string;
  resourceType: ResourceType;
  domainCode?: string;
  ownerSubjectDid?: string;
  capabilityTags?: string[];
  authorizedDomains?: string[];
  description?: string;
  origin?: "generated" | "legacy-genesis-import";
  metadata?: Record<string, unknown>;
}

export interface OanIdentityRecord {
  id: string;
  kind: OanIdentityKind;
  createdAt: string;
  did: string;
  verificationMethodId: string;
  didDocument: DidDocument;
  privateKeyJwk: Record<string, unknown>;
  publicKeyJwk: Record<string, unknown>;
  profile: OanIdentityProfile;
}

export interface OanIdentityStoreSnapshot {
  version: 1;
  updatedAt: string;
  defaultSubjectId?: string;
  defaultAgentId?: string;
  subjects: OanIdentityRecord[];
  agents: OanIdentityRecord[];
  nodes: OanIdentityRecord[];
}

export interface CreateIdentityOptions {
  label: string;
  resourceType: ResourceType;
  kind: OanIdentityKind;
  domainCode?: string;
  did?: string;
  ownerSubjectDid?: string;
  capabilityTags?: string[];
  authorizedDomains?: string[];
  description?: string;
  serviceEndpoint?: string;
  serviceType?: string;
  protocol?: string;
  manifestUrl?: string;
  schemaUrl?: string;
  verificationMethodType?: string;
  origin?: "generated" | "legacy-genesis-import";
  metadata?: Record<string, unknown>;
}

export interface RegistrationMaterialOptions {
  packageVersion?: string;
  metadataHash?: string;
  packageHash?: string;
  hashAlgorithm?: string;
  endpoint?: string;
  manifestUrl?: string;
  schemaUrl?: string;
  serviceType?: string;
  protocol?: string;
  capabilityTags?: string[];
  authorizedDomains?: string[];
  description?: string;
  packageInfo?: Record<string, unknown>;
}

export interface ControllerAuthorizationProofOptions {
  controllerIdentity: OanIdentityRecord;
  registrarDid: string;
  ttlMs?: number;
  now?: Date;
}

const SUBJECT_CODE_BY_RESOURCE_TYPE: Record<ResourceType, string> = {
  agent_service: "AG",
  skill: "SK",
  mcp_server: "MC",
  tool_api: "TL",
  infrastructure_node: "IN",
  organization: "OR",
  developer: "DV",
};

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export async function createOanIdentityRecord(
  options: CreateIdentityOptions,
): Promise<OanIdentityRecord> {
  const domainCode = normalizeDomainCode(options.domainCode);
  const did = options.did ?? createDidOan(options.resourceType, domainCode);
  const keyPair = await generateEd25519JwkPair();
  const verificationMethodId = `${did}#key-1`;
  const didDocument = createResourceDidDocumentDraft({
    resourceDid: did,
    resourceType: options.resourceType,
    name: options.label,
    description: options.description,
    capabilityTags: options.capabilityTags,
    authorizedDomains: options.authorizedDomains,
    serviceEndpoint: options.serviceEndpoint,
    serviceType: options.serviceType,
    protocol: options.protocol,
    manifestUrl: options.manifestUrl,
    schemaUrl: options.schemaUrl,
    controllerDid: options.ownerSubjectDid,
    publisherDid: options.ownerSubjectDid,
    verificationMethodType: options.verificationMethodType,
    publicKeyMultibase: undefined,
  });
  if (Array.isArray(didDocument.verificationMethod) && didDocument.verificationMethod[0]) {
    didDocument.verificationMethod[0] = {
      ...didDocument.verificationMethod[0],
      cryptoSuite: "ed25519-sha256",
      publicKeyJwk: keyPair.publicKeyJwk,
      publicKeyMultibase: undefined,
    };
  }
  const createdAt = new Date().toISOString();
  return {
    id: buildIdentityRecordId(options.kind, options.resourceType),
    kind: options.kind,
    createdAt,
    did,
    verificationMethodId,
    didDocument,
    privateKeyJwk: keyPair.privateKeyJwk,
    publicKeyJwk: keyPair.publicKeyJwk,
    profile: {
      label: options.label,
      resourceType: options.resourceType,
      domainCode,
      ownerSubjectDid: options.ownerSubjectDid,
      capabilityTags: options.capabilityTags,
      authorizedDomains: options.authorizedDomains,
      description: options.description,
      origin: options.origin ?? "generated",
      metadata: options.metadata,
    },
  };
}

export async function createDefaultSubjectIdentity(
  label = "Default OAN Subject",
): Promise<OanIdentityRecord> {
  return createOanIdentityRecord({
    label,
    resourceType: "developer",
    kind: "subject",
  });
}

export async function createAgentIdentity(
  label: string,
  resourceType: Extract<ResourceType, "agent_service" | "skill" | "mcp_server" | "tool_api">,
  ownerSubjectDid?: string,
  options: Partial<CreateIdentityOptions> = {},
): Promise<OanIdentityRecord> {
  return createOanIdentityRecord({
    label,
    resourceType,
    kind: "agent",
    ownerSubjectDid,
    ...options,
  });
}

export function createEmptyIdentityStoreSnapshot(): OanIdentityStoreSnapshot {
  return {
    version: 1,
    updatedAt: new Date().toISOString(),
    subjects: [],
    agents: [],
    nodes: [],
  };
}

export function cloneIdentityStoreSnapshot(snapshot: OanIdentityStoreSnapshot): OanIdentityStoreSnapshot {
  return JSON.parse(JSON.stringify(snapshot)) as OanIdentityStoreSnapshot;
}

export function upsertIdentityRecord(
  snapshot: OanIdentityStoreSnapshot,
  record: OanIdentityRecord,
): OanIdentityStoreSnapshot {
  const next = cloneIdentityStoreSnapshot(snapshot);
  const bucket = bucketForKind(next, record.kind);
  const existingIndex = bucket.findIndex((item) => item.id === record.id || item.did === record.did);
  if (existingIndex >= 0) {
    bucket[existingIndex] = record;
  } else {
    bucket.push(record);
  }
  if (record.kind === "subject" && !next.defaultSubjectId) next.defaultSubjectId = record.id;
  if (record.kind === "agent" && !next.defaultAgentId) next.defaultAgentId = record.id;
  next.updatedAt = new Date().toISOString();
  return next;
}

export function exportIdentityBundle(snapshot: OanIdentityStoreSnapshot): string {
  return JSON.stringify(snapshot, null, 2);
}

export function importIdentityBundle(serialized: string): OanIdentityStoreSnapshot {
  const parsed = JSON.parse(serialized) as OanIdentityStoreSnapshot;
  if (parsed.version !== 1) {
    throw new Error("unsupported_identity_bundle_version");
  }
  return parsed;
}

export function createRegistrationSubmissionFromIdentity(
  record: OanIdentityRecord,
  options: RegistrationMaterialOptions = {},
): ResourceRegistrationSubmission {
  const endpoint = options.endpoint ?? options.manifestUrl ?? options.schemaUrl;
  const description =
    options.description ??
    (record.didDocument.oanMetadata?.resourceDescription?.description as string | undefined) ??
    record.profile.description;
  const capabilityTags =
    options.capabilityTags ??
    record.profile.capabilityTags ??
    (record.didDocument.oanMetadata?.capabilityTags as string[] | undefined);
  const authorizedDomains =
    options.authorizedDomains ??
    record.profile.authorizedDomains ??
    (record.didDocument.oanMetadata?.authorizedDomains as string[] | undefined);
  const draft = createResourceDidDocumentDraft({
    resourceDid: record.did,
    resourceType: record.profile.resourceType,
    name:
      (record.didDocument.oanMetadata?.resourceDescription?.name as string | undefined) ??
      record.profile.label,
    description,
    capabilityTags,
    authorizedDomains,
    serviceEndpoint: endpoint,
    manifestUrl: options.manifestUrl,
    schemaUrl: options.schemaUrl,
    serviceType: options.serviceType,
    protocol: options.protocol,
    controllerDid: record.profile.ownerSubjectDid,
    publisherDid: record.profile.ownerSubjectDid,
    verificationMethodType:
      typeof record.didDocument.verificationMethod?.[0]?.type === "string"
        ? record.didDocument.verificationMethod[0].type
        : undefined,
  });
  if (Array.isArray(draft.verificationMethod) && draft.verificationMethod[0]) {
    draft.verificationMethod[0] = {
      ...draft.verificationMethod[0],
      cryptoSuite: "ed25519-sha256",
      publicKeyJwk: record.publicKeyJwk,
      publicKeyMultibase: undefined,
    };
  }
  draft.oanMetadata = {
    ...(draft.oanMetadata ?? {
      subjectType: record.profile.resourceType,
      resourceType: record.profile.resourceType,
    }),
  };
  return {
    resourceDid: record.did,
    resourceType: record.profile.resourceType,
    didDocument: draft,
    packageVersion: options.packageVersion ?? "1.0.0",
    metadataHash: options.metadataHash ?? "sha256:pending-metadata-hash",
    packageHash: options.packageHash ?? "sha256:pending-package-hash",
    hashAlgorithm: options.hashAlgorithm ?? "sha256",
  };
}

export async function attachControllerAuthorizationProof(
  submission: ResourceRegistrationSubmission,
  options: ControllerAuthorizationProofOptions,
): Promise<ResourceRegistrationSubmission> {
  if (!submission.didDocumentHash || !submission.metadataHash) {
    throw new Error("missing_hashes_for_controller_authorization");
  }
  const controllerDid = submission.didDocument.oanMetadata?.controllerDid ?? options.controllerIdentity.did;
  if (controllerDid !== options.controllerIdentity.did) {
    throw new Error("controller_identity_mismatch");
  }
  const now = options.now ?? new Date();
  const verificationMethod =
    options.controllerIdentity.verificationMethodId || `${options.controllerIdentity.did}#key-1`;
  const challenge = {
    challengeId: `controller-auth-${now.getTime().toString(36)}-${randomBase58(8)}`,
    resourceDid: submission.resourceDid,
    controllerDid,
    publisherDid: submission.didDocument.oanMetadata?.publisherDid,
    didDocumentHash: submission.didDocumentHash,
    metadataHash: submission.metadataHash,
    registrarDid: options.registrarDid,
    purpose: "resource-registration-controller-authorization",
    verificationMethod,
    nonce: randomBase58(24),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + (options.ttlMs ?? 5 * 60 * 1000)).toISOString(),
  };
  const proof = await signDataIntegrityProof(challenge, options.controllerIdentity, "capabilityInvocation");
  const bundle: ControllerAuthorizationProofBundle = {
    challenge,
    controllerDidDocument: sanitizeControllerDidDocument(options.controllerIdentity),
    proof,
  };
  submission.controllerAuthorizationProof = bundle;
  return submission;
}

export function createDidOan(resourceType: ResourceType, domainCode = "DM"): string {
  const subjectCode = SUBJECT_CODE_BY_RESOURCE_TYPE[resourceType];
  if (!subjectCode) {
    throw new Error("unsupported_resource_type_for_did_generation");
  }
  return `did:oan:${subjectCode}${normalizeDomainCode(domainCode)}:${randomBase58(32)}`;
}

export function normalizeDomainCode(value = "DM"): string {
  const normalized = value.toUpperCase();
  if (!/^[A-Z0-9]{2}$/.test(normalized)) {
    throw new Error("invalid_domain_code");
  }
  return normalized;
}

function sanitizeControllerDidDocument(record: OanIdentityRecord): DidDocument {
  const didDocument = JSON.parse(JSON.stringify(record.didDocument)) as DidDocument;
  didDocument.id = record.did;
  didDocument.verificationMethod = [
    {
      ...(didDocument.verificationMethod?.[0] ?? {
        id: record.verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: record.did,
      }),
      id: record.verificationMethodId,
      controller: record.did,
      cryptoSuite: "ed25519-sha256",
      publicKeyJwk: record.publicKeyJwk,
      publicKeyMultibase: undefined,
    },
  ];
  didDocument.authentication = didDocument.authentication?.length
    ? didDocument.authentication
    : [record.verificationMethodId];
  didDocument.assertionMethod = didDocument.assertionMethod?.length
    ? didDocument.assertionMethod
    : [record.verificationMethodId];
  didDocument.capabilityInvocation = didDocument.capabilityInvocation?.length
    ? didDocument.capabilityInvocation
    : [record.verificationMethodId];
  return removePrivateKeyMaterial(didDocument) as DidDocument;
}

async function signDataIntegrityProof(
  payload: unknown,
  record: OanIdentityRecord,
  proofPurpose: string,
): Promise<DataIntegrityProof> {
  const privateKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    record.privateKeyJwk as JsonWebKey,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const signature = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    new TextEncoder().encode(canonicalJson(payload)),
  );
  return {
    type: "Ed25519Signature2020",
    creator: record.did,
    created: new Date().toISOString(),
    proofPurpose,
    proofValue: base64Url(new Uint8Array(signature)),
    cryptoSuite: "ed25519-sha256",
    hashAlgorithm: "SHA-256",
    verificationMethod: record.verificationMethodId,
  };
}

function removePrivateKeyMaterial(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(removePrivateKeyMaterial);
  if (!value || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [key, entryValue] of Object.entries(value as Record<string, unknown>)) {
    if (
      key === "privateKeyJwk" ||
      key === "privateKeyMultibase" ||
      key === "privateKeyBase58" ||
      key === "privateKeyHex" ||
      key === "d"
    ) {
      continue;
    }
    output[key] = removePrivateKeyMaterial(entryValue);
  }
  return output;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJson(entryValue)}`).join(",")}}`;
}

function base64Url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index];
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += alphabet[first >> 2];
    output += alphabet[((first & 0x03) << 4) | ((second ?? 0) >> 4)];
    if (index + 1 < bytes.length) {
      output += alphabet[((second & 0x0f) << 2) | ((third ?? 0) >> 6)];
    }
    if (index + 2 < bytes.length) {
      output += alphabet[third & 0x3f];
    }
  }
  return output;
}

function bucketForKind(
  snapshot: OanIdentityStoreSnapshot,
  kind: OanIdentityKind,
): OanIdentityRecord[] {
  if (kind === "subject") return snapshot.subjects;
  if (kind === "agent") return snapshot.agents;
  return snapshot.nodes;
}

function buildIdentityRecordId(kind: OanIdentityKind, resourceType: ResourceType): string {
  return `${kind}-${resourceType}-${Date.now().toString(36)}-${randomBase58(6).toLowerCase()}`;
}

async function generateEd25519JwkPair(): Promise<{
  privateKeyJwk: Record<string, unknown>;
  publicKeyJwk: Record<string, unknown>;
}> {
  const pair = await globalThis.crypto.subtle.generateKey(
    {
      name: "Ed25519",
    },
    true,
    ["sign", "verify"],
  );
  const [privateKeyJwk, publicKeyJwk] = await Promise.all([
    globalThis.crypto.subtle.exportKey("jwk", pair.privateKey),
    globalThis.crypto.subtle.exportKey("jwk", pair.publicKey),
  ]);
  return {
    privateKeyJwk: privateKeyJwk as Record<string, unknown>,
    publicKeyJwk: publicKeyJwk as Record<string, unknown>,
  };
}

function randomBase58(length: number): string {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  let output = "";
  for (let index = 0; index < length; index += 1) {
    output += BASE58_ALPHABET[bytes[index] % BASE58_ALPHABET.length];
  }
  return output;
}
