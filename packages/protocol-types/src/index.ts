// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import jsigs from "jsonld-signatures";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { documentLoader as ed25519DocumentLoader } from "ed25519-signature-2020-context";
import { encode as base58Encode } from "base58-universal";
import { decode as base64urlDecode } from "base64url-universal";

export type SubjectType =
  | "agent_instance" | "agent_product" | "agent_service" | "skill" | "mcp_server" | "tool_api"
  | "infrastructure_node" | "organization" | "developer" | "root_node" | "registrar_node"
  | "discovery_node" | "cdn_node" | "vc_issuer_node" | "trust_indexer_node" | "unspecified"
  | "controller";

export type ResourceType =
  | "agent_instance"
  | "agent_product"
  | "agent_service"
  | "skill"
  | "mcp_server"
  | "tool_api"
  | "infrastructure_node"
  | "organization"
  | "developer"
  | "root_node"
  | "registrar_node"
  | "discovery_node"
  | "cdn_node"
  | "vc_issuer_node"
  | "trust_indexer_node"
  | "unspecified"
  | "controller";

export type VersionMode = "latest" | "exact" | "constraint" | "any-retained";

export interface DidDocument {
  "@context"?: string | string[];
  id: string;
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  capabilityInvocation?: string[];
  service?: ServiceEndpoint[];
  proof?: DataIntegrityProof;
  oanMetadata?: OanMetadata;
  [key: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
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
  subjectType: SubjectType;
  resourceType: ResourceType;
  externalIdentifiers?: ExternalIdentifier[];
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
  id: string;
  purpose: string;
  credentialType: string;
  issuer?: string | string[];
  scope?: Record<string, unknown>;
  presentationMode?: string;
  required: boolean;
}

export interface PackageInfo {
  manifestUrl?: string;
  downloadUrl?: string;
  packageHash?: string;
  metadataHash?: string;
  version?: string;
  versionScheme?: string;
  previousVersion?: string;
  rootProofRef?: string;
  releaseNotesUrl?: string;
  createdAt?: string;
  updatedAt?: string;
  expiresAt?: string;
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

export interface DidOanJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  d?: string;
  alg?: "EdDSA";
}

export interface DidOanVerificationMethod {
  id: string;
  type: "Ed25519VerificationKey2020";
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: DidOanJwk;
}

export interface DidOanDataIntegrityProof {
  type: "Ed25519Signature2020";
  created: string;
  proofPurpose: "assertionMethod";
  proofValue: string;
  verificationMethod: string;
}

export interface DidOanVerifiableCredential {
  id?: string;
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://openagenet.xyz/did-oan-specs/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ];
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: Record<string, unknown>;
  credentialStatus?: Record<string, unknown>;
  credentialSchema?: Record<string, unknown>;
  proof: DidOanDataIntegrityProof;
}

export type DidOanDocumentLoader = (url: string) => Promise<{
  contextUrl: string | null;
  documentUrl: string;
  document: unknown;
}>;

export interface DidOanDataIntegrityOptions {
  created?: string;
  documentLoader?: DidOanDocumentLoader;
}

function rejectDidOanUnknownFields(
  value: Record<string, unknown>,
  allowed: readonly string[],
  error: string,
): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    throw new Error(error);
  }
}

const didOanPurposes = (jsigs as { purposes: { AssertionProofPurpose: new () => unknown } }).purposes;

function didOanDefaultDocumentLoader(url: string) {
  if (url === "https://www.w3.org/ns/did/v1") {
    return {
      contextUrl: null,
      documentUrl: url,
      document: {
        "@context": {
          id: "@id",
          type: "@type",
          controller: "https://w3id.org/security#controller",
          verificationMethod: "https://w3id.org/security#verificationMethod",
          authentication: "https://w3id.org/security#authenticationMethod",
          assertionMethod: "https://w3id.org/security#assertionMethod",
          capabilityInvocation: "https://w3id.org/security#capabilityInvocationMethod",
          service: "https://www.w3.org/ns/did#service",
          serviceEndpoint: "https://www.w3.org/ns/did#serviceEndpoint",
        },
      },
    };
  }
  if (url === "https://openagenet.xyz/did-oan-specs/v1") {
    return {
      contextUrl: null,
      documentUrl: url,
      document: {
        "@context": {
          "@vocab": "https://openagenet.xyz/did-oan-specs#",
          oanMetadata: "https://openagenet.xyz/did-oan-specs#oanMetadata",
        },
      },
    };
  }
  return ed25519DocumentLoader(url);
}

function didOanPublicKeyMultibase(jwk: DidOanJwk): string {
  return `z${base58Encode(new Uint8Array([0xed, 0x01, ...base64urlDecode(jwk.x)]))}`;
}

function didOanPrivateKeyMultibase(jwk: DidOanJwk): string {
  return `z${base58Encode(new Uint8Array([
    0x80,
    0x26,
    ...base64urlDecode(jwk.d as string),
    ...base64urlDecode(jwk.x),
  ]))}`;
}

async function didOanKeyFromJwk(
  did: string,
  jwk: DidOanJwk,
  includePrivate: boolean,
) {
  return Ed25519VerificationKey2020.from({
    id: `${did}#key-1`,
    controller: did,
    publicKeyMultibase: didOanPublicKeyMultibase(jwk),
    ...(includePrivate ? { privateKeyMultibase: didOanPrivateKeyMultibase(jwk) } : {}),
  });
}

export async function signDidOanDataIntegrity(
  document: Record<string, unknown>,
  did: string,
  privateKeyJwk: unknown,
  options: DidOanDataIntegrityOptions = {},
): Promise<Record<string, unknown>> {
  const privateJwk = parseDidOanJwk(privateKeyJwk, true);
  const key = await didOanKeyFromJwk(did, privateJwk, true);
  const purpose = new didOanPurposes.AssertionProofPurpose();
  const signed = await (jsigs as any).sign(document, {
    suite: new Ed25519Signature2020({
      key,
      ...(options.created ? { proof: { created: options.created } } : {}),
    }),
    purpose,
    documentLoader: options.documentLoader ?? didOanDefaultDocumentLoader,
  });
  const proof = Array.isArray(signed.proof) ? signed.proof[0] : signed.proof;
  parseDidOanDataIntegrityProof(proof);
  return { ...signed, proof } as Record<string, unknown>;
}

export async function verifyDidOanDataIntegrity(
  document: Record<string, unknown>,
  publicKeyJwk: unknown,
  options: DidOanDataIntegrityOptions = {},
): Promise<void> {
  const publicJwk = parseDidOanJwk(publicKeyJwk);
  const proof = parseDidOanDataIntegrityProof(document.proof);
  const did = proof.verificationMethod.slice(0, -"#key-1".length);
  const key = await didOanKeyFromJwk(did, publicJwk, false);
  const result = await (jsigs as any).verify(document, {
    suite: new Ed25519Signature2020({ key }),
    purpose: new didOanPurposes.AssertionProofPurpose(),
    documentLoader: options.documentLoader ?? didOanDefaultDocumentLoader,
  });
  if (!result.verified) {
    throw result.error ?? new Error("oan_profile_data_integrity_verification_failed");
  }
}

export interface DidOanDocument {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://openagenet.xyz/did-oan-specs/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ];
  id: string;
  controller?: string | string[];
  verificationMethod: DidOanVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  capabilityInvocation?: string[];
  service?: unknown[];
  proof: DidOanDataIntegrityProof;
  oanMetadata?: Record<string, unknown>;
}

export function parseDidOanJwk(value: unknown, privateKey = false): DidOanJwk {
  if (!value || typeof value !== "object") {
    throw new Error("invalid_oan_profile_jwk");
  }
  const jwk = value as Record<string, unknown>;
  rejectDidOanUnknownFields(jwk, ["kty", "crv", "x", "d", "alg"], "legacy_jwk_field");
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    (privateKey ? typeof jwk.d !== "string" : jwk.d !== undefined) ||
    (jwk.alg !== undefined && jwk.alg !== "EdDSA")
  ) {
    throw new Error("invalid_oan_profile_jwk");
  }
  decodeDidOanBase64Url(jwk.x, 32);
  if (privateKey) decodeDidOanBase64Url(jwk.d as string, 32);
  return jwk as unknown as DidOanJwk;
}

export function parseDidOanDataIntegrityProof(value: unknown): DidOanDataIntegrityProof {
  if (!value || typeof value !== "object") {
    throw new Error("invalid_oan_profile_proof");
  }
  const proof = value as Record<string, unknown>;
  rejectDidOanUnknownFields(
    proof,
    ["type", "created", "proofPurpose", "proofValue", "verificationMethod"],
    "legacy_proof_field",
  );
  const keys = Object.keys(proof);
  if (keys.some((key) => ["creator", "cryptoSuite", "hashAlgorithm"].includes(key))) {
    throw new Error("legacy_proof_field");
  }
  if (
    proof.type !== "Ed25519Signature2020" ||
    proof.proofPurpose !== "assertionMethod" ||
    typeof proof.created !== "string" ||
    typeof proof.verificationMethod !== "string" ||
    !/^.+#key-1$/.test(proof.verificationMethod) ||
    typeof proof.proofValue !== "string" ||
    !proof.proofValue.startsWith("z") ||
    decodeDidOanBase58(proof.proofValue.slice(1), 64).length !== 64
  ) {
    throw new Error(`invalid_oan_profile_proof:${JSON.stringify(proof)}`);
  }
  return proof as unknown as DidOanDataIntegrityProof;
}

export function parseDidOanDocument(value: unknown): DidOanDocument {
  if (!value || typeof value !== "object") {
    throw new Error("invalid_oan_profile_did_document");
  }
  const document = value as Record<string, unknown>;
  rejectDidOanUnknownFields(
    document,
    [
      "@context",
      "id",
      "controller",
      "verificationMethod",
      "authentication",
      "assertionMethod",
      "capabilityInvocation",
      "service",
      "proof",
      "oanMetadata",
    ],
    "legacy_did_document_field",
  );
  const contexts = document["@context"];
  if (
    !Array.isArray(contexts) ||
    contexts.length !== 3 ||
    contexts[0] !== "https://www.w3.org/ns/did/v1" ||
    contexts[1] !== "https://openagenet.xyz/did-oan-specs/v1" ||
    contexts[2] !== "https://w3id.org/security/suites/ed25519-2020/v1"
  ) {
    throw new Error("invalid_oan_profile_context");
  }
  if (
    typeof document.id !== "string" ||
    !/^did:oan:[1-9A-HJ-NP-Za-km-z]{5}:[1-9A-HJ-NP-Za-km-z]{32}$/.test(document.id)
  ) {
    throw new Error("invalid_oan_profile_did");
  }
  const methods = document.verificationMethod;
  if (!Array.isArray(methods)) {
    throw new Error("invalid_oan_profile_verification_method");
  }
  const keyId = `${document.id}#key-1`;
  const key = methods.find((method) => (method as Record<string, unknown>)?.id === keyId) as
    | Record<string, unknown>
    | undefined;
  if (
    !key ||
    key.type !== "Ed25519VerificationKey2020" ||
    key.controller !== document.id ||
    (key.publicKeyMultibase === undefined && key.publicKeyJwk === undefined)
  ) {
    throw new Error("invalid_oan_profile_verification_method");
  }
  rejectDidOanUnknownFields(
    key,
    ["id", "type", "controller", "publicKeyMultibase", "publicKeyJwk"],
    "legacy_verification_method_field",
  );
  if ("cryptoSuite" in key || "publicKeyFormat" in key || "privateKeyMultibase" in key) {
    throw new Error("legacy_verification_method_field");
  }
  let multibaseKey: Uint8Array | undefined;
  if (key.publicKeyMultibase !== undefined) {
    if (typeof key.publicKeyMultibase !== "string" || !key.publicKeyMultibase.startsWith("z")) {
      throw new Error("invalid_oan_profile_verification_method");
    }
    try {
      multibaseKey = decodeDidOanBase58(key.publicKeyMultibase.slice(1), 34);
      if (multibaseKey[0] !== 0xed || multibaseKey[1] !== 0x01) {
        throw new Error("invalid_oan_profile_verification_method");
      }
    } catch {
      throw new Error("invalid_oan_profile_verification_method");
    }
  }
  if (key.publicKeyJwk !== undefined) {
    const jwk = parseDidOanJwk(key.publicKeyJwk);
    if (multibaseKey) {
      const jwkBytes = decodeDidOanBase64Url(jwk.x, 32);
      const multibasePublicKey = multibaseKey.slice(2);
      if (
        jwkBytes.length !== multibasePublicKey.length ||
        jwkBytes.some((value, index) => value !== multibasePublicKey[index])
      ) {
        throw new Error("invalid_oan_profile_verification_method");
      }
    }
  }
  for (const relationship of ["authentication", "assertionMethod"]) {
    const values = document[relationship];
    if (!Array.isArray(values) || !values.includes(keyId)) {
      throw new Error("invalid_oan_profile_relationship");
    }
  }
  const proof = parseDidOanDataIntegrityProof(document.proof);
  if (proof.verificationMethod !== keyId) {
    throw new Error("invalid_oan_profile_proof");
  }
  return document as unknown as DidOanDocument;
}

export function parseDidOanVerifiableCredential(
  value: unknown,
): DidOanVerifiableCredential {
  if (!value || typeof value !== "object") {
    throw new Error("invalid_oan_profile_credential");
  }
  const credential = value as Record<string, unknown>;
  rejectDidOanUnknownFields(
    credential,
    [
      "id",
      "@context",
      "type",
      "issuer",
      "issuanceDate",
      "expirationDate",
      "credentialSubject",
      "credentialStatus",
      "credentialSchema",
      "proof",
    ],
    "legacy_oan_profile_credential_field",
  );
  const contexts = credential["@context"];
  if (
    !Array.isArray(contexts) ||
    contexts.length !== 3 ||
    contexts[0] !== "https://www.w3.org/2018/credentials/v1" ||
    contexts[1] !== "https://openagenet.xyz/did-oan-specs/v1" ||
    contexts[2] !== "https://w3id.org/security/suites/ed25519-2020/v1"
  ) {
    throw new Error("invalid_oan_profile_credential_context");
  }
  if (
    !Array.isArray(credential.type) ||
    !credential.type.includes("VerifiableCredential") ||
    typeof credential.issuer !== "string" ||
    !/^did:oan:[1-9A-HJ-NP-Za-km-z]{5}:[1-9A-HJ-NP-Za-km-z]{32}$/.test(
      credential.issuer,
    ) ||
    typeof credential.issuanceDate !== "string" ||
    !credential.credentialSubject ||
    typeof credential.credentialSubject !== "object"
  ) {
    throw new Error("invalid_oan_profile_credential");
  }
  const proof = parseDidOanDataIntegrityProof(credential.proof);
  if (proof.verificationMethod !== `${credential.issuer}#key-1`) {
    throw new Error("invalid_oan_profile_credential_proof");
  }
  return credential as unknown as DidOanVerifiableCredential;
}

export interface DidOanIdentity {
  id: string;
  createdAt: string;
  did: string;
  verificationMethodId: string;
  didDocument: DidOanDocument;
  publicKeyJwk: DidOanJwk;
  privateKeyJwk: DidOanJwk;
}

const OAN_BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function decodeDidOanBase58(value: string, expectedLength: number): Uint8Array {
  if (!value || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(value)) {
    throw new Error("invalid_oan_profile_multibase");
  }
  const bytes: number[] = [];
  for (const character of value) {
    const digit = OAN_BASE58_ALPHABET.indexOf(character);
    if (digit < 0) {
      throw new Error("invalid_oan_profile_multibase");
    }
    let carry = digit;
    for (let index = 0; index < bytes.length; index += 1) {
      carry += bytes[index] * 58;
      bytes[index] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let index = 0; index < value.length && value[index] === "1"; index += 1) {
    bytes.push(0);
  }
  const decoded = Uint8Array.from(bytes.reverse());
  if (decoded.length !== expectedLength) {
    throw new Error("invalid_oan_profile_multibase");
  }
  return decoded;
}

function decodeDidOanBase64Url(value: string, expectedLength: number): Uint8Array {
  const expectedLengthInChars = Math.ceil((expectedLength * 8) / 6);
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length !== expectedLengthInChars) {
    throw new Error("invalid_oan_profile_jwk");
  }
  const unusedBits = (value.length * 6) % 8;
  if (unusedBits !== 0) {
    const last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(
      value[value.length - 1],
    );
    if (last < 0 || (last & ((1 << unusedBits) - 1)) !== 0) {
      throw new Error("invalid_oan_profile_jwk");
    }
  }
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of value) {
    buffer = (buffer << 6) | alphabet.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  if (bytes.length !== expectedLength) {
    throw new Error("invalid_oan_profile_jwk");
  }
  return Uint8Array.from(bytes);
}

export function parseDidOanIdentity(value: unknown): DidOanIdentity {
  if (!value || typeof value !== "object") {
    throw new Error("invalid_oan_profile_identity");
  }
  const identity = value as Record<string, unknown>;
  rejectDidOanUnknownFields(
    identity,
    [
      "id",
      "createdAt",
      "did",
      "verificationMethodId",
      "didDocument",
      "publicKeyJwk",
      "privateKeyJwk",
    ],
    "legacy_oan_profile_identity_field",
  );
  if (
    typeof identity.id !== "string" ||
    typeof identity.createdAt !== "string" ||
    typeof identity.did !== "string" ||
    identity.verificationMethodId !== `${identity.did}#key-1`
  ) {
    throw new Error("invalid_oan_profile_identity");
  }
  const didDocument = parseDidOanDocument(identity.didDocument);
  if (didDocument.id !== identity.did) {
    throw new Error("invalid_oan_profile_identity");
  }
  const publicKeyJwk = parseDidOanJwk(identity.publicKeyJwk);
  const privateKeyJwk = parseDidOanJwk(identity.privateKeyJwk, true);
  const method = didDocument.verificationMethod.find(
    (entry) => entry.id === identity.verificationMethodId,
  );
  if (!method) {
    throw new Error("invalid_oan_profile_identity");
  }
  if (method.publicKeyJwk !== undefined) {
    if (JSON.stringify(method.publicKeyJwk) !== JSON.stringify(publicKeyJwk)) {
      throw new Error("invalid_oan_profile_identity");
    }
  } else if (method.publicKeyMultibase !== undefined) {
    try {
      const methodKey = decodeDidOanBase58(method.publicKeyMultibase.slice(1), 34);
      const identityKey = decodeDidOanBase64Url(publicKeyJwk.x, 32);
      if (
        methodKey[0] !== 0xed ||
        methodKey[1] !== 0x01 ||
        methodKey.slice(2).some((value, index) => value !== identityKey[index])
      ) {
        throw new Error("invalid_oan_profile_identity");
      }
    } catch {
      throw new Error("invalid_oan_profile_identity");
    }
  } else {
    throw new Error("invalid_oan_profile_identity");
  }
  if (privateKeyJwk.x !== publicKeyJwk.x) {
    throw new Error("invalid_oan_profile_identity");
  }
  return identity as unknown as DidOanIdentity;
}

export async function validateDidOanIdentityKeyPair(
  identity: DidOanIdentity,
): Promise<void> {
  const privateKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    identity.privateKeyJwk as JsonWebKey,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const publicKey = await globalThis.crypto.subtle.importKey(
    "jwk",
    identity.publicKeyJwk as JsonWebKey,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const challenge = new TextEncoder().encode("oan-identity-key-pair");
  const signature = await globalThis.crypto.subtle.sign("Ed25519", privateKey, challenge);
  const valid = await globalThis.crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signature,
    challenge,
  );
  if (!valid) {
    throw new Error("invalid_oan_profile_identity");
  }
}

export type OanCredentialType =
  | "OANInfrastructureAuthorizationCredential"
  | "OANResourceRegistrationCredential"
  | "OANBusinessFactCredential"
  | "OANQualificationCredential"
  | "OANAuditResultCredential"
  | "OANSelfClaimedCapabilityCredential";

export type OanCredentialStatusValue = "active" | "suspended" | "revoked" | "expired" | "unknown";

export interface OanCredentialStatusReference {
  id: string;
  type: string;
  credentialId?: string;
  subjectDid?: string;
  issuerDid?: string;
  status?: OanCredentialStatusValue;
  sequence?: number;
  eventDigest?: string;
  updatedAt?: string;
  [key: string]: unknown;
}

export interface OanInfrastructureAuthorizationCredentialSubject {
  id: string;
  role: "root" | "registrar" | "discovery" | "vc_issuer";
  subjectType: "infrastructure_node";
  resourceType: "root_node" | "registrar_node" | "discovery_node" | "vc_issuer_node";
  endpoint?: string;
  authorizedDomains: string[];
  didDocumentHash: string;
}

export interface OanResourceRegistrationCredentialSubject {
  id: string;
  resourceType: ResourceType;
  subjectType: SubjectType;
  registrarDid: string;
  didDocumentHash: string;
  metadataHash: string;
  packageHash: string;
  packageVersion: string;
  hashAlgorithm: string;
  authorizedDomains: string[];
  externalIdentifiers: Array<{ id: string }>;
  lifecycleState: string;
}

export interface OanBusinessFactCredentialSubject {
  id: string;
  subjectType: string;
  factType: string;
  claim: Record<string, unknown>;
}

export interface OanQualificationCredentialSubject {
  id: string;
  subjectType: string;
  qualificationType: string;
  qualification: Record<string, unknown>;
}

export interface OanAuditResultCredentialSubject {
  id: string;
  subjectType: string;
  auditType: string;
  result: Record<string, unknown>;
  auditedAt: string;
}

export interface OanSelfClaimedCapabilityCredentialSubject {
  id: string;
  capability: string;
  claim: Record<string, unknown>;
}

export interface OanVerifiableCredential {
  "@context": string | string[];
  id?: string;
  type: ["VerifiableCredential", OanCredentialType];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: Record<string, unknown>;
  credentialStatus?: OanCredentialStatusReference;
  credentialSchema?: { id: string; type: string; [key: string]: unknown };
  proof: DataIntegrityProof;
  [key: string]: unknown;
}

export interface OanIdentity {
  id: string;
  createdAt: string;
  did: string;
  verificationMethodId: string;
  didDocument: DidDocument;
  publicKeyJwk: Record<string, unknown>;
  privateKeyJwk: Record<string, unknown>;
}

export interface ExternalIdentifier {
  id: string;
  resolutionServiceEndpoint?: string;
}

export interface DidControlChallenge {
  challengeId: string;
  draftId: string;
  subjectDid: string;
  didDocumentHash: string;
  registrarDid: string;
  purpose: string;
  verificationMethod: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SubjectControlProofBundle {
  challenge: DidControlChallenge;
  proof: DataIntegrityProof;
  verifiedAt?: string;
  verifiedVerificationMethod?: string;
  proofHash?: string;
}

export interface ControllerAuthorizationChallenge {
  challengeId: string;
  resourceDid: string;
  controllerDid: string;
  publisherDid?: string;
  didDocumentHash: string;
  metadataHash: string;
  registrarDid: string;
  purpose: "resource-registration-controller-authorization" | string;
  verificationMethod: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface ControllerAuthorizationProofBundle {
  challenge: ControllerAuthorizationChallenge;
  controllerDidDocument: DidDocument;
  proof: DataIntegrityProof;
}

export interface ResourceMetadata {
  resourceDid: string;
  resourceType: ResourceType;
  subjectType: SubjectType;
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
  didDocumentHash?: string;
  metadata?: unknown;
  packageVersion: string;
  metadataHash: string;
  packageHash: string;
  hashAlgorithm: string;
  registrationCredential?: unknown;
  subjectControlProof?: SubjectControlProofBundle;
  controllerAuthorizationProof?: ControllerAuthorizationProofBundle;
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

export interface RegistrarResourceListResponse {
  items: Array<Record<string, unknown>>;
  count: number;
  afterDid: string | null;
  nextDid: string | null;
  hasMore: boolean;
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

export interface ResourceCdnIndexItem {
  cursor: number;
  package: ResourcePackage;
}

export interface ResourceCdnIndexResponse {
  items: ResourceCdnIndexItem[];
  count: number;
  afterCursor: number;
  nextCursor: number;
  hasMore: boolean;
}

export interface DiscoveryIndexResourceListResponse {
  items: Array<Record<string, unknown>>;
  count: number;
  afterCursor: number;
  afterResourceDid?: string | null;
  nextCursor: number;
  nextResourceDid?: string | null;
  hasMore: boolean;
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
