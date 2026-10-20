// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import {
  createEmptyIdentityStoreSnapshot,
  normalizeIdentityJwk,
  upsertIdentityRecord,
  validateOanIdentityRecord,
  type OanIdentityRecord,
  type OanIdentityStoreSnapshot,
} from "./identity.js";
import { didOanDefaultDocumentLoader, verifyDidOanDataIntegrity, type DidDocument, type ResourceType } from "../../protocol-types/src/index.js";

/** The existing on-disk format. Local profile/index data is reconstructed on import. */
export type OanIdentityFile = Pick<OanIdentityRecord,
  "id" | "createdAt" | "did" | "verificationMethodId" | "didDocument" | "privateKeyJwk" | "publicKeyJwk">;

export function exportIdentityFile(record: OanIdentityRecord): string {
  validateOanIdentityRecord(record);
  const { id, createdAt, did, verificationMethodId, didDocument } = record;
  return JSON.stringify({ id, createdAt, did, verificationMethodId, didDocument,
    privateKeyJwk: normalizeIdentityJwk(record.privateKeyJwk),
    publicKeyJwk: normalizeIdentityJwk(record.publicKeyJwk),
  } satisfies OanIdentityFile, null, 2);
}

/** Accept a Node identity.json, a complete record, or a browser identity bundle. */
export function importIdentityMaterials(serialized: string): OanIdentityStoreSnapshot {
  const value = JSON.parse(serialized);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("unsupported_identity_format");
  if ("version" in value || "subjects" in value || "agents" in value || "nodes" in value) {
    if (value.version !== 1) throw new Error("unsupported_identity_bundle_version");
    const snapshot = structuredClone(value) as OanIdentityStoreSnapshot;
    const seenIds = new Set<string>();
    const seenDids = new Set<string>();
    for (const [bucket, kind] of [["subjects", "subject"], ["agents", "agent"], ["nodes", "node"]] as const) {
      if (!Array.isArray(snapshot[bucket])) throw new Error("invalid_identity_bundle_bucket");
      snapshot[bucket] = snapshot[bucket].map((item) => {
        const record = importIdentityRecord(item);
        if (record.kind !== kind) throw new Error("identity_bundle_kind_mismatch");
        if (seenIds.has(record.id) || seenDids.has(record.did)) throw new Error("duplicate_identity_in_bundle");
        seenIds.add(record.id); seenDids.add(record.did);
        return record;
      });
    }
    if (snapshot.defaultSubjectId && !snapshot.subjects.some(r => r.id === snapshot.defaultSubjectId)) throw new Error("identity_bundle_default_missing");
    if (snapshot.defaultAgentId && !snapshot.agents.some(r => r.id === snapshot.defaultAgentId)) throw new Error("identity_bundle_default_missing");
    return snapshot;
  }
  return upsertIdentityRecord(createEmptyIdentityStoreSnapshot(), importIdentityRecord(value));
}

function importIdentityRecord(value: unknown): OanIdentityRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("unsupported_identity_format");
  const raw = structuredClone(value) as Partial<OanIdentityRecord>;
  const document = raw.didDocument as DidDocument | undefined;
  if (!raw.did || !document || document.id !== raw.did) throw new Error("identity_did_document_mismatch");
  if (!raw.privateKeyJwk || typeof raw.privateKeyJwk.d !== "string") throw new Error("identity_private_key_required");
  if (!raw.publicKeyJwk || typeof raw.publicKeyJwk.x !== "string") throw new Error("identity_public_key_required");
  const resourceType = document.oanMetadata?.resourceType ?? raw.profile?.resourceType ?? "unspecified";
  if (raw.profile?.resourceType && document.oanMetadata?.resourceType && raw.profile.resourceType !== document.oanMetadata.resourceType) throw new Error("identity_resource_type_mismatch");
  const kind = raw.kind ?? (resourceType === "infrastructure_node" ? "node" : ["controller", "developer", "organization"].includes(resourceType) ? "subject" : "agent");
  if (!["subject", "agent", "node"].includes(kind)) throw new Error("identity_kind_invalid");
  const record: OanIdentityRecord = {
    ...raw,
    id: raw.id ?? `${kind}-${raw.did}`,
    createdAt: raw.createdAt ?? (typeof document.created === "string" ? document.created : new Date().toISOString()),
    did: raw.did,
    verificationMethodId: raw.verificationMethodId ?? document.verificationMethod?.[0]?.id ?? "",
    didDocument: document,
    privateKeyJwk: normalizeIdentityJwk(raw.privateKeyJwk),
    publicKeyJwk: normalizeIdentityJwk(raw.publicKeyJwk),
    kind,
    profile: {
      ...raw.profile,
      label: raw.profile?.label ?? document.oanMetadata?.resourceDescription?.name ?? raw.did,
      resourceType: resourceType as ResourceType,
      ownerSubjectDid: raw.profile ? raw.profile.ownerSubjectDid : document.oanMetadata?.controllerDid,
      authorizedDomains: raw.profile?.authorizedDomains ?? document.oanMetadata?.authorizedDomains,
      capabilityTags: raw.profile?.capabilityTags ?? document.oanMetadata?.capabilityTags,
    },
  };
  if (record.privateKeyJwk.kty !== "OKP" || record.privateKeyJwk.crv !== "Ed25519" || record.publicKeyJwk.kty !== "OKP" || record.publicKeyJwk.crv !== "Ed25519") throw new Error("identity_key_algorithm_unsupported");
  if (record.privateKeyJwk.x !== record.publicKeyJwk.x) throw new Error("identity_private_public_key_mismatch");
  validateOanIdentityRecord(record);
  return record;
}

/** Check the actual private/public key pair locally before enabling signing. */
export async function validateIdentitySigningKey(record: OanIdentityRecord): Promise<void> {
  validateOanIdentityRecord(record);
  const privateKey = await crypto.subtle.importKey("jwk", normalizeIdentityJwk(record.privateKeyJwk), "Ed25519", false, ["sign"]);
  const publicKey = await crypto.subtle.importKey("jwk", normalizeIdentityJwk(record.publicKeyJwk), "Ed25519", false, ["verify"]);
  const message = new TextEncoder().encode("OAN local identity key consistency check");
  const signature = await crypto.subtle.sign("Ed25519", privateKey, message);
  if (!await crypto.subtle.verify("Ed25519", publicKey, signature, message)) throw new Error("identity_private_public_key_mismatch");
  if (record.didDocument.proof) {
    await verifyDidOanDataIntegrity(record.didDocument, record.publicKeyJwk, {
      documentLoader: async url => url === record.did
        ? { contextUrl: null, documentUrl: url, document: record.didDocument }
        : didOanDefaultDocumentLoader(url),
    });
  }
}
