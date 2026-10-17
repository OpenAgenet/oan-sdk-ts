// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { didOanDefaultDocumentLoader, verifyDidOanDataIntegrity, type DidDocument, type DidOanDocumentLoader, type IdentityVerificationReport } from "../../protocol-types/src/index.js";
import type { ResourcePackage } from "../../protocol-types/src/index.js";
import { decode as base58Decode } from "base58-universal";
import { canonicalJson, hashDidDocumentWithProof, hashRegistrationPackageBinding, verifyResourcePackageShape } from "./index.js";

export interface PinnedRootAnchor {
  rootDid: string;
  verificationMethod: string;
  publicKeyJwk: JsonWebKey;
}

/** Public package path: pinned Root claims authenticate the document/key binding.
 * This does not establish latest chain governance, private VC attributes or real-time revocation.
 * observedAt is supplied by the trusted fetch/cache host, never by the remote peer.
 */
export async function verifyPinnedRootPackage(input: {
  resourcePackage: ResourcePackage; expectedDid: string; anchor: PinnedRootAnchor;
  observedAt: string; maxAgeMs: number; now?: number;
}): Promise<{ document: DidDocument; verificationMethod: string; publicKeyJwk: JsonWebKey;
  packageHash: string; validUntil: number; checks: Record<string, string> }> {
  const { resourcePackage: supplied, expectedDid, anchor, observedAt, maxAgeMs } = input;
  const pkg = structuredClone(supplied);
  const now = input.now ?? Date.now(), observed = Date.parse(observedAt);
  if (!Number.isFinite(observed) || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0 || observed > now + 30000 || observed + maxAgeMs <= now) throw new Error("evidence_freshness_unknown");
  if (pkg.resourceDid !== expectedDid || pkg.didDocument.id !== expectedDid || pkg.hashAlgorithm.toLowerCase() !== "sha256") throw new Error("resource_package_binding_mismatch");
  verifyResourcePackageShape(pkg);
  if (pkg.metadata.lifecycleState !== "active") throw new Error("resource_lifecycle_not_active");
  const hash = async (value: unknown) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)))), b => b.toString(16).padStart(2,"0")).join("");
  const matches = (expected: string, actual: string) => expected === actual || expected === `sha256:${actual}`;
  if (!matches(pkg.didDocumentHash, await hashDidDocumentWithProof(pkg.didDocument))) throw new Error("did_document_hash_mismatch");
  if (!matches(pkg.metadataHash, await hash({...pkg.metadata, metadataHash:"", packageHash:""}))) throw new Error("metadata_hash_mismatch");
  if (!matches(pkg.packageHash, await hashRegistrationPackageBinding(pkg))) throw new Error("package_hash_mismatch");
  const root = pkg.rootProof, proof = root.proof;
  if (root.rootDid !== anchor.rootDid || anchor.verificationMethod !== anchor.rootDid+'#key-1' || !proof || proof.verificationMethod !== anchor.verificationMethod || proof.creator !== anchor.verificationMethod || proof.proofPurpose !== 'assertionMethod' || proof.type !== 'Ed25519Signature2020' || proof.cryptoSuite !== 'ed25519-sha256' || proof.hashAlgorithm !== 'sha256' || !proof.proofValue.startsWith('z')) throw new Error("root_proof_binding_mismatch");
  if (anchor.publicKeyJwk.kty !== 'OKP' || anchor.publicKeyJwk.crv !== 'Ed25519' || anchor.publicKeyJwk.d) throw new Error("invalid_root_public_key");
  const key = await crypto.subtle.importKey('jwk',anchor.publicKeyJwk,{name:'Ed25519'},false,['verify']);
  const signature = new Uint8Array(base58Decode(proof.proofValue.slice(1)));
  if (!await crypto.subtle.verify('Ed25519',key,signature,new TextEncoder().encode(canonicalJson(root.packageClaims)))) throw new Error("root_claim_signature_invalid");
  const methodId = `${expectedDid}#key-1`;
  const method = pkg.didDocument.verificationMethod?.find(m=>m.id===methodId);
  if (!method || method.controller !== expectedDid || !pkg.didDocument.authentication?.includes(methodId) || !pkg.didDocument.assertionMethod?.includes(methodId) || method.publicKeyJwk?.kty !== 'OKP' || method.publicKeyJwk?.crv !== 'Ed25519' || method.publicKeyJwk?.d) throw new Error("resource_key_relationship_invalid");
  await verifyDidOanDataIntegrity(pkg.didDocument as Record<string,unknown>,method.publicKeyJwk, {
    documentLoader: async url => url === expectedDid
      ? { contextUrl: null, documentUrl: url, document: pkg.didDocument }
      : didOanDefaultDocumentLoader(url),
  });
  return {document:pkg.didDocument,verificationMethod:methodId,publicKeyJwk:method.publicKeyJwk as JsonWebKey,packageHash:pkg.packageHash,validUntil:observed+maxAgeMs,
    checks:{signature:'valid',documentBinding:'valid',registrationEvidence:'valid',registrationStatus:'root_signed_snapshot_active',governance:'pinned_root_only',freshness:'bounded_snapshot',controllerBinding:'not_checked',instanceBinding:'not_applicable',privateVc:'not_required'}};
}

/** Verify document proof against a pinned public key. Registration trust is separate. */
export async function verifyPinnedDidDocument(
  document: DidDocument,
  options: { expectedDid: string; publicKeyJwk: Record<string, unknown>; documentLoader?: DidOanDocumentLoader },
): Promise<IdentityVerificationReport> {
  if (document.id !== options.expectedDid) {
    return { valid: false, checks: [{ name: "did_binding", status: "failed", code: "did_mismatch" }] };
  }
  try {
    await verifyDidOanDataIntegrity(document as Record<string, unknown>, options.publicKeyJwk, options);
    return { valid: true, checks: [
      { name: "document_proof", status: "passed" },
      { name: "registration_trust", status: "not_checked" },
    ] };
  } catch {
    return { valid: false, checks: [{ name: "document_proof", status: "failed", code: "document_verification_failed" }] };
  }
}
