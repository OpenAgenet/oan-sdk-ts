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

export interface IdentityEvidenceInput {
  expectedDid: string;
  didDocument: DidDocument;
  resourcePackage?: ResourcePackage;
  registrationVc?: unknown;
}

/** Trust configuration belongs to the local host, never to peer/tool input. */
export interface IdentityEvidencePolicy {
  anchor: PinnedRootAnchor;
  observedAt: string;
  maxAgeMs: number;
  now?: number;
  requirePrivateVc?: boolean;
  registrar?: { did: string; verificationMethod: string; publicKeyJwk: Record<string, unknown>; documentLoader?: DidOanDocumentLoader; proofProfile?: "registrar-canonical-v1" | "data-integrity" };
}

/** L1 report: a pinned Root snapshot is not live governance or controller consent.
 * Optional private credentials are never returned in the report.
 */
export async function verifyIdentityEvidence(input: IdentityEvidenceInput, policy: IdentityEvidencePolicy): Promise<IdentityVerificationReport> {
  try { return await inspectIdentityEvidence(input, policy); }
  catch { return {valid:false,checks:[{name:'registrationTrust',status:'failed',code:'invalid_identity_evidence'}]}; }
}

async function inspectIdentityEvidence(input: IdentityEvidenceInput, policy: IdentityEvidencePolicy): Promise<IdentityVerificationReport> {
  const checks: IdentityVerificationReport['checks'] = [];
  const add = (name: string, status: 'passed' | 'failed' | 'not_checked', code?: string) => checks.push({ name, status, ...(code ? {code} : {}) });
  if (!input || !input.didDocument || typeof input.didDocument !== 'object' || Array.isArray(input.didDocument)
    || typeof input.expectedDid !== 'string' || !input.expectedDid) {
    return {valid:false,checks:[{name:'documentSignature',status:'failed',code:'invalid_identity_evidence'},
      ...['documentBinding','registrationTrust','freshness','registrationStatus','privateVc','governance','controllerBinding','instanceBinding','liveRevocation'].map(name=>({name,status:'not_checked' as const}))]};
  }
  const document = structuredClone(input.didDocument);
  const method = Array.isArray(document?.verificationMethod) ? document.verificationMethod.find(m => m?.id === `${input.expectedDid}#key-1`) : undefined;
  const loader: DidOanDocumentLoader = async url => url === input.expectedDid
    ? { contextUrl: null, documentUrl: url, document } : didOanDefaultDocumentLoader(url);
  if (method?.controller === input.expectedDid && method.publicKeyJwk && !method.publicKeyJwk.d
    && document.proof?.verificationMethod === method.id
    && Array.isArray(document.authentication) && document.authentication.includes(method.id)
    && Array.isArray(document.assertionMethod) && document.assertionMethod.includes(method.id)) {
    const proof = await verifyPinnedDidDocument(document, {expectedDid: input.expectedDid, publicKeyJwk: method.publicKeyJwk, documentLoader: loader});
    add('documentSignature', proof.valid ? 'passed' : 'failed', proof.valid ? undefined : 'document_verification_failed');
  } else add('documentSignature', 'failed', 'resource_key_relationship_invalid');
  if (!input.resourcePackage) {
    add('documentBinding', 'not_checked', 'resource_package_missing');
    add('registrationTrust', 'not_checked', 'resource_package_missing');
    add('freshness', 'not_checked');
    add('registrationStatus', 'not_checked');
  } else {
    const pkg = input.resourcePackage;
    const bound = document.id === input.expectedDid && pkg.resourceDid === input.expectedDid
      && canonicalJson(document) === canonicalJson(pkg.didDocument);
    add('documentBinding', bound ? 'passed' : 'failed', bound ? undefined : 'document_binding_mismatch');
    const observed = Date.parse(policy.observedAt), now = policy.now ?? Date.now();
    const fresh = Number.isFinite(observed) && Number.isFinite(policy.maxAgeMs) && policy.maxAgeMs > 0
      && observed <= now + 30000 && observed + policy.maxAgeMs > now;
    add('freshness', fresh ? 'passed' : 'failed', fresh ? undefined : 'evidence_freshness_unknown');
    const active = pkg.metadata?.lifecycleState === 'active';
    add('registrationStatus', active ? 'passed' : 'failed', active ? undefined : 'resource_lifecycle_not_active');
    try {
      if (!bound) throw new Error('document_binding_mismatch');
      await verifyPinnedRootPackage({...policy, resourcePackage: input.resourcePackage, expectedDid: input.expectedDid});
      add('registrationTrust', 'passed');
    } catch (error) {
      // Only known protocol codes are exposed; arbitrary loader/network errors may contain secrets.
      const known = new Set(['evidence_freshness_unknown','document_binding_mismatch','did_document_hash_mismatch','metadata_hash_mismatch','package_hash_mismatch','root_claim_signature_invalid','root_proof_binding_mismatch','resource_lifecycle_not_active','resource_package_binding_mismatch','resource_key_relationship_invalid']);
      const code = error instanceof Error && known.has(error.message) ? error.message : 'registration_evidence_invalid';
      add('registrationTrust', 'failed', code);
    }
  }
  if (input.registrationVc !== undefined && policy.registrar) {
    try {
      const vc = structuredClone(input.registrationVc) as Record<string, any>;
      const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id;
      const subject = vc.credentialSubject;
      const pkg = input.resourcePackage;
      if (!pkg || issuer !== policy.registrar.did || subject?.id !== input.expectedDid
        || subject.registrarDid !== policy.registrar.did || vc.proof?.verificationMethod !== policy.registrar.verificationMethod
        || vc.proof?.proofPurpose !== 'assertionMethod'
        || !Array.isArray(vc.type) || !vc.type.includes('OANResourceRegistrationCredential')
        || subject.packageVersion !== pkg.packageVersion || subject.didDocumentHash !== pkg.didDocumentHash
        || subject.metadataHash !== pkg.metadataHash || subject.packageHash !== pkg.packageHash) throw new Error();
      const now = policy.now ?? Date.now();
      if (!Number.isFinite(Date.parse(vc.issuanceDate)) || Date.parse(vc.issuanceDate) > now + 30000
        || (vc.expirationDate && (!Number.isFinite(Date.parse(vc.expirationDate)) || Date.parse(vc.expirationDate) <= now))) throw new Error();
      if (policy.registrar.proofProfile === 'data-integrity') {
        await verifyDidOanDataIntegrity(vc, policy.registrar.publicKeyJwk, {documentLoader: policy.registrar.documentLoader});
      } else {
        // Current Registrar sign_credential signs canonical unsigned JSON (not a JSON-LD proof).
        const unsigned = structuredClone(vc); delete unsigned.proof;
        const jwk = policy.registrar.publicKeyJwk as JsonWebKey;
        if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || jwk.d || vc.proof?.type !== 'Ed25519Signature2020'
          || typeof vc.proof?.proofValue !== 'string' || !vc.proof.proofValue.startsWith('z')) throw new Error();
        const key = await crypto.subtle.importKey('jwk', jwk, {name:'Ed25519'}, false, ['verify']);
        if (!await crypto.subtle.verify('Ed25519', key, new Uint8Array(base58Decode(vc.proof.proofValue.slice(1))),
          new TextEncoder().encode(canonicalJson(unsigned)))) throw new Error();
      }
      add('privateVc', 'passed');
    } catch { add('privateVc', 'failed', 'registration_vc_invalid'); }
  } else add('privateVc', 'not_checked', input.registrationVc === undefined ? 'not_supplied' : 'trusted_registrar_required');
  for (const name of ['governance', 'controllerBinding', 'instanceBinding', 'liveRevocation']) add(name, 'not_checked');
  const required = ['documentSignature','documentBinding','registrationTrust','freshness','registrationStatus', ...(policy.requirePrivateVc ? ['privateVc'] : [])];
  return {valid: !checks.some(c => c.status === 'failed') && required.every(name => checks.some(c => c.name === name && c.status === 'passed')), checks};
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
  if (!pkg || pkg.resourceDid !== expectedDid || pkg.didDocument?.id !== expectedDid || typeof pkg.hashAlgorithm !== 'string' || pkg.hashAlgorithm.toLowerCase() !== "sha256") throw new Error("resource_package_binding_mismatch");
  verifyResourcePackageShape(pkg);
  if (pkg.metadata.lifecycleState !== "active") throw new Error("resource_lifecycle_not_active");
  const hash = async (value: unknown) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)))), b => b.toString(16).padStart(2,"0")).join("");
  const matches = (expected: string, actual: string) => expected === actual || expected === `sha256:${actual}`;
  if (!matches(pkg.didDocumentHash, await hashDidDocumentWithProof(pkg.didDocument))) throw new Error("did_document_hash_mismatch");
  if (!matches(pkg.metadataHash, await hash({...pkg.metadata, metadataHash:"", packageHash:""}))) throw new Error("metadata_hash_mismatch");
  if (!matches(pkg.packageHash, await hashRegistrationPackageBinding(pkg))) throw new Error("package_hash_mismatch");
  const root = pkg.rootProof, proof = root?.proof;
  if (root?.rootDid !== anchor.rootDid || anchor.verificationMethod !== anchor.rootDid+'#key-1' || !proof || proof.verificationMethod !== anchor.verificationMethod || proof.creator !== anchor.verificationMethod || proof.proofPurpose !== 'assertionMethod' || proof.type !== 'Ed25519Signature2020' || proof.cryptoSuite !== 'ed25519-sha256' || proof.hashAlgorithm !== 'sha256' || typeof proof.proofValue !== 'string' || !proof.proofValue.startsWith('z')) throw new Error("root_proof_binding_mismatch");
  if (anchor.publicKeyJwk.kty !== 'OKP' || anchor.publicKeyJwk.crv !== 'Ed25519' || anchor.publicKeyJwk.d) throw new Error("invalid_root_public_key");
  const key = await crypto.subtle.importKey('jwk',anchor.publicKeyJwk,{name:'Ed25519'},false,['verify']);
  const signature = new Uint8Array(base58Decode(proof.proofValue.slice(1)));
  if (!await crypto.subtle.verify('Ed25519',key,signature,new TextEncoder().encode(canonicalJson(root.packageClaims)))) throw new Error("root_claim_signature_invalid");
  const methodId = `${expectedDid}#key-1`;
  const method = Array.isArray(pkg.didDocument.verificationMethod) ? pkg.didDocument.verificationMethod.find(m=>m?.id===methodId) : undefined;
  if (!method || method.controller !== expectedDid || pkg.didDocument.proof?.verificationMethod !== methodId || !Array.isArray(pkg.didDocument.authentication) || !pkg.didDocument.authentication.includes(methodId) || !Array.isArray(pkg.didDocument.assertionMethod) || !pkg.didDocument.assertionMethod.includes(methodId) || method.publicKeyJwk?.kty !== 'OKP' || method.publicKeyJwk?.crv !== 'Ed25519' || method.publicKeyJwk?.d) throw new Error("resource_key_relationship_invalid");
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
