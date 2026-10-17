// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { verifyDidOanDataIntegrity, type DidDocument, type DidOanDocumentLoader, type IdentityVerificationReport } from "../../protocol-types/src/index.js";

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
