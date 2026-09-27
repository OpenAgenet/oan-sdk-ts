// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { DidDocument, OanMetadata, ResourceRegistrationSubmission } from "../../protocol-types/src/index.js";
import { OanVerificationError } from "./index.js";

export const OAN_METHOD = "oan";
export const OAN_DID_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/oan/v1"] as const;
export const OAN_DID_ID_RE = /^[1-9A-HJ-NP-Za-km-z]{5}:[1-9A-HJ-NP-Za-km-z]{32}$/;

export interface DidOanParts {
  method: string;
  id: string;
  routingCode: string;
  suffixCode: string;
}

export function parseDidOan(value: string): DidOanParts {
  const segments = value.split(":");
  if (segments.length !== 4 || segments[0] !== "did" || segments[1] !== OAN_METHOD) {
    throw new OanVerificationError("did_method_mismatch");
  }
  const id = `${segments[2]}:${segments[3]}`;
  const normalizedId = normalizeDidOanId(id);
  if (!OAN_DID_ID_RE.test(normalizedId)) {
    throw new OanVerificationError("did_method_mismatch");
  }
  const [routingCode, suffixCode] = normalizedId.split(":");
  return {
    method: OAN_METHOD,
    id: normalizedId,
    routingCode,
    suffixCode,
  };
}

export function normalizeDidOanId(id: string): string {
  const segments = id.split(":");
  if (segments.length !== 2) {
    return id;
  }
  return `${segments[0]}:${segments[1]}`;
}

export function normalizeDidOan(value: string): string {
  const parsed = parseDidOan(value);
  return `did:${OAN_METHOD}:${parsed.id}`;
}

export function normalizeDidOanReference(value: string): string {
  const [did, fragment] = value.split("#", 2);
  const normalizedDid = normalizeDidOan(did ?? value);
  return fragment === undefined ? normalizedDid : `${normalizedDid}#${fragment}`;
}

export function hasDidOanSemanticConflict(
  value: string,
  metadata: Pick<DidDocument, "oanMetadata">["oanMetadata"] | undefined,
): boolean {
  if (!metadata) {
    return false;
  }
  parseDidOan(value);
  return false;
}

/** @deprecated Resource type is no longer encoded in the DID. */
export function inferResourceTypeFromDidOan(_value: string): undefined {
  return undefined;
}

export function getDefaultOanMetadataFromDidOan(
  value: string,
): Partial<Pick<OanMetadata, "subjectType" | "resourceType">> {
  parseDidOan(value);
  return {};
}

export function normalizeDidOanMaybe(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeDidOanMaybe(item));
  }
  if (typeof value !== "string") {
    return value;
  }
  try {
    return normalizeDidOanReference(value);
  } catch {
    return value;
  }
}

export function normalizeDidDocumentForOan(document: DidDocument): DidDocument {
  const normalizedId = normalizeDidOan(document.id);
  return {
    ...document,
    id: normalizedId,
    controller: normalizeDidOanMaybe(document.controller) as string | string[] | undefined,
    verificationMethod: Array.isArray(document.verificationMethod)
      ? document.verificationMethod.map((method) => {
          const controller =
            typeof method.controller === "string"
              ? normalizeDidOanMaybe(method.controller) as string
              : method.controller;
          return {
            ...method,
            id:
              typeof method.id === "string" && method.id.startsWith(document.id)
                ? method.id.replace(document.id, normalizedId)
                : method.id,
            controller,
          };
        })
      : document.verificationMethod,
    authentication: Array.isArray(document.authentication)
      ? document.authentication.map((value) =>
          typeof value === "string" && value.startsWith(document.id) ? value.replace(document.id, normalizedId) : value,
        )
      : document.authentication,
    assertionMethod: Array.isArray(document.assertionMethod)
      ? document.assertionMethod.map((value) =>
          typeof value === "string" && value.startsWith(document.id) ? value.replace(document.id, normalizedId) : value,
        )
      : document.assertionMethod,
    service: Array.isArray(document.service)
      ? document.service.map((service) => ({
          ...service,
          id: typeof service.id === "string" && service.id.startsWith(document.id)
            ? service.id.replace(document.id, normalizedId)
            : service.id,
        }))
      : document.service,
    oanMetadata: document.oanMetadata
      ? {
          ...getDefaultOanMetadataFromDidOan(normalizedId),
          ...document.oanMetadata,
          controllerDid: normalizeDidOanMaybe(document.oanMetadata.controllerDid) as string | undefined,
          publisherDid: normalizeDidOanMaybe(document.oanMetadata.publisherDid) as string | undefined,
          issuerDid: normalizeDidOanMaybe(document.oanMetadata.issuerDid) as string | undefined,
        }
      : document.oanMetadata,
  };
}

export function normalizeRegistrationSubmissionForOan(
  submission: ResourceRegistrationSubmission,
): ResourceRegistrationSubmission {
  const normalizedResourceDid = normalizeDidOan(submission.resourceDid);
  const normalizedDocument = normalizeDidDocumentForOan({
    ...submission.didDocument,
    id: normalizedResourceDid,
  });
  return {
    ...submission,
    resourceDid: normalizedResourceDid,
    didDocument: normalizedDocument,
  };
}
