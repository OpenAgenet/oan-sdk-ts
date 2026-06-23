// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { DidDocument, OanMetadata, ResourceRegistrationSubmission, ResourceType } from "../../protocol-types/src/index.js";
import { OanVerificationError } from "./index.js";

export const OAN_METHOD = "oan";
export const OAN_DID_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/oan/v1"] as const;
export const OAN_DID_ID_RE = /^[A-Z0-9]{4}:[1-9A-HJ-NP-Za-km-z]{32}$/;

export const OAN_RESOURCE_TYPE_BY_SUBJECT_CODE: Record<string, ResourceType> = {
  AG: "agent_service",
  SK: "skill",
  MC: "mcp_server",
  TL: "tool_api",
  IN: "infrastructure_node",
  OR: "organization",
  DV: "developer",
};

export function parseDidOan(value: string): { method: string; id: string; semanticCode: string; subjectCode: string } {
  const segments = value.split(":");
  if (segments.length !== 4 || segments[0] !== "did" || segments[1] !== OAN_METHOD) {
    throw new OanVerificationError("did_method_mismatch");
  }
  const id = `${segments[2]}:${segments[3]}`;
  const normalizedId = normalizeDidOanId(id);
  if (!OAN_DID_ID_RE.test(normalizedId)) {
    throw new OanVerificationError("did_method_mismatch");
  }
  const semanticCode = normalizedId.split(":")[0] ?? "";
  const subjectCode = semanticCode.slice(0, 2);
  return {
    method: OAN_METHOD,
    id: normalizedId,
    semanticCode,
    subjectCode,
  };
}

export function normalizeDidOanId(id: string): string {
  const segments = id.split(":");
  if (segments.length !== 2) {
    return id;
  }
  return `${segments[0].toUpperCase()}:${segments[1]}`;
}

export function normalizeDidOan(value: string): string {
  const parsed = parseDidOan(value);
  return `did:${OAN_METHOD}:${parsed.id}`;
}

export function inferResourceTypeFromDidOan(value: string): ResourceType | undefined {
  const parsed = parseDidOan(value);
  return OAN_RESOURCE_TYPE_BY_SUBJECT_CODE[parsed.subjectCode];
}

export function hasDidOanSemanticConflict(
  value: string,
  metadata: Pick<DidDocument, "oanMetadata">["oanMetadata"] | undefined,
): boolean {
  if (!metadata) {
    return false;
  }
  const expected = inferResourceTypeFromDidOan(value);
  if (!expected) {
    return false;
  }
  const subjectType = typeof metadata.subjectType === "string" ? metadata.subjectType : undefined;
  const resourceType = typeof metadata.resourceType === "string" ? metadata.resourceType : undefined;
  if (subjectType && subjectType !== expected) {
    return true;
  }
  if (resourceType && resourceType !== expected) {
    return true;
  }
  return false;
}

export function getDefaultOanMetadataFromDidOan(
  value: string,
): Partial<Pick<OanMetadata, "subjectType" | "resourceType">> {
  const inferred = inferResourceTypeFromDidOan(value);
  if (!inferred) {
    return {};
  }
  return {
    subjectType: inferred,
    resourceType: inferred,
  };
}

export function normalizeDidOanMaybe(value: unknown): unknown {
  if (typeof value !== "string") {
    return value;
  }
  try {
    return normalizeDidOan(value);
  } catch {
    return value;
  }
}

export function normalizeDidDocumentForOan(document: DidDocument): DidDocument {
  const normalizedId = normalizeDidOan(document.id);
  return {
    ...document,
    id: normalizedId,
    controller: normalizeDidOanMaybe(document.controller),
    verificationMethod: Array.isArray(document.verificationMethod)
      ? document.verificationMethod.map((method) => {
          const controller =
            typeof method.controller === "string"
              ? normalizeDidOan(method.controller)
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
