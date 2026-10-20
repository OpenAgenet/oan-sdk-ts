// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

// Extracted from the proven community registration workflow. Normalize only
// newly prepared resource documents; never rewrite a registered controller.
import type { ResourceRegistrationSubmission } from "../../protocol-types/src/index.js";
import { canonicalJson, hashDidDocumentWithProof, hashRegistrationPackageBinding } from "./index.js";
import { normalizeRegistrationSubmissionForOan } from "./did-oan.js";

export async function prepareRegistrationMaterial(
  input: ResourceRegistrationSubmission,
  timestamp = new Date(),
): Promise<ResourceRegistrationSubmission> {
  assertPublicMaterial(input);
  const submission = normalizeRegistrationSubmissionForOan(input);
  const hashAlgorithm = submission.hashAlgorithm || "sha256";
  const now = timestamp.toISOString();

  submission.hashAlgorithm = hashAlgorithm;
  submission.packageVersion = submission.packageVersion || "1.0.0";
  submission.didDocument = enrichDidDocumentMetadata(
    submission.didDocument as Record<string, unknown>,
    submission,
  ) as ResourceRegistrationSubmission["didDocument"];

  const didDocumentHash = `${hashAlgorithm}:${await hashDidDocumentWithProof(submission.didDocument)}`;
  submission.didDocumentHash = didDocumentHash;

  const metadata = buildResourceMetadata(submission, now);
  submission.metadataHash = `${hashAlgorithm}:${await hashJson(metadata)}`;
  submission.packageHash = `${hashAlgorithm}:${await hashRegistrationPackageBinding(submission)}`;
  submission.metadata = {
    ...(typeof submission.metadata === "object" && submission.metadata
      ? submission.metadata
      : {}),
    name: metadata.name,
    description: metadata.description,
    capabilityTags: metadata.capabilityTags,
    authorizedDomains: metadata.authorizedDomains,
    lifecycleState: metadata.lifecycleState,
  };
  return submission;
}

/** Registration requests are public wire material and must never carry keys. */
export function assertPublicMaterial(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) assertPublicMaterial(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  for (const [key, entry] of Object.entries(record)) {
    if (
      key === "privateKeyJwk" || key === "privateKeyMultibase" ||
      key === "privateKeyBase58" || key === "privateKeyHex" ||
      key === "secretKey" || key === "seed" ||
      (key === "d" && record.kty !== undefined)
    ) {
      throw new Error("private_key_material_in_public_submission");
    }
    assertPublicMaterial(entry);
  }
}

function enrichDidDocumentMetadata(
  didDocument: Record<string, unknown>,
  submission: ResourceRegistrationSubmission,
): Record<string, unknown> {
  const metadata = {
    ...asRecord(didDocument.oanMetadata),
  };
  // serde(default) Vec fields without skip_serializing_if must be present,
  // even when empty. This is especially common for dedicated controllers.
  metadata.capabilityTags ??= [];
  metadata.authorizedDomains ??= [];
  if (metadata.resourceDescription) {
    const description = { ...asRecord(metadata.resourceDescription) };
    description.capabilityTags ??= [];
    description.useCaseExamples ??= [];
    metadata.resourceDescription = description;
  }
  if (metadata.agentDescription) {
    const description = { ...asRecord(metadata.agentDescription) };
    description.capabilityTags ??= [];
    description.useCaseExamples ??= [];
    metadata.agentDescription = description;
  }
  const packageInfo = normalizePackageInfo(metadata.packageInfo, submission.packageVersion);
  // PackageInfo is deny_unknown_fields in the wire protocol. Hash algorithm
  // belongs to the submission, not the DID document's packageInfo.
  delete (packageInfo as Record<string, unknown>).hashAlgorithm;
  for (const field of ["packageHash", "metadataHash"] as const) {
    if (/^sha256:0{64}$/.test(String(packageInfo[field])))
      delete packageInfo[field];
  }
  metadata.packageInfo = packageInfo;
  metadata.implementationLinks = normalizeImplementationLinks(
    metadata.implementationLinks,
    submission,
  );
  metadata.credentialRequirements = normalizeCredentialRequirements(
    metadata.credentialRequirements,
  );
  // Rust OanMetadata omits these empty vectors during serialization. Apply
  // that projection before signing, not merely while hashing, so the signed
  // wire document and the Root's typed document have identical content.
  for (const field of ["implementationLinks", "credentialRequirements", "protocolBindings", "externalIdentifiers"] as const) {
    if (Array.isArray(metadata[field]) && metadata[field].length === 0) {
      delete metadata[field];
    }
  }
  return {
    ...didDocument,
    verificationMethod: didDocument.verificationMethod ?? [],
    authentication: didDocument.authentication ?? [],
    assertionMethod: didDocument.assertionMethod ?? [],
    service: didDocument.service ?? [],
    oanMetadata: metadata,
  };
}

/** Rust's PackageInfo is deny_unknown_fields; project only known wire fields. */
function normalizePackageInfo(value: unknown, version: string): Record<string, unknown> {
  const input = asRecord(value);
  const allowed = [
    "manifestUrl", "downloadUrl", "packageHash", "metadataHash", "version",
    "versionScheme", "previousVersion", "rootProofRef", "releaseNotesUrl",
    "createdAt", "updatedAt", "expiresAt",
  ] as const;
  const output: Record<string, unknown> = {};
  for (const key of allowed) {
    if (input[key] !== undefined) output[key] = input[key];
  }
  output.version = version;
  return output;
}

function normalizeImplementationLinks(
  value: unknown,
  submission: ResourceRegistrationSubmission,
): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return [];
  return value.map((link) => {
    const record = asRecord(link);
    if (typeof record.relation !== "string" || record.relation.length === 0) {
      throw new Error("implementation_link_relation_required");
    }
    return {
      relation: record.relation,
      targetDid: record.targetDid ?? submission.resourceDid,
      targetType: record.targetType ?? submission.resourceType,
      ...(record.targetService !== undefined ? { targetService: record.targetService } : {}),
      ...(record.versionConstraint !== undefined ? { versionConstraint: record.versionConstraint } : {}),
    };
  });
}

function normalizeCredentialRequirements(
  value: unknown,
): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    const record = asRecord(item);
    const credentialType = record.credentialType ?? record.type;
    const purpose = record.purpose ?? asRecord(record.scope).purpose;
    if (typeof credentialType !== "string" || credentialType.length === 0) {
      throw new Error("credential_requirement_type_required");
    }
    if (typeof purpose !== "string" || purpose.length === 0) {
      throw new Error("credential_requirement_purpose_required");
    }
    return {
      id: record.id ?? submissionRequirementId(record),
      credentialType,
      purpose,
      ...(record.issuer !== undefined ? { issuer: record.issuer } : {}),
      ...(record.scope !== undefined ? { scope: record.scope } : {}),
      ...(record.presentationMode !== undefined ? { presentationMode: record.presentationMode } : {}),
      required: record.required ?? true,
    };
  });
}

function submissionRequirementId(record: Record<string, unknown>): string {
  return `requirement-${String(record.credentialType ?? record.type ?? "credential")}`;
}

function buildResourceMetadata(
  submission: ResourceRegistrationSubmission,
  now: string,
): Record<string, unknown> {
  const oanMetadata = asRecord(submission.didDocument.oanMetadata);
  const resourceDescription = asRecord(oanMetadata.resourceDescription);
  return {
    resourceDid: submission.resourceDid,
    resourceType: submission.resourceType,
    subjectType: submission.resourceType,
    publisherDid: oanMetadata.publisherDid,
    subjectDid: submission.resourceDid,
    name: resourceDescription.name ?? "Untitled OAN resource",
    description: resourceDescription.description ?? "",
    capabilityTags:
      oanMetadata.capabilityTags ?? resourceDescription.capabilityTags ?? [],
    authorizedDomains: oanMetadata.authorizedDomains ?? [],
    protocolBindings: oanMetadata.protocolBindings ?? [],
    services: submission.didDocument.service ?? [],
    lifecycleState: oanMetadata.lifecycleState ?? "active",
    packageVersion: submission.packageVersion,
    packageHash: "",
    metadataHash: "",
    hashAlgorithm: submission.hashAlgorithm,
    updatedAt: now,
  };
}

async function hashJson(value: unknown): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

