// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { copyFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import type { DidDocument, ResourceType } from "../../protocol-types/src/index.js";
import {
  createEmptyIdentityStoreSnapshot,
  createOanIdentityRecord,
  type OanIdentityKind,
  type OanIdentityProfile,
  type OanIdentityRecord,
  type OanIdentityStoreSnapshot,
  upsertIdentityRecord,
} from "./identity.js";

interface NodeProfileFile {
  id: string;
  kind: OanIdentityKind;
  createdAt: string;
  did: string;
  verificationMethodId: string;
  profile: OanIdentityProfile;
}

interface LegacyGenesisNodeMetadata {
  id: string;
  role?: string;
  did: string;
  didDocumentFile?: string;
  keyFiles?: {
    privateKeyJwk?: string;
    publicKeyJwk?: string;
  };
  governanceNoticeFile?: string;
  rootAuthorizationCredentialFile?: string;
  [key: string]: unknown;
}

export function getDefaultIdentityStoreDir(): string {
  return resolve(homedir(), ".oan-dids");
}

export async function loadIdentityStoreSnapshot(
  dir = getDefaultIdentityStoreDir(),
): Promise<OanIdentityStoreSnapshot> {
  const indexPath = join(dir, "index.json");
  try {
    const index = JSON.parse(await readFile(indexPath, "utf8")) as OanIdentityStoreSnapshot;
    return {
      ...index,
      subjects: await loadRecordBucket(dir, "subjects"),
      agents: await loadRecordBucket(dir, "agents"),
      nodes: await loadRecordBucket(dir, "nodes"),
    };
  } catch {
    return createEmptyIdentityStoreSnapshot();
  }
}

export async function saveIdentityStoreSnapshot(
  snapshot: OanIdentityStoreSnapshot,
  dir = getDefaultIdentityStoreDir(),
): Promise<void> {
  await ensureStoreLayout(dir);
  await saveRecordBucket(dir, "subjects", snapshot.subjects);
  await saveRecordBucket(dir, "agents", snapshot.agents);
  await saveRecordBucket(dir, "nodes", snapshot.nodes);
  await writeJson(join(dir, "index.json"), {
    version: snapshot.version,
    updatedAt: new Date().toISOString(),
    defaultSubjectId: snapshot.defaultSubjectId,
    defaultAgentId: snapshot.defaultAgentId,
    subjects: snapshot.subjects.map(recordIndexSummary),
    agents: snapshot.agents.map(recordIndexSummary),
    nodes: snapshot.nodes.map(recordIndexSummary),
  });
}

export async function ensureSubjectIdentityNode(
  options: { label?: string; resourceType?: Extract<ResourceType, "developer" | "organization">; identityDir?: string } = {},
): Promise<{ record: OanIdentityRecord; snapshot: OanIdentityStoreSnapshot; identityDir: string }> {
  const identityDir = options.identityDir ?? getDefaultIdentityStoreDir();
  const snapshot = await loadIdentityStoreSnapshot(identityDir);
  const defaultSubject = snapshot.subjects.find((record) => record.id === snapshot.defaultSubjectId) ?? snapshot.subjects[0];
  if (defaultSubject) {
    return { record: defaultSubject, snapshot, identityDir };
  }
  const record = await createOanIdentityRecord({
    label: options.label ?? "Default OAN Subject",
    resourceType: options.resourceType ?? "developer",
    kind: "subject",
  });
  const next = upsertIdentityRecord(snapshot, record);
  await saveIdentityStoreSnapshot(next, identityDir);
  return { record, snapshot: next, identityDir };
}

export async function createAgentIdentityNode(
  options: {
    label: string;
    resourceType: Extract<ResourceType, "agent_service" | "skill" | "mcp_server" | "tool_api">;
    ownerSubjectDid?: string;
    identityDir?: string;
    description?: string;
    capabilityTags?: string[];
    authorizedDomains?: string[];
    serviceEndpoint?: string;
    manifestUrl?: string;
    schemaUrl?: string;
  },
): Promise<{ record: OanIdentityRecord; snapshot: OanIdentityStoreSnapshot; identityDir: string }> {
  const identityDir = options.identityDir ?? getDefaultIdentityStoreDir();
  const snapshot = await loadIdentityStoreSnapshot(identityDir);
  const record = await createOanIdentityRecord({
    label: options.label,
    resourceType: options.resourceType,
    kind: "agent",
    ownerSubjectDid: options.ownerSubjectDid,
    description: options.description,
    capabilityTags: options.capabilityTags,
    authorizedDomains: options.authorizedDomains,
    serviceEndpoint: options.serviceEndpoint,
    manifestUrl: options.manifestUrl,
    schemaUrl: options.schemaUrl,
  });
  const next = upsertIdentityRecord(snapshot, record);
  await saveIdentityStoreSnapshot(next, identityDir);
  return { record, snapshot: next, identityDir };
}

export async function importLegacyGenesisNodeDirectory(
  legacyDir: string,
  identityDir = getDefaultIdentityStoreDir(),
): Promise<{ record: OanIdentityRecord; snapshot: OanIdentityStoreSnapshot; identityDir: string }> {
  const root = resolve(legacyDir);
  const nodeJson = JSON.parse(await readFile(join(root, "node.json"), "utf8")) as LegacyGenesisNodeMetadata;
  const didDocument = JSON.parse(
    await readFile(join(root, nodeJson.didDocumentFile ?? "did-document.json"), "utf8"),
  ) as DidDocument;
  const privateKeyJwk = JSON.parse(
    await readFile(join(root, nodeJson.keyFiles?.privateKeyJwk ?? "private-key.jwk.json"), "utf8"),
  ) as Record<string, unknown>;
  const publicKeyJwk = JSON.parse(
    await readFile(join(root, nodeJson.keyFiles?.publicKeyJwk ?? "public-key.jwk.json"), "utf8"),
  ) as Record<string, unknown>;
  const record: OanIdentityRecord = {
    id: `node-${nodeJson.id}`,
    kind: "node",
    createdAt: new Date().toISOString(),
    did: nodeJson.did,
    verificationMethodId:
      typeof didDocument.verificationMethod?.[0]?.id === "string"
        ? didDocument.verificationMethod[0].id
        : `${nodeJson.did}#key-1`,
    didDocument,
    privateKeyJwk,
    publicKeyJwk,
    profile: {
      label: String(nodeJson.id),
      resourceType: "infrastructure_node",
      origin: "legacy-genesis-import",
      metadata: nodeJson,
    },
  };
  const snapshot = upsertIdentityRecord(await loadIdentityStoreSnapshot(identityDir), record);
  await saveIdentityStoreSnapshot(snapshot, identityDir);
  const recordDir = join(identityDir, "nodes", record.id);
  await mkdir(join(recordDir, "legacy"), { recursive: true });
  for (const filename of [
    "node.json",
    nodeJson.didDocumentFile ?? "did-document.json",
    nodeJson.keyFiles?.privateKeyJwk ?? "private-key.jwk.json",
    nodeJson.keyFiles?.publicKeyJwk ?? "public-key.jwk.json",
    nodeJson.governanceNoticeFile,
    nodeJson.rootAuthorizationCredentialFile,
  ]) {
    if (!filename) continue;
    await copyFile(join(root, filename), join(recordDir, "legacy", basename(filename)));
  }
  return { record, snapshot, identityDir };
}

async function ensureStoreLayout(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  await mkdir(join(dir, "subjects"), { recursive: true });
  await mkdir(join(dir, "agents"), { recursive: true });
  await mkdir(join(dir, "nodes"), { recursive: true });
}

async function loadRecordBucket(
  dir: string,
  bucket: "subjects" | "agents" | "nodes",
): Promise<OanIdentityRecord[]> {
  const bucketDir = join(dir, bucket);
  try {
    const entries = await readdir(bucketDir, { withFileTypes: true });
    const records: OanIdentityRecord[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      records.push(await loadRecord(join(bucketDir, entry.name)));
    }
    return records;
  } catch {
    return [];
  }
}

async function loadRecord(recordDir: string): Promise<OanIdentityRecord> {
  const profileFile = JSON.parse(await readFile(join(recordDir, "profile.json"), "utf8")) as NodeProfileFile;
  return {
    id: profileFile.id,
    kind: profileFile.kind,
    createdAt: profileFile.createdAt,
    did: profileFile.did,
    verificationMethodId: profileFile.verificationMethodId,
    profile: profileFile.profile,
    didDocument: JSON.parse(await readFile(join(recordDir, "did-document.json"), "utf8")) as DidDocument,
    privateKeyJwk: JSON.parse(await readFile(join(recordDir, "private-key.jwk.json"), "utf8")) as Record<string, unknown>,
    publicKeyJwk: JSON.parse(await readFile(join(recordDir, "public-key.jwk.json"), "utf8")) as Record<string, unknown>,
  };
}

async function saveRecordBucket(
  dir: string,
  bucket: "subjects" | "agents" | "nodes",
  records: OanIdentityRecord[],
): Promise<void> {
  const bucketDir = join(dir, bucket);
  await mkdir(bucketDir, { recursive: true });
  for (const record of records) {
    const recordDir = join(bucketDir, record.id);
    await mkdir(recordDir, { recursive: true });
    await writeJson(join(recordDir, "profile.json"), {
      id: record.id,
      kind: record.kind,
      createdAt: record.createdAt,
      did: record.did,
      verificationMethodId: record.verificationMethodId,
      profile: record.profile,
    } satisfies NodeProfileFile);
    await writeJson(join(recordDir, "did-document.json"), record.didDocument);
    await writeJson(join(recordDir, "private-key.jwk.json"), record.privateKeyJwk);
    await writeJson(join(recordDir, "public-key.jwk.json"), record.publicKeyJwk);
  }
}

function recordIndexSummary(record: OanIdentityRecord): Record<string, unknown> {
  return {
    id: record.id,
    kind: record.kind,
    did: record.did,
    createdAt: record.createdAt,
    label: record.profile.label,
    resourceType: record.profile.resourceType,
    origin: record.profile.origin,
  };
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
