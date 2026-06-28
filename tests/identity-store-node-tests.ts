// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { mkdtemp, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  createAgentIdentityNode,
  ensureSubjectIdentityNode,
  importLegacyGenesisNodeDirectory,
  loadIdentityStoreSnapshot,
  saveIdentityStoreSnapshot,
} from "../packages/sdk-ts/src/identity-store-node.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const genesisRegistrarDir =
  process.env.OAN_GENESIS_REGISTRAR_DIR ??
  resolve(repoRoot, "..", "oan-design-docs", "genesis", "nodes", "genesis-registrar-1");

const workspace = await mkdtemp(join(tmpdir(), "oan-identity-store-"));
try {
  const ensured = await ensureSubjectIdentityNode({ identityDir: workspace, label: "Node Store Subject" });
  assert(ensured.record.profile.resourceType === "developer", "default subject resource type mismatch");

  const agent = await createAgentIdentityNode({
    identityDir: workspace,
    label: "Node Store Skill",
    resourceType: "skill",
    ownerSubjectDid: ensured.record.did,
    manifestUrl: "https://example.org/skills/node-store.json",
  });
  assert(agent.record.profile.ownerSubjectDid === ensured.record.did, "agent owner subject mismatch");

  await saveIdentityStoreSnapshot(agent.snapshot, workspace);
  const loaded = await loadIdentityStoreSnapshot(workspace);
  assert(loaded.subjects.length === 1, "loaded subject count mismatch");
  assert(loaded.agents.length === 1, "loaded agent count mismatch");

  const importedNode = await importLegacyGenesisNodeDirectory(genesisRegistrarDir, workspace);
  assert(importedNode.record.kind === "node", "legacy import should create node record");
  const reloaded = await loadIdentityStoreSnapshot(workspace);
  assert(reloaded.nodes.length === 1, "loaded node count mismatch after legacy import");
} finally {
  await rm(workspace, { recursive: true, force: true });
}

console.log("identity-store-node tests passed");
