// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  createAgentIdentityNode,
  ensureSubjectIdentityNode,
  importGenesisNodeIdentityDirectory,
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
  await access(join(workspace, "agents", agent.record.id, "identity.json"));
  for (const legacyFile of ["profile.json", "did-document.json", "private-key.jwk.json", "public-key.jwk.json"]) {
    let exists = true;
    try {
      await access(join(workspace, "agents", agent.record.id, legacyFile));
    } catch {
      exists = false;
    }
    assert(!exists, `new identity output must not emit legacy ${legacyFile}`);
  }
  const identityFile = JSON.parse(
    await readFile(join(workspace, "agents", agent.record.id, "identity.json"), "utf8"),
  ) as Record<string, unknown>;
  assert(!("kind" in identityFile) && !("profile" in identityFile), "identity file must use the minimal model");
  const loaded = await loadIdentityStoreSnapshot(workspace);
  assert(loaded.subjects.length === 1, "loaded subject count mismatch");
  assert(loaded.agents.length === 1, "loaded agent count mismatch");

  const importedNode = await importGenesisNodeIdentityDirectory(genesisRegistrarDir, workspace);
  assert(importedNode.record.kind === "node", "genesis identity import should create node record");
  assert(importedNode.record.didDocument.id === importedNode.record.did, "genesis identity DID mismatch");
  const reloaded = await loadIdentityStoreSnapshot(workspace);
  assert(reloaded.nodes.length === 1, "loaded node count mismatch after genesis import");
  const importedByCompat = await importLegacyGenesisNodeDirectory(genesisRegistrarDir, workspace);
  assert(importedByCompat.record.did === importedNode.record.did, "compat import should use unified identity");
} finally {
  await rm(workspace, { recursive: true, force: true });
}

console.log("identity-store-node tests passed");
