// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { decode } from "base58-universal";
import {
  canonicalJson, createAgentIdentity, createControllerIdentity,
  createEmptyIdentityStoreSnapshot, createRegistrationSubmissionFromIdentity,
  exportIdentityBundle, exportIdentityFile, finalizeRegistrationSubmissionWithProof,
  hashDidDocumentWithProof, importIdentityMaterials, prepareRegistrationMaterial,
  upsertIdentityRecord, validateIdentitySigningKey,
} from "../packages/sdk-ts/src/index.js";
import { didOanDefaultDocumentLoader, verifyDidOanDataIntegrity } from "../packages/protocol-types/src/index.js";

const registrarDid = "did:oan:2Xr85:HmxwAudrBEA87hc6tv9JQx91cNfLqHwv";
const now = new Date("2026-10-20T00:00:00.000Z");

for (const type of ["controller", "skill", "agent_service", "mcp_server", "tool_api"] as const) {
  test(`shared preparation preserves ${type} registration wire defaults, hashes and signature`, async () => {
    const identity = type === "controller"
      ? await createControllerIdentity("Fixture controller", { registrarDid, authorizedDomains: ["legal.contract_law"] })
      : await createAgentIdentity("Fixture resource", type, undefined, { registrarDid, authorizedDomains: ["legal.contract_law"] });
    const input = createRegistrationSubmissionFromIdentity(identity, { endpoint: "https://example.org/resource", packageVersion: "1.2.3" });
    const before = structuredClone(input);
    const prepared = await prepareRegistrationMaterial(input, now);
    assert.deepEqual(input, before, "preparation must not mutate caller data");
    assert.deepEqual(await prepareRegistrationMaterial(prepared, now), prepared);
    assert.deepEqual(prepared.didDocument.oanMetadata?.capabilityTags, []);
    assert.deepEqual(prepared.didDocument.oanMetadata?.resourceDescription?.useCaseExamples, []);
    assert.equal(prepared.didDocument.oanMetadata?.packageInfo?.version, "1.2.3");
    assert.equal(prepared.didDocument.oanMetadata?.externalIdentifiers, undefined);
    const signed = await finalizeRegistrationSubmissionWithProof(prepared, {
      resourceIdentity: identity, controllerIdentity: identity, registrarDid, now,
    });
    assert.equal(signed.didDocumentHash, "sha256:" + createHash("sha256").update(canonicalJson(signed.didDocument)).digest("hex"));
    assert.equal(signed.didDocumentHash, "sha256:" + await hashDidDocumentWithProof(signed.didDocument));
    assert.equal(signed.subjectControlProof?.challenge.didDocumentHash, signed.didDocumentHash);
    assert.equal(signed.controllerAuthorizationProof, undefined);
    assert.equal(signed.didDocument.proof?.creator, undefined, "ordinary DID proof profile stays unchanged");
    await verifyDidOanDataIntegrity(signed.didDocument, identity.publicKeyJwk, {
      documentLoader: async url => url === identity.did
        ? { contextUrl: null, documentUrl: url, document: signed.didDocument }
        : didOanDefaultDocumentLoader(url),
    });
    assert(!JSON.stringify(signed).includes("privateKeyJwk"));
    await assert.rejects(
      () => prepareRegistrationMaterial({
        ...input,
        metadata: { privateKeyJwk: { d: "forbidden" } },
      }, now),
      /private_key_material_in_public_submission/,
    );
  });
}

test("external controller authorization preserves the exact signed controller document and binds creator", async () => {
  // A normal resource may also control another resource.
  const controller = await createAgentIdentity("Resource controller", "agent_service", undefined, { registrarDid, authorizedDomains: ["legal.contract_law"] });
  const own = await finalizeRegistrationSubmissionWithProof(await prepareRegistrationMaterial(createRegistrationSubmissionFromIdentity(controller), now), {
    resourceIdentity: controller, controllerIdentity: controller, registrarDid, now,
  });
  controller.didDocument = own.didDocument;
  const controllerBefore = structuredClone(controller);
  const resource = await createAgentIdentity("Controlled resource", "skill", controller.did, { registrarDid, authorizedDomains: ["legal.contract_law"] });
  const submission = await finalizeRegistrationSubmissionWithProof(await prepareRegistrationMaterial(createRegistrationSubmissionFromIdentity(resource), now), {
    resourceIdentity: resource, controllerIdentity: controller, registrarDid, now,
  });
  const authorization = submission.controllerAuthorizationProof!;
  assert.deepEqual(controller, controllerBefore);
  assert.deepEqual(authorization.controllerDidDocument, controllerBefore.didDocument);
  assert.equal(authorization.proof.creator, controller.verificationMethodId);
  assert.equal(authorization.challenge.didDocumentHash, submission.didDocumentHash);
  assert.equal(authorization.challenge.metadataHash, submission.metadataHash);
  const key = await crypto.subtle.importKey("jwk", controller.publicKeyJwk, "Ed25519", false, ["verify"]);
  assert(await crypto.subtle.verify("Ed25519", key, new Uint8Array(decode(authorization.proof.proofValue.slice(1))), new TextEncoder().encode(canonicalJson(authorization.challenge))));
});

test("single identity and browser bundle roundtrip with legacy JWK ordering and transport hints", async () => {
  const controller = await createControllerIdentity("Import fixture", { registrarDid });
  const raw = JSON.parse(exportIdentityFile(controller));
  raw.publicKeyJwk = { ext: true, key_ops: ["verify"], x: controller.publicKeyJwk.x, kty: "OKP", crv: "Ed25519" };
  const imported = importIdentityMaterials(JSON.stringify(raw));
  assert.equal(imported.subjects[0].did, controller.did);
  assert.equal(canonicalJson(imported.subjects[0].didDocument), canonicalJson(controller.didDocument));
  await validateIdentitySigningKey(imported.subjects[0]);
  const bundle = upsertIdentityRecord(createEmptyIdentityStoreSnapshot(), controller);
  assert.equal(canonicalJson(importIdentityMaterials(exportIdentityBundle(bundle))), canonicalJson(bundle));
  assert.throws(() => importIdentityMaterials(JSON.stringify({ ...bundle, version: 2 })), /unsupported_identity_bundle_version/);
  assert.throws(() => importIdentityMaterials(JSON.stringify({ ...bundle, subjects: [controller, controller] })), /duplicate_identity/);
  assert.throws(() => importIdentityMaterials(JSON.stringify({ ...bundle, defaultSubjectId: "missing" })), /identity_bundle_default_missing/);
  assert.throws(() => importIdentityMaterials(JSON.stringify(controller.didDocument)), /identity_did_document_mismatch/);
  const wrong = await createControllerIdentity("Wrong key", { registrarDid });
  const mismatched = { ...controller, privateKeyJwk: { ...wrong.privateKeyJwk, x: controller.publicKeyJwk.x } };
  await assert.rejects(() => validateIdentitySigningKey(mismatched));
  const missingKey = { ...raw }; delete missingKey.privateKeyJwk;
  assert.throws(() => importIdentityMaterials(JSON.stringify(missingKey)), /identity_private_key_required/);
});

test("nonempty registration relationships retain protocol fields and reject incomplete credential requirements", async () => {
  const identity = await createAgentIdentity("Relationships", "skill", undefined, { registrarDid });
  const input = createRegistrationSubmissionFromIdentity(identity);
  input.didDocument.oanMetadata!.implementationLinks = [{
    relation: "implements", targetDid: identity.did, targetType: "skill",
    targetService: "#manifest", versionConstraint: "1.x",
  }];
  input.didDocument.oanMetadata!.externalIdentifiers = [{ id: "example/resource", resolutionServiceEndpoint: "https://example.org/" }];
  input.didDocument.oanMetadata!.credentialRequirements = [{
    id: "qualification", credentialType: "QualificationCredential", purpose: "access",
    issuer: [identity.did], scope: { action: "invoke" }, presentationMode: "vp", required: false,
  }];
  const before = structuredClone(input);
  const prepared = await prepareRegistrationMaterial(input, now);
  for (const field of ["implementationLinks", "externalIdentifiers", "credentialRequirements"] as const) {
    assert.deepEqual(prepared.didDocument.oanMetadata![field], before.didDocument.oanMetadata![field]);
  }
  assert.deepEqual(input, before);
  delete (input.didDocument.oanMetadata!.credentialRequirements![0] as Partial<{ purpose: string }>).purpose;
  await assert.rejects(() => prepareRegistrationMaterial(input, now), /credential_requirement_purpose_required/);
});
