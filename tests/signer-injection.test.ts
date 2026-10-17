import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createOanIdentityRecord, createJwkOanSigner, asDataIntegritySigner, signDidDocumentProof, verifyPinnedDidDocument } from '../packages/sdk-ts/src/index.js';
import { signDidOanDataIntegrity, verifyDidOanDataIntegrity, didOanDefaultDocumentLoader, type IdentityMessageContext } from '../packages/protocol-types/src/index.js';

test('injected signer uses the original JSON-LD suite and independently verifies', async () => {
  const identity = await createOanIdentityRecord({ label: 'fixture', resourceType: 'skill', kind: 'agent' });
  const signer = await createJwkOanSigner(identity.verificationMethodId, identity.privateKeyJwk);
  const { proof: _, ...unsigned } = identity.didDocument;
  const options = { created: '2026-10-16T00:00:00Z' };
  const compatible = await signDidOanDataIntegrity(unsigned, identity.did, identity.privateKeyJwk, options);
  const injected = await signDidOanDataIntegrity(unsigned, identity.did, undefined, { ...options, signer });
  const verificationOptions = {
    documentLoader: async (url: string) => url === identity.did
      ? { contextUrl: null, documentUrl: url, document: identity.didDocument }
      : didOanDefaultDocumentLoader(url),
  };
  await verifyDidOanDataIntegrity(injected, identity.publicKeyJwk, verificationOptions);
  const { privateKeyJwk: _private, ...publicIdentity } = identity;
  const signedDocument = await signDidDocumentProof(identity.didDocument, publicIdentity, { signer });
  const report = await verifyPinnedDidDocument(signedDocument, { ...verificationOptions, expectedDid: identity.did, publicKeyJwk: identity.publicKeyJwk });
  assert.equal(report.valid, true);
  assert.equal(report.checks.find(c => c.name === 'registration_trust')?.status, 'not_checked');
  assert.equal((await verifyPinnedDidDocument(signedDocument, { expectedDid: 'wrong', publicKeyJwk: identity.publicKeyJwk })).valid, false);
  assert.deepEqual(injected, compatible);
  assert.equal('d' in await signer.publicKey(), false);
  await assert.rejects(asDataIntegritySigner(signer, 'wrong#key-1'), /binding_mismatch/);
  const invalid = { ...signer, async signPreparedInput() { return new Uint8Array(64); } };
  await assert.rejects(signDidOanDataIntegrity(unsigned, identity.did, undefined, { signer: invalid }), /invalid_signer_signature/);
});
test('shared Rust fixture preserves exact camelCase fields', async () => {
  const context: IdentityMessageContext = JSON.parse(await readFile(new URL('./identity-runtime-fixture.json', import.meta.url), 'utf8'));
  assert.equal(context.profile, 'oan-message-v1');
  assert.equal(context.protocol, 'http');
  const rustFixture = JSON.parse(await readFile(new URL('../../oan-protocol-common/test-fixtures/identity-runtime/message-context.json', import.meta.url), 'utf8'));
  assert.deepEqual(context, rustFixture);
});
