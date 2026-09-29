import jsigs from "jsonld-signatures";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { documentLoader as ed25519DocumentLoader } from "ed25519-signature-2020-context";
import { decode as base58Decode } from "base58-universal";
import { encode as base64urlEncode } from "base64url-universal";
import fs from "node:fs";
import path from "node:path";
import {
  parseProfileV2DataIntegrityProof,
  parseProfileV2DidDocument,
  parseProfileV2Jwk,
  parseProfileV2OanIdentity,
  parseProfileV2VerifiableCredential,
  signProfileV2DataIntegrity,
  verifyProfileV2DataIntegrity,
  validateProfileV2OanIdentityKeyPair,
} from "../packages/protocol-types/src/index.js";

const { purposes } = jsigs as any;
const fixturePath = path.resolve(
  process.cwd(),
  "../oan-protocol-common/test-fixtures/ed25519-signature-2020-cross-language.json",
);
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const localCredentialContext = {
  "@context": {
    VerifiableCredential: "https://www.w3.org/2018/credentials#VerifiableCredential",
    issuer: "https://www.w3.org/2018/credentials#issuer",
    credentialSubject: "https://www.w3.org/2018/credentials#credentialSubject",
    id: "@id",
    type: "@type",
  },
};

const documentLoader = async (url: string) => {
  if (url === "https://w3id.org/security/suites/ed25519-2020/v1") {
    return ed25519DocumentLoader(url);
  }
  if (url === fixture.signed.issuer) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: {
        "@context": ["https://www.w3.org/ns/did/v1"],
        id: fixture.signed.issuer,
        assertionMethod: [fixture.key.id],
        verificationMethod: [
          {
            id: fixture.key.id,
            type: fixture.key.type,
            controller: fixture.key.controller,
            publicKeyMultibase: fixture.key.publicKeyMultibase,
          },
        ],
      },
    };
  }
  throw new Error(`unexpected context: ${url}`);
};

const key = await Ed25519VerificationKey2020.from(fixture.key);
const suite = new Ed25519Signature2020({ key });
const purpose = new purposes.AssertionProofPurpose();
const fixtureJwk = {
  kty: "OKP" as const,
  crv: "Ed25519" as const,
  x: base64urlEncode(base58Decode(fixture.key.publicKeyMultibase.slice(1)).slice(2)),
  d: base64urlEncode(base58Decode(fixture.key.privateKeyMultibase.slice(1)).slice(2, 34)),
};
const signedFromTs = await signProfileV2DataIntegrity(
  fixture.signed && {
    "@context": fixture.signed["@context"],
    type: fixture.signed.type,
    issuer: fixture.signed.issuer,
    credentialSubject: fixture.signed.credentialSubject,
  },
  fixture.signed.issuer,
  fixtureJwk,
  { created: fixture.signed.proof.created, documentLoader },
);
if ((signedFromTs.proof as any).proofValue !== fixture.signed.proof.proofValue) {
  throw new Error("TypeScript signature does not match the frozen fixture");
}
await verifyProfileV2DataIntegrity(fixture.signed, {
  kty: "OKP",
  crv: "Ed25519",
  x: fixtureJwk.x,
}, { documentLoader });

if (!fixture.signed.proof.proofValue.startsWith("z")) {
  throw new Error("standard Data Integrity proofValue must use base58-btc Multibase");
}
parseProfileV2DataIntegrityProof(fixture.signed.proof);
parseProfileV2DidDocument({
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://openagenet.xyz/did-oan-specs/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ],
  id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
  verificationMethod: [{
    id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
    type: "Ed25519VerificationKey2020",
    controller: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
    publicKeyMultibase: fixture.key.publicKeyMultibase,
  }],
  authentication: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
  assertionMethod: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
  proof: {
    ...fixture.signed.proof,
    verificationMethod: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
  },
});

for (const invalidDocument of [
  {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://openagenet.xyz/did-oan-specs/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
    verificationMethod: [{
      id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
      type: "Ed25519VerificationKey2020",
      controller: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
      publicKeyMultibase: "z111",
    }],
    authentication: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
    assertionMethod: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
    proof: fixture.signed.proof,
  },
  {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://openagenet.xyz/did-oan-specs/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
    verificationMethod: [{
      id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
      type: "Ed25519VerificationKey2020",
      controller: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
      publicKeyMultibase: fixture.key.publicKeyMultibase,
      publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
    }],
    authentication: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
    assertionMethod: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
    proof: fixture.signed.proof,
  },
]) {
  let rejected = false;
  try {
    parseProfileV2DidDocument(invalidDocument);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error("invalid DID Document was accepted");
  }
}

for (const invalidProof of [
  { ...fixture.signed.proof, verificationMethod: `${fixture.signed.issuer}#key-2` },
  { ...fixture.signed.proof, unexpected: true },
]) {
  let rejected = false;
  try {
    parseProfileV2DataIntegrityProof(invalidProof);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error("invalid proof shape was accepted");
  }
}

let credentialRejected = false;
try {
  parseProfileV2VerifiableCredential({
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://openagenet.xyz/did-oan-specs/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    type: ["VerifiableCredential"],
    issuer: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
    issuanceDate: "2026-01-01T00:00:00Z",
    credentialSubject: { id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu" },
    proof: {
      ...fixture.signed.proof,
      verificationMethod:
        "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
    },
    creator: "legacy",
  });
} catch {
  credentialRejected = true;
}
if (!credentialRejected) {
  throw new Error("legacy VC field was accepted");
}
let identityRejected = false;
try {
  parseProfileV2OanIdentity({
    id: "urn:oan:identity:test",
    createdAt: "2026-01-01T00:00:00Z",
    did: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
    verificationMethodId: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
    didDocument: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://openagenet.xyz/did-oan-specs/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
      verificationMethod: [{
        id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: fixture.key.publicKeyMultibase },
      }],
      authentication: [],
      assertionMethod: [],
      proof: fixture.signed.proof,
    },
    publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: fixture.key.publicKeyMultibase },
    privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: fixture.key.publicKeyMultibase, d: "AQ" },
  });
} catch {
  identityRejected = true;
}
if (!identityRejected) {
  throw new Error("invalid OAN Identity was accepted");
}

const identityKeyPair = (await globalThis.crypto.subtle.generateKey(
  { name: "Ed25519" },
  true,
  ["sign", "verify"],
)) as CryptoKeyPair;
const identityPrivateExport = await globalThis.crypto.subtle.exportKey("jwk", identityKeyPair.privateKey);
const identityPublicExport = await globalThis.crypto.subtle.exportKey("jwk", identityKeyPair.publicKey);
const identityPrivateKeyJwk = {
  kty: "OKP" as const,
  crv: "Ed25519" as const,
  x: identityPrivateExport.x as string,
  d: identityPrivateExport.d as string,
};
const identityPublicKeyJwk = {
  kty: "OKP" as const,
  crv: "Ed25519" as const,
  x: identityPublicExport.x as string,
};
const validIdentity = parseProfileV2OanIdentity({
  id: "urn:oan:identity:valid",
  createdAt: "2026-01-01T00:00:00Z",
  did: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
  verificationMethodId: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
  didDocument: {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://openagenet.xyz/did-oan-specs/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
    verificationMethod: [{
      id: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
      type: "Ed25519VerificationKey2020",
      controller: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu",
      publicKeyJwk: identityPublicKeyJwk,
    }],
    authentication: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
    assertionMethod: ["did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1"],
    proof: {
      ...fixture.signed.proof,
      verificationMethod: "did:oan:K7mQ9:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu#key-1",
    },
  },
  publicKeyJwk: identityPublicKeyJwk,
  privateKeyJwk: identityPrivateKeyJwk,
});
await validateProfileV2OanIdentityKeyPair(validIdentity);
const mismatchedIdentity = structuredClone(validIdentity);
const mismatchKeyPair = (await globalThis.crypto.subtle.generateKey(
  { name: "Ed25519" },
  true,
  ["sign", "verify"],
)) as CryptoKeyPair;
const mismatchPrivateExport = await globalThis.crypto.subtle.exportKey("jwk", mismatchKeyPair.privateKey);
mismatchedIdentity.privateKeyJwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: identityPublicKeyJwk.x,
  d: mismatchPrivateExport.d as string,
};
let mismatchedIdentityRejected = false;
try {
  await validateProfileV2OanIdentityKeyPair(mismatchedIdentity);
} catch {
  mismatchedIdentityRejected = true;
}
if (!mismatchedIdentityRejected) {
  throw new Error("mismatched OAN Identity key pair was accepted");
}

for (const legacyProof of [
  { ...fixture.signed.proof, creator: fixture.key.id },
  { ...fixture.signed.proof, cryptoSuite: "ed25519-sha256" },
  { ...fixture.signed.proof, hashAlgorithm: "sha256" },
  { ...fixture.signed.proof, proofValue: "base64url-signature" },
]) {
  let rejected = false;
  try {
    parseProfileV2DataIntegrityProof(legacyProof);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error("legacy proof was accepted");
  }
}
for (const legacyJwk of [
  { kty: "OKP", crv: "Ed25519", x: "AQ", alg: "Ed25519" },
  { kty: "OKP", crv: "Ed25519", x: "AQ", d: "AQ", extra: true },
]) {
  let rejected = false;
  try {
    parseProfileV2Jwk(legacyJwk);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error("legacy JWK was accepted");
  }
}
for (const legacyField of ["creator", "cryptoSuite", "hashAlgorithm"]) {
  if (legacyField in fixture.signed.proof) {
    throw new Error(`legacy proof field present: ${legacyField}`);
  }
}

const tampered = structuredClone(fixture.signed);
tampered.credentialSubject.id = "did:example:changed";
const tamperedResult = await jsigs.verify(tampered, {
  suite,
  purpose,
  documentLoader,
});
if (tamperedResult.verified) {
  throw new Error("tampered Data Integrity document was accepted");
}

void localCredentialContext;
console.log("standard Data Integrity cross-language fixture passed");
