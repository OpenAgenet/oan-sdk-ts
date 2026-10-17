/** Trusted SDK/Runtime interface. Never expose this byte-signing API as an agent tool. */
export interface OanSigner {
  readonly keyId: string;
  readonly algorithm: "Ed25519";
  publicKey(): Promise<Record<string, unknown>>;
  signPreparedInput(input: Uint8Array): Promise<Uint8Array>;
}

/** Compatibility adapter; the resulting signer never returns its private JWK. */
export async function createJwkOanSigner(
  keyId: string,
  privateKeyJwk: JsonWebKey,
): Promise<OanSigner> {
  if (privateKeyJwk.kty !== "OKP" || privateKeyJwk.crv !== "Ed25519" || !privateKeyJwk.d || !privateKeyJwk.x) {
    throw new Error("invalid_ed25519_private_jwk");
  }
  const key = await globalThis.crypto.subtle.importKey("jwk", privateKeyJwk, "Ed25519", false, ["sign"]);
  const publicJwk = { kty: "OKP", crv: "Ed25519", x: privateKeyJwk.x };
  return {
    keyId,
    algorithm: "Ed25519",
    async publicKey() { return { ...publicJwk }; },
    async signPreparedInput(input) {
      return new Uint8Array(await globalThis.crypto.subtle.sign("Ed25519", key, new Uint8Array(input)));
    },
  };
}

/** Adapt to the existing JSON-LD suite: its canonicalization remains authoritative. */
export async function asDataIntegritySigner(signer: OanSigner, expectedKeyId: string) {
  if (signer.algorithm !== "Ed25519" || signer.keyId !== expectedKeyId) {
    throw new Error("signer_key_binding_mismatch");
  }
  const jwk = await signer.publicKey();
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || "d" in jwk) {
    throw new Error("invalid_signer_public_key");
  }
  const key = await globalThis.crypto.subtle.importKey("jwk", jwk, "Ed25519", false, ["verify"]);
  return {
    id: signer.keyId,
    async sign({ data }: { data: Uint8Array }) {
      const prepared = new Uint8Array(data);
      const signature = new Uint8Array(await signer.signPreparedInput(new Uint8Array(prepared)));
      if (signature.length !== 64 || !await globalThis.crypto.subtle.verify("Ed25519", key, signature, prepared)) {
        throw new Error("invalid_signer_signature");
      }
      return signature;
    },
  };
}
