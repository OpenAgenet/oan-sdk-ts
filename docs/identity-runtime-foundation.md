# Edge identity foundation (development)

`OanSigner` and `createJwkOanSigner` expose a trusted prepared-input interface without returning private JWKs. `signDidOanDataIntegrity` accepts `options.signer`, and `signDidDocumentProof` accepts public identity fields plus `{ signer }`. Existing private-key calls remain supported. The JSON-LD suite constructs the signing bytes. Returned signatures are checked against the injected public key and expected key ID.

`verifyPinnedDidDocument` produces a structured proof verification report using a caller-pinned public key and trusted document loader. It explicitly leaves registration trust unchecked. It does not replace VC, ResourcePackage, Root/governance, revocation, or current-status verification. A report's `valid` field covers the performed checks only.

`IdentityMessageContext` is an experimental edge context mirrored in Rust `oan_protocol::identity_runtime`. It belongs inside an existing authenticated message body; it does not change registration hashes, HTTP service envelope proofs, or current deployed APIs. The fixture is synthetic test data, not a deployed resource.

Full signer injection through registration challenge/controller helpers and complete evidence verification remain subsequent implementation work. Do not expose the trusted signer interface as an agent tool; Runtime policy and SignIntent sit above it.
