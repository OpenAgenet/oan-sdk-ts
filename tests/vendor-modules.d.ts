declare module "jsonld-signatures" {
  const value: any;
  export default value;
}

declare module "@digitalbazaar/ed25519-signature-2020" {
  export const Ed25519Signature2020: any;
}

declare module "@digitalbazaar/ed25519-verification-key-2020" {
  export const Ed25519VerificationKey2020: any;
}

declare module "ed25519-signature-2020-context" {
  export const documentLoader: (url: string) => Promise<any>;
}
