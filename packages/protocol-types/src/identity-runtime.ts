// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

/** Experimental edge identity context, carried inside existing signed envelopes.
 * This does not change Registrar/Discovery wire contracts or proof algorithms.
 */
export interface IdentityMessageContext {
  profile: "oan-message-v1";
  senderDid: string;
  audienceDid: string;
  purpose: "request" | "response" | "challenge" | "event";
  protocol: "http" | "mcp" | "a2a";
  sessionId: string;
  messageId: string;
  requestId: string;
  createdAt: string;
  expiresAt: string;
  nonce: string;
  payloadDigest: string;
}

/** A successful individual check is not equivalent to trust-chain validation. */
export interface IdentityVerificationReport {
  valid: boolean;
  checks: Array<{ name: string; status: "passed" | "failed" | "not_checked"; code?: string }>;
}
