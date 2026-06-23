// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

export type GovernanceSubjectRole = "registrar" | "discovery" | "vc_issuer" | "unknown";

export interface GovernanceDecision {
  governanceActive: boolean;
  authorized: boolean;
  reason?: string;
  subjectType?: string;
  subjectTypeCode?: number;
  subjectDid: string;
  status?: string | null;
  effectiveFromMs?: number | null;
  expiresAtMs?: number | null;
  scope?: string;
  note?: string;
  interpretation?: string;
}

export interface GovernanceSummary {
  [key: string]: unknown;
}

export interface GovernanceSubjectListResponse {
  subjects?: Array<Record<string, unknown>>;
}

export interface GovernanceClientOptions {
  trustIndexerEndpoint?: string;
  fetchImpl?: typeof fetch;
}

export class GovernanceHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    public readonly body: unknown,
  ) {
    super(`OAN governance HTTP ${status} ${url}`);
    this.name = "GovernanceHttpError";
  }
}

export class GovernanceClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: GovernanceClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async getSummary(): Promise<GovernanceSummary> {
    return this.getJson(this.requireEndpoint("/v1/summary"));
  }

  async getStatus(): Promise<Record<string, unknown>> {
    return this.getJson(this.requireEndpoint("/v1/status"));
  }

  async listRegistrars(params: { status?: string; domain?: string } = {}): Promise<GovernanceSubjectListResponse> {
    return this.getJson(this.requireEndpoint(`/v1/registrars${buildQuery(params)}`));
  }

  async listDiscoveries(params: { status?: string; domain?: string } = {}): Promise<GovernanceSubjectListResponse> {
    return this.getJson(this.requireEndpoint(`/v1/discoveries${buildQuery(params)}`));
  }

  async listVcIssuers(params: { status?: string; domain?: string } = {}): Promise<GovernanceSubjectListResponse> {
    return this.getJson(this.requireEndpoint(`/v1/vc-issuers${buildQuery(params)}`));
  }

  async getGovernanceDecision(subjectType: number, subjectDid: string): Promise<GovernanceDecision> {
    const value = await this.getJson<Record<string, unknown>>(
      this.requireEndpoint(
        `/v1/subjects/${encodeURIComponent(String(subjectType))}/${encodeURIComponent(subjectDid)}/governance-active`,
      ),
    );
    return {
      governanceActive: Boolean(value.governance_active),
      authorized: Boolean(value.authorized),
      reason: stringOrUndefined(value.reason),
      subjectType: stringOrUndefined(value.subject_type),
      subjectTypeCode: numberOrUndefined(value.subject_type_code),
      subjectDid: String(value.subject_did ?? subjectDid),
      status: stringOrUndefined(value.status) ?? null,
      effectiveFromMs: numberOrUndefined(value.effective_from_ms) ?? null,
      expiresAtMs: numberOrUndefined(value.expires_at_ms) ?? null,
      scope: stringOrUndefined(value.scope),
      note: stringOrUndefined(value.note),
      interpretation:
        "Governance-visible chain state only. This does not by itself prove current Root-issued operational authorization.",
    };
  }

  private requireEndpoint(path: string): string {
    const endpoint = this.options.trustIndexerEndpoint;
    if (typeof endpoint !== "string" || endpoint.trim() === "") {
      throw new Error("missing_trustIndexerEndpoint");
    }
    return `${endpoint.replace(/\/+$/, "")}${path}`;
  }

  private async getJson<T>(url: string): Promise<T> {
    const response = await this.fetchImpl(url);
    const body = await response.json();
    if (!response.ok) {
      throw new GovernanceHttpError(response.status, url, body);
    }
    return body as T;
  }
}

export function subjectTypeCodeForRole(role: GovernanceSubjectRole): number | undefined {
  if (role === "registrar") return 1;
  if (role === "discovery") return 2;
  if (role === "vc_issuer") return 3;
  return undefined;
}

function buildQuery(params: Record<string, string | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === "string" && value.length > 0) {
      search.set(key, value);
    }
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
