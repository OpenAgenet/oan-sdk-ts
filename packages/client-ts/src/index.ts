// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  CapabilityTagNormalizeResponse,
  CapabilityTagSuggestionResponse,
  CdnStatusResponse,
  DiscoveryIndexResourceListResponse,
  DiscoverySuggestionInput,
  DiscoverySuggestionResult,
  DiscoveryAuthorizedDomainsResponse,
  ResourceDiscoveryExplainResponse,
  DiscoveryStatusResponse,
  DiscoveryVisibilityResponse,
  OanLifecycleSnapshot,
  OanWorkflowStage,
  RegistrationDomainCatalogResponse,
  RegistrationSuggestionInput,
  RegistrationSuggestionResult,
  RegistrarResourceListResponse,
  RegistrarStatusResponse,
  ResourceCdnIndexResponse,
  ResourceRegistrationResponse,
  ResourceRegistrationSubmission,
  ResourceDiscoveryQuery,
  ResourceDiscoveryResponse,
  ResourcePackage,
  RootAuthorizationInspection,
  RootResourceVersionListResponse,
  RootStatusResponse,
} from "../../protocol-types/src/index.js";

export interface OanClientOptions {
  baseUrl?: string;
  registrarEndpoint?: string;
  discoveryEndpoint?: string;
  rootEndpoint?: string;
  cdnEndpoint?: string;
  fetchImpl?: typeof fetch;
}

export interface OanOfficialEndpoints {
  baseUrl: string;
  homepageEndpoint: string;
  homepageApiEndpoint: string;
  registrarEndpoint: string;
  discoveryEndpoint: string;
  rootEndpoint: string;
  cdnEndpoint: string;
  trustIndexerEndpoint: string;
}

type OanClientEndpointKey = Exclude<keyof OanClientOptions, "fetchImpl" | "baseUrl">;
type OanClientResolvedEndpoints = Required<Pick<
  OanClientOptions,
  "registrarEndpoint" | "discoveryEndpoint" | "rootEndpoint" | "cdnEndpoint"
>>;

const DEFAULT_PAGE_SIZE = 100;

export const DEFAULT_OAN_OFFICIAL_ENDPOINTS: OanOfficialEndpoints = {
  baseUrl: "https://api.openagenet.xyz",
  homepageEndpoint: "https://openagenet.xyz",
  homepageApiEndpoint: "https://api.openagenet.xyz",
  registrarEndpoint: "https://registrar.openagenet.xyz",
  discoveryEndpoint: "https://discovery.openagenet.xyz",
  rootEndpoint: "https://root.openagenet.xyz",
  cdnEndpoint: "https://cdn.openagenet.xyz",
  trustIndexerEndpoint: "https://trust.openagenet.xyz",
};

export interface ObserveLifecycleUntilVisibleOptions {
  intervalMs?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  onPoll?: (snapshot: OanLifecycleSnapshot) => void;
}

export interface BoundedPaginationOptions {
  pageSize?: number;
  maxItems?: number;
  maxPages?: number;
  timeoutMs?: number;
}

export class OanHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    public readonly body: unknown,
  ) {
    super(`OAN HTTP ${status} ${url}`);
    this.name = "OanHttpError";
  }
}

export class OanClient {
  private readonly fetchImpl: typeof fetch;
  private readonly options: OanClientResolvedEndpoints;

  constructor(options: OanClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    const baseUrl = normalizeEndpoint(options.baseUrl ?? DEFAULT_OAN_OFFICIAL_ENDPOINTS.baseUrl);
    this.options = {
      registrarEndpoint: options.registrarEndpoint ?? baseUrl,
      discoveryEndpoint: options.discoveryEndpoint ?? baseUrl,
      rootEndpoint: options.rootEndpoint ?? baseUrl,
      cdnEndpoint: options.cdnEndpoint ?? baseUrl,
    };
  }

  async registerResource(
    submission: ResourceRegistrationSubmission,
  ): Promise<ResourceRegistrationResponse> {
    return this.postJson<ResourceRegistrationResponse>(
      this.requireEndpoint("registrarEndpoint", "/resources/register"),
      submission,
    );
  }

  async discoverResources(query: ResourceDiscoveryQuery): Promise<ResourceDiscoveryResponse> {
    return this.postJson<ResourceDiscoveryResponse>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/resources/query"),
      query,
    );
  }

  async getDiscoveryResource(resourceDid: string): Promise<{ resourceDid: string; package?: ResourcePackage | null }> {
    return this.getJson(
      this.requireEndpoint("discoveryEndpoint", `/discovery/index/resources/${encodeURIComponent(resourceDid)}`),
    );
  }

  async getRegistrarStatus(): Promise<RegistrarStatusResponse> {
    return this.getJson(this.requireEndpoint("registrarEndpoint", "/registrar/status"));
  }

  async getRegistrarRootAuthorization(): Promise<RootAuthorizationInspection> {
    return this.getJson(this.requireEndpoint("registrarEndpoint", "/registrar/root-authorization"));
  }

  async getRegistrarResourcesPage(
    options: { afterDid?: string | null; limit?: number } = {},
  ): Promise<RegistrarResourceListResponse> {
    const query = new URLSearchParams();
    if (options.afterDid) {
      query.set("afterDid", options.afterDid);
    }
    query.set("limit", String(Math.trunc(options.limit ?? DEFAULT_PAGE_SIZE)));
    const queryString = query.toString();
    const suffix = queryString ? `?${queryString}` : "";
    return validateRegistrarResourceListResponse(
      await this.getJson(this.requireEndpoint("registrarEndpoint", `/resources${suffix}`)),
    );
  }

  async *iterateRegistrarResources(
    options: BoundedPaginationOptions = {},
  ): AsyncGenerator<Record<string, unknown>> {
    if (options.maxItems !== undefined && options.maxItems <= 0) {
      return;
    }
    const startedAt = Date.now();
    let afterDid: string | null | undefined = null;
    let yielded = 0;
    for (let pageCount = 0; ; pageCount += 1) {
      assertPaginationBounds("registrar_resource_list", options, pageCount, yielded, startedAt);
      const page = await this.getRegistrarResourcesPage({ afterDid, limit: options.pageSize });
      for (const item of page.items) {
        if (options.maxItems !== undefined && yielded >= options.maxItems) {
          return;
        }
        yielded += 1;
        yield item;
      }
      if (options.maxItems !== undefined && yielded >= options.maxItems) {
        return;
      }
      if (!page.hasMore) {
        return;
      }
      if (!page.nextDid || page.nextDid === afterDid) {
        throw new Error("registrar_resource_list_cursor_not_advanced");
      }
      afterDid = page.nextDid;
    }
  }

  async suggestCapabilityTags(payload: { description?: string; query?: string }): Promise<CapabilityTagSuggestionResponse> {
    return this.postJson<CapabilityTagSuggestionResponse>(
      this.requireEndpoint("registrarEndpoint", "/capability-tags/suggest"),
      payload,
    );
  }

  async normalizeCapabilityTags(tags: string[]): Promise<CapabilityTagNormalizeResponse> {
    return this.postJson<CapabilityTagNormalizeResponse>(
      this.requireEndpoint("registrarEndpoint", "/capability-tags/normalize"),
      { tags },
    );
  }

  async getRegistrationDomainCatalog(): Promise<RegistrationDomainCatalogResponse> {
    return this.getJson(this.requireEndpoint("registrarEndpoint", "/registration/domain-catalog"));
  }

  async suggestRegistrationMetadata(input: RegistrationSuggestionInput): Promise<RegistrationSuggestionResult> {
    return this.postJson<RegistrationSuggestionResult>(
      this.requireEndpoint("registrarEndpoint", "/registration/suggestions"),
      input,
    );
  }

  async suggestDiscoveryQuery(input: DiscoverySuggestionInput): Promise<DiscoverySuggestionResult> {
    return this.postJson<DiscoverySuggestionResult>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/query/suggestions"),
      input,
    );
  }

  async getRootStatus(): Promise<RootStatusResponse> {
    return this.getJson(this.requireEndpoint("rootEndpoint", "/root/status"));
  }

  async getCdnStatus(): Promise<CdnStatusResponse> {
    return this.getJson(this.requireEndpoint("cdnEndpoint", "/cdn/status"));
  }

  async getDiscoveryStatus(): Promise<DiscoveryStatusResponse> {
    return this.getJson(this.requireEndpoint("discoveryEndpoint", "/discovery/status"));
  }

  async getDiscoveryRootAuthorization(): Promise<RootAuthorizationInspection> {
    return this.getJson(this.requireEndpoint("discoveryEndpoint", "/discovery/root-authorization"));
  }

  async getDiscoveryAuthorizedDomains(): Promise<DiscoveryAuthorizedDomainsResponse> {
    return this.getJson(this.requireEndpoint("discoveryEndpoint", "/discovery/authorized-domains"));
  }

  async getRegistrarResource(resourceDid: string): Promise<unknown> {
    const value = await this.getJson<Record<string, unknown>>(
      this.requireEndpoint("registrarEndpoint", `/resources/${encodeURIComponent(resourceDid)}`),
    );
    return value.record;
  }

  async getRootResource(resourceDid: string): Promise<unknown> {
    const value = await this.getJson<Record<string, unknown>>(
      this.requireEndpoint("rootEndpoint", `/root/resources/${encodeURIComponent(resourceDid)}`),
    );
    return value.package;
  }

  async getRootResourceVersion(resourceDid: string, version: string): Promise<{ package?: ResourcePackage | null }> {
    return this.getJson(
      this.requireEndpoint(
        "rootEndpoint",
        `/root/resources/${encodeURIComponent(resourceDid)}/versions/${encodeURIComponent(version)}`,
      ),
    );
  }

  async getRootResourceVersions(resourceDid: string): Promise<RootResourceVersionListResponse> {
    return this.getJson(
      this.requireEndpoint("rootEndpoint", `/root/resources/${encodeURIComponent(resourceDid)}/versions`),
    );
  }

  async getCdnResourcesPage(options: { afterCursor?: number; limit?: number } = {}): Promise<ResourceCdnIndexResponse> {
    const query = new URLSearchParams({
      afterCursor: String(Math.max(0, Math.trunc(options.afterCursor ?? 0))),
      limit: String(Math.trunc(options.limit ?? DEFAULT_PAGE_SIZE)),
    });
    return validateCdnIndexResponse(
      await this.getJson(this.requireEndpoint("cdnEndpoint", `/cdn/resources/index?${query.toString()}`)),
    );
  }

  async getCdnResources(): Promise<ResourceCdnIndexResponse> {
    return this.getCdnResourcesPage();
  }

  async *iterateCdnResources(options: BoundedPaginationOptions = {}): AsyncGenerator<ResourcePackage> {
    if (options.maxItems !== undefined && options.maxItems <= 0) {
      return;
    }
    const startedAt = Date.now();
    let afterCursor = 0;
    let yielded = 0;
    for (let pageCount = 0; ; pageCount += 1) {
      assertPaginationBounds("cdn_resource_index", options, pageCount, yielded, startedAt);
      const page = await this.getCdnResourcesPage({
        afterCursor,
        limit: options.pageSize,
      });
      for (const item of page.items ?? []) {
        if (options.maxItems !== undefined && yielded >= options.maxItems) {
          return;
        }
        yielded += 1;
        yield item.package;
      }
      if (options.maxItems !== undefined && yielded >= options.maxItems) {
        return;
      }
      if (!page.hasMore) {
        return;
      }
      if (page.nextCursor <= afterCursor) {
        throw new Error("cdn_resource_index_cursor_not_advanced");
      }
      afterCursor = page.nextCursor;
    }
  }

  async getDiscoveryIndexResourcesPage(
    options: { afterCursor?: number; afterResourceDid?: string | null; limit?: number } = {},
  ): Promise<DiscoveryIndexResourceListResponse> {
    const query = new URLSearchParams({
      afterCursor: String(Math.max(0, Math.trunc(options.afterCursor ?? 0))),
      limit: String(Math.trunc(options.limit ?? DEFAULT_PAGE_SIZE)),
    });
    if (options.afterResourceDid) {
      query.set("afterResourceDid", options.afterResourceDid);
    }
    return validateDiscoveryIndexResourceListResponse(
      await this.getJson(this.requireEndpoint("discoveryEndpoint", `/discovery/index/resources?${query.toString()}`)),
    );
  }

  async *iterateDiscoveryIndexResources(
    options: BoundedPaginationOptions = {},
  ): AsyncGenerator<Record<string, unknown>> {
    if (options.maxItems !== undefined && options.maxItems <= 0) {
      return;
    }
    const startedAt = Date.now();
    let afterCursor = 0;
    let afterResourceDid: string | null | undefined = null;
    let yielded = 0;
    for (let pageCount = 0; ; pageCount += 1) {
      assertPaginationBounds("discovery_index_resources", options, pageCount, yielded, startedAt);
      const page = await this.getDiscoveryIndexResourcesPage({
        afterCursor,
        afterResourceDid,
        limit: options.pageSize,
      });
      for (const item of page.items) {
        if (options.maxItems !== undefined && yielded >= options.maxItems) {
          return;
        }
        yielded += 1;
        yield item;
      }
      if (options.maxItems !== undefined && yielded >= options.maxItems) {
        return;
      }
      if (!page.hasMore) {
        return;
      }
      if (page.nextCursor < afterCursor) {
        throw new Error("discovery_index_cursor_not_advanced");
      }
      if (page.nextCursor === afterCursor && page.nextResourceDid === afterResourceDid) {
        throw new Error("discovery_index_cursor_not_advanced");
      }
      afterCursor = page.nextCursor;
      afterResourceDid = page.nextResourceDid ?? null;
    }
  }

  async getCdnResourcePackage(resourceDid: string): Promise<ResourcePackage | null> {
    try {
      return await this.getJson<ResourcePackage>(
        this.requireEndpoint("cdnEndpoint", `/cdn/resources/${encodeURIComponent(resourceDid)}`),
      );
    } catch (error) {
      if (error instanceof OanHttpError && error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  async getDiscoveryVisibility(resourceDid: string): Promise<DiscoveryVisibilityResponse> {
    return this.postJson<DiscoveryVisibilityResponse>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/index/resources/visibility"),
      { resourceDids: [resourceDid] },
    );
  }

  async explainDiscoveryQuery(query: ResourceDiscoveryQuery): Promise<ResourceDiscoveryExplainResponse> {
    return this.postJson<ResourceDiscoveryExplainResponse>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/query/explain"),
      query,
    );
  }

  async observeLifecycle(resourceDid: string): Promise<OanLifecycleSnapshot> {
    const [registrarStatus, rootStatus, cdnStatus, discoveryStatus] = await Promise.all([
      this.tryGet(() => this.getRegistrarStatus()),
      this.tryGet(() => this.getRootStatus()),
      this.tryGet(() => this.getCdnStatus()),
      this.tryGet(() => this.getDiscoveryStatus()),
    ]);

    const [registrarRecord, rootResource, rootVersions, cdnPackage, discoveryVisibility] = await Promise.all([
      this.tryGet(() => this.getRegistrarResource(resourceDid)),
      this.tryGet(() => this.getRootResource(resourceDid)),
      this.tryGet(() => this.getRootResourceVersions(resourceDid)),
      this.tryGet(() => this.getCdnResourcePackage(resourceDid)),
      this.tryGet(() => this.getDiscoveryVisibility(resourceDid)),
    ]);

    const observations: string[] = [];
    const registrarAccepted = registrarRecord !== undefined && registrarRecord !== null;
    const rootVersionObserved = Array.isArray(rootVersions?.items) && rootVersions.items.length > 0;
    const rootObserved = (rootResource !== undefined && rootResource !== null) || rootVersionObserved;
    const cdnObserved = cdnPackage !== undefined && cdnPackage !== null;
    const visibleList = Array.isArray(discoveryVisibility?.visible)
      ? discoveryVisibility.visible.map(String)
      : [];
    const discoveryVisible = visibleList.includes(resourceDid);
    if (registrarAccepted) observations.push("registrar record exists");
    if (rootObserved) observations.push("root package exists");
    if (rootVersionObserved && (rootResource === undefined || rootResource === null)) {
      observations.push("root version history exists");
    }
    if (cdnObserved) observations.push("cdn package exists");
    if (discoveryVisible) observations.push("discovery index visibility confirmed");
    if (!rootObserved && registrarAccepted && hasQueuedRootWork(rootStatus)) {
      observations.push("root status indicates queued publication work");
    }

    return {
      resourceDid,
      registrarAccepted,
      rootObserved,
      cdnObserved,
      discoveryVisible,
      stage: deriveWorkflowStage({
        registrarAccepted,
        rootObserved,
        cdnObserved,
        discoveryVisible,
        rootStatus,
      }),
      registrarRecord,
      rootResource,
      rootVersions,
      cdnPackage,
      discoveryVisibility,
      registrarStatus,
      rootStatus,
      cdnStatus,
      discoveryStatus,
      observations,
    };
  }

  async observeLifecycleUntilVisible(
    resourceDid: string,
    options: ObserveLifecycleUntilVisibleOptions = {},
  ): Promise<OanLifecycleSnapshot> {
    const startedAt = Date.now();
    const intervalMs = Math.max(50, options.intervalMs ?? 1000);
    const timeoutMs = Math.max(intervalMs, options.timeoutMs ?? 30000);

    for (;;) {
      if (options.signal?.aborted) {
        throw new Error("observe_lifecycle_aborted");
      }
      const snapshot = await this.observeLifecycle(resourceDid);
      options.onPoll?.(snapshot);
      if (snapshot.discoveryVisible) {
        return snapshot;
      }
      if (Date.now() - startedAt >= timeoutMs) {
        return {
          ...snapshot,
          stage: snapshot.stage === "visible-in-discovery" ? snapshot.stage : "visibility-pending",
          observations: [...(snapshot.observations ?? []), `timed out after ${timeoutMs}ms`],
        };
      }
      await sleep(intervalMs, options.signal);
    }
  }

  private requireEndpoint(key: OanClientEndpointKey, path: string): string {
    const endpoint = this.options[key];
    if (typeof endpoint !== "string" || endpoint.trim() === "") {
      throw new Error(`missing_${String(key)}`);
    }
    return `${normalizeEndpoint(endpoint)}${path}`;
  }

  private async getJson<T>(url: string): Promise<T> {
    const response = await this.fetchImpl(url);
    const body = await response.json();
    if (!response.ok) {
      throw new OanHttpError(response.status, url, body);
    }
    return body as T;
  }

  private async postJson<T>(url: string, payload: unknown): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json();
    if (!response.ok) {
      throw new OanHttpError(response.status, url, body);
    }
    return body as T;
  }

  private async tryGet<T>(fn: () => Promise<T>): Promise<T | undefined> {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof OanHttpError && error.status === 404) {
        return undefined;
      }
      return undefined;
    }
  }
}

function normalizeEndpoint(endpoint: string): string {
  return endpoint.trim().replace(/\/+$/, "");
}

function deriveWorkflowStage(input: {
  registrarAccepted: boolean;
  rootObserved: boolean;
  cdnObserved: boolean;
  discoveryVisible: boolean;
  rootStatus?: RootStatusResponse;
}): OanWorkflowStage {
  if (input.discoveryVisible) return "visible-in-discovery";
  if (input.cdnObserved) return "published-to-cdn";
  if (input.rootObserved) return "accepted-by-root";
  if (input.registrarAccepted && hasQueuedRootWork(input.rootStatus)) return "queued-at-root";
  if (input.registrarAccepted) return "accepted-by-registrar";
  return "submitted-to-registrar";
}

export function normalizeWorkflowStage(snapshot: OanLifecycleSnapshot): OanWorkflowStage {
  return snapshot.stage;
}

function hasQueuedRootWork(rootStatus?: RootStatusResponse): boolean {
  if (!rootStatus) return false;
  const counters = [
    rootStatus.cdnQueueCount,
    rootStatus.cdnReadyQueueCount,
    rootStatus.cdnActiveQueueCount,
    rootStatus.discoveryQueueCount,
    rootStatus.discoveryReadyQueueCount,
    rootStatus.discoveryPendingQueueCount,
  ];
  return counters.some((value) => typeof value === "number" && value > 0);
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = () => {
      cleanup();
      reject(new Error("observe_lifecycle_aborted"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function assertPaginationBounds(
  name: string,
  options: BoundedPaginationOptions,
  pageCount: number,
  yielded: number,
  startedAt: number,
): void {
  if (options.maxPages !== undefined && pageCount >= options.maxPages) {
    throw new Error(`${name}_max_pages_exceeded`);
  }
  if (options.timeoutMs !== undefined && Date.now() - startedAt >= options.timeoutMs) {
    throw new Error(`${name}_timeout`);
  }
}

function validateRegistrarResourceListResponse(value: unknown): RegistrarResourceListResponse {
  const page = asRecord(value, "registrar_resource_list_invalid_response");
  if (
    !Array.isArray(page.items) ||
    typeof page.count !== "number" ||
    page.count < 0 ||
    page.count !== page.items.length ||
    typeof page.hasMore !== "boolean" ||
    page.items.some((item) => !item || typeof item !== "object" || Array.isArray(item))
  ) {
    throw new Error("registrar_resource_list_invalid_response");
  }
  if (page.afterDid !== null && page.afterDid !== undefined && typeof page.afterDid !== "string") {
    throw new Error("registrar_resource_list_invalid_response");
  }
  if (page.nextDid !== null && page.nextDid !== undefined && typeof page.nextDid !== "string") {
    throw new Error("registrar_resource_list_invalid_response");
  }
  return page as unknown as RegistrarResourceListResponse;
}

function validateCdnIndexResponse(value: unknown): ResourceCdnIndexResponse {
  const page = asRecord(value, "cdn_resource_index_invalid_response");
  if (
    !Array.isArray(page.items) ||
    typeof page.count !== "number" ||
    page.count < 0 ||
    page.count !== page.items.length ||
    typeof page.afterCursor !== "number" ||
    page.afterCursor < 0 ||
    typeof page.nextCursor !== "number" ||
    page.nextCursor < 0 ||
    typeof page.hasMore !== "boolean"
  ) {
    throw new Error("cdn_resource_index_invalid_response");
  }
  if (
    page.items.some(
      (item) => {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          return true;
        }
        const record = item as Record<string, unknown>;
        return typeof record.cursor !== "number" || record.cursor < 0 || !("package" in record);
      },
    )
  ) {
    throw new Error("cdn_resource_index_invalid_response");
  }
  return page as unknown as ResourceCdnIndexResponse;
}

function validateDiscoveryIndexResourceListResponse(value: unknown): DiscoveryIndexResourceListResponse {
  const page = asRecord(value, "discovery_index_resources_invalid_response");
  if (
    !Array.isArray(page.items) ||
    typeof page.count !== "number" ||
    page.count < 0 ||
    page.count !== page.items.length ||
    typeof page.afterCursor !== "number" ||
    page.afterCursor < 0 ||
    typeof page.nextCursor !== "number" ||
    page.nextCursor < 0 ||
    typeof page.hasMore !== "boolean"
  ) {
    throw new Error("discovery_index_resources_invalid_response");
  }
  if (
    page.items.some(
      (item) => !item || typeof item !== "object" || Array.isArray(item),
    )
  ) {
    throw new Error("discovery_index_resources_invalid_response");
  }
  if (
    page.afterResourceDid !== null &&
    page.afterResourceDid !== undefined &&
    typeof page.afterResourceDid !== "string"
  ) {
    throw new Error("discovery_index_resources_invalid_response");
  }
  if (
    page.nextResourceDid !== null &&
    page.nextResourceDid !== undefined &&
    typeof page.nextResourceDid !== "string"
  ) {
    throw new Error("discovery_index_resources_invalid_response");
  }
  return page as unknown as DiscoveryIndexResourceListResponse;
}

function asRecord(value: unknown, errorCode: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(errorCode);
  }
  return value as Record<string, unknown>;
}
