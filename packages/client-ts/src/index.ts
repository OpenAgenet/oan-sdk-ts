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
  /** Total polling budget, including requests, response bodies, and waits. */
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

  async getRegistrarStatus(signal?: AbortSignal): Promise<RegistrarStatusResponse> {
    return this.getJson(this.requireEndpoint("registrarEndpoint", "/registrar/status"), signal);
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

  async getRootStatus(signal?: AbortSignal): Promise<RootStatusResponse> {
    return this.getJson(this.requireEndpoint("rootEndpoint", "/root/status"), signal);
  }

  async getCdnStatus(signal?: AbortSignal): Promise<CdnStatusResponse> {
    return this.getJson(this.requireEndpoint("cdnEndpoint", "/cdn/status"), signal);
  }

  async getDiscoveryStatus(signal?: AbortSignal): Promise<DiscoveryStatusResponse> {
    return this.getJson(this.requireEndpoint("discoveryEndpoint", "/discovery/status"), signal);
  }

  async getDiscoveryRootAuthorization(): Promise<RootAuthorizationInspection> {
    return this.getJson(this.requireEndpoint("discoveryEndpoint", "/discovery/root-authorization"));
  }

  async getDiscoveryAuthorizedDomains(): Promise<DiscoveryAuthorizedDomainsResponse> {
    return this.getJson(this.requireEndpoint("discoveryEndpoint", "/discovery/authorized-domains"));
  }

  async getRegistrarResource(resourceDid: string, signal?: AbortSignal): Promise<unknown> {
    const value = await this.getJson<Record<string, unknown>>(
      this.requireEndpoint("registrarEndpoint", `/resources/${encodeURIComponent(resourceDid)}`),
      signal,
    );
    return value.record;
  }

  async getRootResource(resourceDid: string, signal?: AbortSignal): Promise<unknown> {
    const value = await this.getJson<Record<string, unknown>>(
      this.requireEndpoint("rootEndpoint", `/root/resources/${encodeURIComponent(resourceDid)}`),
      signal,
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

  async getRootResourceVersions(resourceDid: string, signal?: AbortSignal): Promise<RootResourceVersionListResponse> {
    return this.getJson(
      this.requireEndpoint("rootEndpoint", `/root/resources/${encodeURIComponent(resourceDid)}/versions`),
      signal,
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

  async getCdnResourcePackage(resourceDid: string, signal?: AbortSignal): Promise<ResourcePackage | null> {
    try {
      return await this.getJson<ResourcePackage>(
        this.requireEndpoint("cdnEndpoint", `/cdn/resources/${encodeURIComponent(resourceDid)}`),
        signal,
      );
    } catch (error) {
      if (error instanceof OanHttpError && error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  async getDiscoveryVisibility(resourceDid: string, signal?: AbortSignal): Promise<DiscoveryVisibilityResponse> {
    return this.postJson<DiscoveryVisibilityResponse>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/index/resources/visibility"),
      { resourceDids: [resourceDid] },
      signal,
    );
  }

  async explainDiscoveryQuery(query: ResourceDiscoveryQuery): Promise<ResourceDiscoveryExplainResponse> {
    return this.postJson<ResourceDiscoveryExplainResponse>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/query/explain"),
      query,
    );
  }

  async observeLifecycle(resourceDid: string, signal?: AbortSignal): Promise<OanLifecycleSnapshot> {
    signal?.throwIfAborted();
    const [registrarStatus, rootStatus, cdnStatus, discoveryStatus] = await Promise.all([
      this.tryGet(() => this.getRegistrarStatus(signal), signal),
      this.tryGet(() => this.getRootStatus(signal), signal),
      this.tryGet(() => this.getCdnStatus(signal), signal),
      this.tryGet(() => this.getDiscoveryStatus(signal), signal),
    ]);

    signal?.throwIfAborted();
    const [registrarRecord, rootResource, rootVersions, cdnPackage, discoveryVisibility] = await Promise.all([
      this.tryGet(() => this.getRegistrarResource(resourceDid, signal), signal),
      this.tryGet(() => this.getRootResource(resourceDid, signal), signal),
      this.tryGet(() => this.getRootResourceVersions(resourceDid, signal), signal),
      this.tryGet(() => this.getCdnResourcePackage(resourceDid, signal), signal),
      this.tryGet(() => this.getDiscoveryVisibility(resourceDid, signal), signal),
    ]);
    signal?.throwIfAborted();

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
    const timeoutMs = Math.max(0, options.timeoutMs ?? 30000);
    const controller = new AbortController();
    const abortedError = new Error("observe_lifecycle_aborted");
    const timeoutError = new Error("observe_lifecycle_timeout");
    const onAbort = () => controller.abort(abortedError);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let lastSnapshot: OanLifecycleSnapshot | undefined;

    const checkStopped = () => {
      if (Date.now() - startedAt >= timeoutMs) {
        controller.abort(timeoutError);
      }
      controller.signal.throwIfAborted();
    };
    const scheduleDeadline = () => {
      if (!Number.isFinite(timeoutMs)) return;
      const remaining = timeoutMs - (Date.now() - startedAt);
      if (remaining <= 0) {
        controller.abort(timeoutError);
      } else {
        // Long budgets must not overflow the platform's timer delay.
        timer = setTimeout(scheduleDeadline, Math.min(remaining, 2 ** 31 - 1));
      }
    };

    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
    scheduleDeadline();
    try {
      for (;;) {
        checkStopped();
        const snapshot = await abortable(this.observeLifecycle(resourceDid, controller.signal), controller.signal);
        checkStopped();
        lastSnapshot = snapshot;
        options.onPoll?.(snapshot);
        checkStopped();
        if (snapshot.discoveryVisible) return snapshot;
        await sleep(intervalMs, controller.signal);
      }
    } catch (error) {
      if (controller.signal.reason === timeoutError) {
        return {
          resourceDid,
          registrarAccepted: false,
          rootObserved: false,
          cdnObserved: false,
          discoveryVisible: false,
          ...lastSnapshot,
          stage: lastSnapshot?.discoveryVisible ? "visible-in-discovery" : "visibility-pending",
          observations: [...(lastSnapshot?.observations ?? []), `timed out after ${timeoutMs}ms`],
        };
      }
      if (controller.signal.aborted) throw abortedError;
      throw error;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    }
  }

  private requireEndpoint(key: OanClientEndpointKey, path: string): string {
    const endpoint = this.options[key];
    if (typeof endpoint !== "string" || endpoint.trim() === "") {
      throw new Error(`missing_${String(key)}`);
    }
    return `${normalizeEndpoint(endpoint)}${path}`;
  }

  private async getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
    const response = await this.fetchImpl(url, { signal });
    const body = await response.json();
    if (!response.ok) {
      throw new OanHttpError(response.status, url, body);
    }
    return body as T;
  }

  private async postJson<T>(url: string, payload: unknown, signal?: AbortSignal): Promise<T> {
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal,
    });
    const body = await response.json();
    if (!response.ok) {
      throw new OanHttpError(response.status, url, body);
    }
    return body as T;
  }

  private async tryGet<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T | undefined> {
    try {
      signal?.throwIfAborted();
      const value = await fn();
      signal?.throwIfAborted();
      return value;
    } catch (error) {
      signal?.throwIfAborted();
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
      reject(signal?.reason ?? new Error("observe_lifecycle_aborted"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

// Bound the wait even when an injected fetch implementation ignores its signal.
function abortable<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    const onAbort = () => {
      cleanup();
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
    pending.then(
      (value) => { cleanup(); resolve(value); },
      (error) => { cleanup(); reject(error); },
    );
    if (signal.aborted) onAbort();
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
