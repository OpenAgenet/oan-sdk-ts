// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  CapabilityTagSuggestionResponse,
  CdnStatusResponse,
  DiscoveryAuthorizedDomainsResponse,
  ResourceDiscoveryExplainResponse,
  DiscoveryStatusResponse,
  DiscoveryVisibilityResponse,
  OanLifecycleSnapshot,
  OanWorkflowStage,
  RegistrarStatusResponse,
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
  registrarEndpoint?: string;
  discoveryEndpoint?: string;
  rootEndpoint?: string;
  cdnEndpoint?: string;
  fetchImpl?: typeof fetch;
}

export interface ObserveLifecycleUntilVisibleOptions {
  intervalMs?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  onPoll?: (snapshot: OanLifecycleSnapshot) => void;
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

  constructor(private readonly options: OanClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
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

  async suggestCapabilityTags(payload: { description?: string; query?: string }): Promise<CapabilityTagSuggestionResponse> {
    return this.postJson<CapabilityTagSuggestionResponse>(
      this.requireEndpoint("registrarEndpoint", "/capability-tags/suggest"),
      payload,
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

  async getCdnResources(): Promise<{ items?: ResourcePackage[]; resources?: Record<string, ResourcePackage> }> {
    return this.getJson(this.requireEndpoint("cdnEndpoint", "/cdn/resources/index"));
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

    const [registrarRecord, rootResource, cdnPackage, discoveryVisibility] = await Promise.all([
      this.tryGet(() => this.getRegistrarResource(resourceDid)),
      this.tryGet(() => this.getRootResource(resourceDid)),
      this.tryGet(() => this.getCdnResourcePackage(resourceDid)),
      this.tryGet(() => this.getDiscoveryVisibility(resourceDid)),
    ]);

    const observations: string[] = [];
    const registrarAccepted = registrarRecord !== undefined && registrarRecord !== null;
    const rootObserved = rootResource !== undefined && rootResource !== null;
    const cdnObserved = cdnPackage !== undefined && cdnPackage !== null;
    const visibleList = Array.isArray(discoveryVisibility?.visible)
      ? discoveryVisibility.visible.map(String)
      : [];
    const discoveryVisible = visibleList.includes(resourceDid);
    if (registrarAccepted) observations.push("registrar record exists");
    if (rootObserved) observations.push("root package exists");
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

  private requireEndpoint(key: keyof OanClientOptions, path: string): string {
    const endpoint = this.options[key];
    if (typeof endpoint !== "string" || endpoint.trim() === "") {
      throw new Error(`missing_${String(key)}`);
    }
    return `${endpoint.replace(/\/+$/, "")}${path}`;
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
