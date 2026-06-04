// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type {
  ResourceDiscoveryQuery,
  ResourceDiscoveryResponse,
  ResourcePackage,
} from "../../protocol-types/src/index";

export interface OanClientOptions {
  registrarEndpoint?: string;
  discoveryEndpoint?: string;
  rootEndpoint?: string;
  cdnEndpoint?: string;
  fetchImpl?: typeof fetch;
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

  async discoverResources(query: ResourceDiscoveryQuery): Promise<ResourceDiscoveryResponse> {
    return this.postJson<ResourceDiscoveryResponse>(
      this.requireEndpoint("discoveryEndpoint", "/discovery/resources/query"),
      query,
    );
  }

  async syncDiscoveryResources(): Promise<unknown> {
    return this.postJson(
      this.requireEndpoint("discoveryEndpoint", "/discovery/resources/sync"),
      {},
    );
  }

  async getDiscoveryResource(resourceDid: string): Promise<{ resourceDid: string; package?: ResourcePackage | null }> {
    return this.getJson(
      this.requireEndpoint("discoveryEndpoint", `/discovery/index/resources/${encodeURIComponent(resourceDid)}`),
    );
  }

  async getRootResourceVersion(resourceDid: string, version: string): Promise<{ package?: ResourcePackage | null }> {
    return this.getJson(
      this.requireEndpoint(
        "rootEndpoint",
        `/root/resources/${encodeURIComponent(resourceDid)}/versions/${encodeURIComponent(version)}`,
      ),
    );
  }

  async getCdnResources(): Promise<{ items?: ResourcePackage[]; resources?: Record<string, ResourcePackage> }> {
    return this.getJson(this.requireEndpoint("cdnEndpoint", "/cdn/resources/index"));
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
}
