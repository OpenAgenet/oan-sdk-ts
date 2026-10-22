// Copyright (c) 2026 OpenAgenet contributors

import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import test from "node:test";
import { OanClient } from "../packages/client-ts/src/index.js";
import type { OanLifecycleSnapshot } from "../packages/protocol-types/src/index.js";

const resourceDid = "did:oan:test:resource";
const testOptions = { timeout: 2000 };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

// Bound regressions even when an injected fetch never settles or observes abort.
async function bounded<T>(promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("poll did not settle promptly")), 500);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function responseFor(input: RequestInfo | URL, visible = true): Response {
  const path = new URL(String(input)).pathname;
  let body: unknown = { status: "ok" };
  if (path.endsWith("/visibility")) body = { visible: visible ? [resourceDid] : [] };
  else if (path.endsWith("/versions")) body = { items: [] };
  else if (path.startsWith("/root/resources/")) body = { package: { resourceDid } };
  else if (path.startsWith("/resources/")) body = { record: { resourceDid } };
  else if (path.startsWith("/cdn/resources/")) body = { resourceDid };
  return Response.json(body);
}

function clientWith(fetchImpl: typeof fetch): OanClient {
  return new OanClient({ baseUrl: "https://oan.example", fetchImpl });
}

interface PendingRequest {
  url: string;
  init?: RequestInit;
}

function pendingRequests(count: number) {
  const requests: PendingRequest[] = [];
  const started = deferred<void>();
  const fetchImpl: typeof fetch = (input, init) => {
    requests.push({ url: String(input), init });
    if (requests.length === count) started.resolve(undefined);
    return new Promise<Response>((_, reject) => {
      const signal = init?.signal;
      const abort = () => reject(new DOMException("The operation was aborted", "AbortError"));
      if (signal?.aborted) abort();
      else signal?.addEventListener("abort", abort, { once: true });
    });
  };
  return { requests, started: started.promise, fetchImpl };
}

function assertAborted(requests: PendingRequest[], count: number): void {
  assert.equal(requests.length, count);
  for (const { init } of requests) {
    assert.ok(init?.signal instanceof AbortSignal, "each request receives an AbortSignal");
    assert.equal(init.signal.aborted, true);
  }
}

function assertTimedOut(snapshot: OanLifecycleSnapshot, timeoutMs: number): void {
  assert.equal(snapshot.resourceDid, resourceDid);
  assert.equal(snapshot.stage, "visibility-pending");
  assert.equal(snapshot.discoveryVisible, false);
  assert.ok(snapshot.observations?.includes(`timed out after ${timeoutMs}ms`));
}

test("a pre-aborted signal rejects without issuing requests", testOptions, async () => {
  const controller = new AbortController();
  controller.abort();
  let requests = 0;
  const client = clientWith(async (input) => { requests += 1; return responseFor(input); });
  await assert.rejects(client.observeLifecycleUntilVisible(resourceDid, {
    signal: controller.signal,
  }), { message: "observe_lifecycle_aborted" });
  assert.equal(requests, 0);
});

test("cancellation aborts all four pending status requests", testOptions, async () => {
  const pending = pendingRequests(4);
  const controller = new AbortController();
  const result = clientWith(pending.fetchImpl).observeLifecycleUntilVisible(resourceDid, {
    signal: controller.signal,
  });
  const rejected = assert.rejects(result, { message: "observe_lifecycle_aborted" });
  await bounded(pending.started);
  controller.abort();
  await bounded(rejected);
  assertAborted(pending.requests, 4);
});

test("cancellation reaches resource GETs and the visibility POST", testOptions, async () => {
  const pending = pendingRequests(5);
  const controller = new AbortController();
  const client = clientWith((input, init) => new URL(String(input)).pathname.endsWith("/status")
    ? Promise.resolve(responseFor(input))
    : pending.fetchImpl(input, init));
  const result = client.observeLifecycleUntilVisible(resourceDid, { signal: controller.signal });
  const rejected = assert.rejects(result, { message: "observe_lifecycle_aborted" });
  await bounded(pending.started);
  controller.abort();
  await bounded(rejected);
  assertAborted(pending.requests, 5);
  const visibility = pending.requests.find(({ url }) => url.endsWith("/visibility"));
  assert.equal(visibility?.init?.method, "POST");
  assert.deepEqual(JSON.parse(String(visibility?.init?.body)), { resourceDids: [resourceDid] });
});

test("cancellation interrupts a pending JSON response body", testOptions, async () => {
  const controller = new AbortController();
  const reading = deferred<void>();
  let body!: ReadableStreamDefaultController<Uint8Array>;
  const client = clientWith(async (input) => {
    if (String(input).endsWith("/registrar/status")) {
      return new Response(new ReadableStream<Uint8Array>({
        start(value) { body = value; },
        pull() { reading.resolve(undefined); },
      }));
    }
    return responseFor(input);
  });
  const result = client.observeLifecycleUntilVisible(resourceDid, { signal: controller.signal });
  const rejected = assert.rejects(result, { message: "observe_lifecycle_aborted" });
  await bounded(reading.promise);
  controller.abort();
  try {
    await bounded(rejected);
  } finally {
    body.error(new Error("test cleanup"));
  }
});

test("a deadline shorter than the interval aborts pending requests", testOptions, async () => {
  const pending = pendingRequests(4);
  const snapshot = await bounded(clientWith(pending.fetchImpl).observeLifecycleUntilVisible(resourceDid, {
    intervalMs: 1000,
    timeoutMs: 20,
  }));
  assertTimedOut(snapshot, 20);
  assert.equal(snapshot.registrarAccepted, false);
  assert.equal(snapshot.rootObserved, false);
  assert.equal(snapshot.cdnObserved, false);
  assertAborted(pending.requests, 4);
});

test("the deadline bounds fetch implementations that ignore AbortSignal", testOptions, async () => {
  let requests = 0;
  const client = clientWith(() => {
    requests += 1;
    return new Promise<Response>(() => {});
  });
  const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid, {
    intervalMs: 1000,
    timeoutMs: 20,
  }));
  assertTimedOut(snapshot, 20);
  assert.equal(requests, 4);
});

test("late status responses cannot start another batch after timeout", testOptions, async () => {
  const requests: Array<{ response: Response; pending: ReturnType<typeof deferred<Response>> }> = [];
  let polls = 0;
  const client = clientWith((input) => {
    const pending = deferred<Response>();
    requests.push({ response: responseFor(input), pending });
    return pending.promise;
  });
  const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid, {
    intervalMs: 1000,
    timeoutMs: 20,
    onPoll() { polls += 1; },
  }));
  assertTimedOut(snapshot, 20);
  assert.equal(requests.length, 4);
  for (const { response, pending } of requests) pending.resolve(response);
  // Drain the response-body continuations after the original fetches resolve.
  await bounded(new Promise<void>((resolve) => setImmediate(resolve)));
  assert.equal(requests.length, 4);
  assert.equal(polls, 0);
});

test("the deadline bounds a stalled body and removes the caller's listener", testOptions, async () => {
  const controller = new AbortController();
  let body!: ReadableStreamDefaultController<Uint8Array>;
  const client = clientWith(async (input) => {
    if (String(input).endsWith("/registrar/status")) {
      return new Response(new ReadableStream<Uint8Array>({ start(value) { body = value; } }));
    }
    return responseFor(input);
  });
  try {
    const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid, {
      intervalMs: 1000,
      timeoutMs: 20,
      signal: controller.signal,
    }));
    assertTimedOut(snapshot, 20);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  } finally {
    controller.abort();
    body.error(new Error("test cleanup"));
  }
});

test("the deadline preserves the last complete snapshot during a later stalled poll", testOptions, async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: 0 });
  const pending = pendingRequests(4);
  const firstPolled = deferred<void>();
  let firstSnapshot: OanLifecycleSnapshot | undefined;
  const client = clientWith((input, init) => firstSnapshot
    ? pending.fetchImpl(input, init)
    : Promise.resolve(responseFor(input, false)));
  const result = client.observeLifecycleUntilVisible(resourceDid, {
    intervalMs: 50,
    timeoutMs: 80,
    onPoll(value) { firstSnapshot = value; firstPolled.resolve(undefined); },
  });
  await firstPolled.promise;
  t.mock.timers.tick(50);
  await pending.started;
  t.mock.timers.tick(30);
  const snapshot = await result;
  assert.ok(firstSnapshot);
  assertTimedOut(snapshot, 80);
  assert.equal(snapshot.registrarAccepted, true);
  assert.equal(snapshot.rootObserved, true);
  assert.equal(snapshot.cdnObserved, true);
  assert.deepEqual(snapshot.registrarRecord, firstSnapshot.registrarRecord);
  assert.deepEqual(snapshot.observations, [...firstSnapshot.observations!, "timed out after 80ms"]);
  assertAborted(pending.requests, 4);
});

test("the deadline interrupts the interval without starting another poll", testOptions, async () => {
  let requests = 0;
  let polls = 0;
  const client = clientWith(async (input) => { requests += 1; return responseFor(input, false); });
  const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid, {
    intervalMs: 1000,
    timeoutMs: 20,
    onPoll() { polls += 1; },
  }));
  assertTimedOut(snapshot, 20);
  assert.equal(polls, 1);
  assert.equal(requests, 9);
});

test("cancellation from onPoll takes precedence over a visible snapshot", testOptions, async () => {
  const controller = new AbortController();
  let polls = 0;
  const client = clientWith(async (input) => responseFor(input));
  await bounded(assert.rejects(client.observeLifecycleUntilVisible(resourceDid, {
    signal: controller.signal,
    onPoll() { polls += 1; controller.abort(); },
  }), { message: "observe_lifecycle_aborted" }));
  assert.equal(polls, 1);
});

test("onPoll errors propagate unchanged and remove the caller's listener", testOptions, async () => {
  const controller = new AbortController();
  const expected = new Error("callback failed");
  const client = clientWith(async (input) => responseFor(input));
  await bounded(assert.rejects(client.observeLifecycleUntilVisible(resourceDid, {
    signal: controller.signal,
    onPoll() { throw expected; },
  }), (error) => error === expected));
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

for (const visible of [false, true]) {
  test(`a synchronous onPoll that crosses the deadline preserves visibility=${visible}`, testOptions, async (t) => {
    let now = 1000;
    t.mock.method(Date, "now", () => now);
    let requests = 0;
    const client = clientWith(async (input) => { requests += 1; return responseFor(input, visible); });
    const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid, {
      intervalMs: 1000,
      timeoutMs: 20,
      onPoll() { now += 21; },
    }));
    assert.equal(snapshot.discoveryVisible, visible);
    assert.equal(snapshot.stage, visible ? "visible-in-discovery" : "visibility-pending");
    assert.ok(snapshot.observations?.includes("timed out after 20ms"));
    assert.equal(requests, 9);
  });
}

test("cancellation interrupts the interval and removes the caller's listener", testOptions, async () => {
  const controller = new AbortController();
  let requests = 0;
  const client = clientWith(async (input) => { requests += 1; return responseFor(input, false); });
  await bounded(assert.rejects(client.observeLifecycleUntilVisible(resourceDid, {
    intervalMs: 1000,
    signal: controller.signal,
    onPoll() { queueMicrotask(() => controller.abort()); },
  }), { message: "observe_lifecycle_aborted" }));
  assert.equal(requests, 9);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("an immediately visible resource calls onPoll once and removes the caller's listener", testOptions, async () => {
  const controller = new AbortController();
  const snapshots: OanLifecycleSnapshot[] = [];
  const client = clientWith(async (input) => responseFor(input));
  const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid, {
    signal: controller.signal,
    onPoll(value) { snapshots.push(value); },
  }));
  assert.equal(snapshot.stage, "visible-in-discovery");
  assert.deepEqual(snapshots, [snapshot]);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("ordinary endpoint failures remain best effort", testOptions, async () => {
  const client = clientWith(async (input) => {
    const path = new URL(String(input)).pathname;
    if (path.endsWith("/visibility")) return responseFor(input);
    if (path.startsWith("/root/")) return Response.json({ error: "missing" }, { status: 404 });
    throw new Error("endpoint unavailable");
  });
  const snapshot = await bounded(client.observeLifecycleUntilVisible(resourceDid));
  assert.equal(snapshot.discoveryVisible, true);
  assert.equal(snapshot.registrarAccepted, false);
  assert.equal(snapshot.rootObserved, false);
  assert.equal(snapshot.cdnObserved, false);
});

test("cancelling one concurrent observation does not cancel another", testOptions, async () => {
  const controller = new AbortController();
  const pending = pendingRequests(4);
  let requestCount = 0;
  const client = clientWith((input, init) => {
    requestCount += 1;
    return requestCount <= 4 ? pending.fetchImpl(input, init) : Promise.resolve(responseFor(input));
  });
  const cancelled = assert.rejects(client.observeLifecycleUntilVisible(resourceDid, {
    signal: controller.signal,
  }), { message: "observe_lifecycle_aborted" });
  await bounded(pending.started);
  const successful = client.observeLifecycleUntilVisible(resourceDid);
  controller.abort();
  const [, snapshot] = await bounded(Promise.all([cancelled, successful]));
  assert.equal(snapshot.discoveryVisible, true);
  assertAborted(pending.requests, 4);
});
