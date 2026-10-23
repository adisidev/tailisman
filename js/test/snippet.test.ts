import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import { claim, mount } from "../../client/tailisman.js";

const ISSUER = "https://laptop.example-tailnet.ts.net:8443";

interface Call { url: string; init: RequestInit & { targetAddressSpace?: string } }

let calls: Call[];
let assigned: string[];
let reloads: number;
let button: { hidden: boolean; listeners: Array<() => void>; addEventListener(t: string, f: () => void): void; removeEventListener(): void };

function setGlobal(name: string, value: unknown): void {
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}

function browser({ permission = "unsupported", webdriver = false, issuer = (_url: string): Response | Promise<Response> => json(200, { token: "tsm1.p.m" }) } = {}): void {
  calls = [];
  assigned = [];
  reloads = 0;
  button = { hidden: true, listeners: [], addEventListener(_t, f) { this.listeners.push(f); }, removeEventListener() {} };
  setGlobal("navigator", {
    webdriver,
    userAgent: "Mozilla/5.0",
    permissions: permission === "unsupported" ? undefined : { query: async () => ({ state: permission }) },
  });
  setGlobal("location", { href: "https://heckle.example.com/page", assign: (url: string) => assigned.push(url), reload: () => reloads++ });
  setGlobal("document", { querySelector: () => button });
  setGlobal("fetch", async (url: string, init: Call["init"]) => {
    calls.push({ url, init });
    if (url.startsWith(ISSUER)) return issuer(url);
    return new Response(null, { status: 204 });
  });
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

beforeEach(() => browser());

test("claim asks the issuer with a credential-free cors fetch to the local address space", async () => {
  assert.deepEqual(await claim({ issuer: ISSUER + "/" }), { ok: true, token: "tsm1.p.m" });
  assert.equal(calls[0]!.url, `${ISSUER}/v1/claim?a=0`);
  assert.equal(calls[0]!.init.mode, "cors");
  assert.equal(calls[0]!.init.credentials, "omit");
  assert.equal(calls[0]!.init.targetAddressSpace, "local");
});

test("claim reports automation when navigator.webdriver is set", async () => {
  browser({ webdriver: true });
  await claim({ issuer: ISSUER });
  assert.equal(calls[0]!.url, `${ISSUER}/v1/claim?a=1`);
});

test("claim resolves with the refusal code", async () => {
  browser({ issuer: () => json(403, { error: "not_on_allowlist" }) });
  assert.deepEqual(await claim({ issuer: ISSUER }), { ok: false, reason: "refused", error: "not_on_allowlist" });
});

test("claim resolves unreachable on a network error", async () => {
  browser({ issuer: () => { throw new TypeError("Failed to fetch"); } });
  assert.deepEqual(await claim({ issuer: ISSUER }), { ok: false, reason: "unreachable" });
});

test("claim resolves unreachable on timeout", async () => {
  setGlobal("fetch", (_url: string, init: RequestInit) => new Promise((_resolve, reject) => init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))));
  assert.deepEqual(await claim({ issuer: ISSUER, timeoutMs: 10 }), { ok: false, reason: "unreachable" });
});

test("mount exchanges the token as JSON and hands the status to onResult", async () => {
  const results: unknown[] = [];
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", onResult: (r: unknown, s: unknown) => results.push([r, s]) });
  await settle();
  const exchange = calls.find((c) => c.url === "/auth/tailisman")!;
  assert.equal(exchange.init.method, "POST");
  assert.equal(exchange.init.body, JSON.stringify({ token: "tsm1.p.m" }));
  assert.deepEqual(results, [[{ ok: true, token: "tsm1.p.m" }, 204]]);
  assert.equal(button.hidden, true);
});

test("mount reloads after a successful exchange by default", async () => {
  mount({ issuer: ISSUER, exchange: "/auth/tailisman" });
  await settle();
  assert.equal(reloads, 1);
});

test("mount reveals the button when unreachable, and the click navigates to /v1/start", async () => {
  browser({ issuer: () => { throw new TypeError("Failed to fetch"); } });
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", onResult: () => {} });
  await settle();
  assert.equal(button.hidden, false);
  button.listeners[0]!();
  assert.deepEqual(assigned, [`${ISSUER}/v1/start?return_to=${encodeURIComponent("https://heckle.example.com/auth/tailisman")}&a=0`]);
});

test("mount keeps the button hidden for a refused device", async () => {
  browser({ issuer: () => json(403, { error: "tagged_node" }) });
  const results: unknown[] = [];
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", onResult: (r: unknown) => results.push(r) });
  await settle();
  assert.equal(button.hidden, true);
  assert.deepEqual(results, [{ ok: false, reason: "refused", error: "tagged_node" }]);
});

test("mount skips the fetch when the permission is denied", async () => {
  browser({ permission: "denied" });
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", onResult: () => {} });
  await settle();
  assert.equal(calls.length, 0);
  assert.equal(button.hidden, false);
});

test("mount with askPermission false skips the fetch while the permission is prompt, and fetches once granted", async () => {
  browser({ permission: "prompt" });
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", askPermission: false, onResult: () => {} });
  await settle();
  assert.equal(calls.length, 0);
  assert.equal(button.hidden, false);
  for (const permission of ["prompt", "granted"]) {
    browser({ permission });
    mount({ issuer: ISSUER, exchange: "/auth/tailisman", askPermission: permission === "granted" ? false : true, onResult: () => {} });
    await settle();
    assert.ok(calls.some((c) => c.url.startsWith(ISSUER)), permission);
  }
});

test("mount does nothing when the page already has a session", async () => {
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", isSignedIn: () => true });
  await settle();
  assert.equal(calls.length, 0);
  assert.equal(button.hidden, true);
});

test("mount with silent false shows only the button", async () => {
  mount({ issuer: ISSUER, exchange: "/auth/tailisman", button: "#b", silent: false });
  await settle();
  assert.equal(calls.length, 0);
  assert.equal(button.hidden, false);
});
