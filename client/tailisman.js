// tailisman browser snippet. Plain ES module, no dependencies, never parses a token.
//
//   import { mount } from "/static/tailisman.js";
//   mount({ issuer: "https://laptop.example-tailnet.ts.net:8443", exchange: "/auth/tailisman", button: "#tailnet-signin" });
//
// The snippet never navigates on its own: a failed silent fetch from an off-tailnet visitor looks the same as a
// denied Local Network Access permission, and navigating that visitor would land them on a DNS error page.

const DEFAULT_TIMEOUT_MS = 20000;

/**
 * Silent transport. targetAddressSpace must match where Chrome places the issuer's IP: "local" for a tailnet
 * address (100.64.0.0/10), "loopback" only for an issuer on 127.0.0.1 in local testing; a mismatch fails the fetch.
 * Resolves, never rejects, with one of
 *   { ok: true, token }
 *   { ok: false, reason: "unreachable" }          DNS failure, permission denied, timeout, network error
 *   { ok: false, reason: "refused", error }       the issuer answered with a refusal code
 */
export async function claim({ issuer, timeoutMs = DEFAULT_TIMEOUT_MS, targetAddressSpace = "local", signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  try {
    const response = await fetch(`${base(issuer)}/v1/claim?a=${automationFlag()}`, {
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      targetAddressSpace,
      signal: controller.signal,
    });
    const body = await response.json().catch(() => null);
    if (response.ok && typeof body?.token === "string") return { ok: true, token: body.token };
    if (typeof body?.error === "string") return { ok: false, reason: "refused", error: body.error };
    return { ok: false, reason: "unreachable" };
  } catch {
    return { ok: false, reason: "unreachable" };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

/** Navigation transport. A top-level navigation is never gated by Local Network Access. The issuer POSTs the token back to `exchange`. */
export function navigate({ issuer, exchange }) {
  const returnTo = new URL(exchange, location.href).href;
  location.assign(`${base(issuer)}/v1/start?return_to=${encodeURIComponent(returnTo)}&a=${automationFlag()}`);
}

/**
 * The default integration. Returns a function that cancels it.
 *
 * Options: issuer, exchange (same-origin path that accepts the token), button (selector or element, hidden until
 * needed), silent (default true; false shows only the button), askPermission (default true; false skips the silent
 * fetch while the Local Network Access permission is still "prompt"), isSignedIn (default () => false), timeoutMs,
 * targetAddressSpace (see claim), onResult(result, exchangeStatus) (default reloads after a successful exchange).
 */
export function mount({ issuer, exchange, button, silent = true, askPermission = true, isSignedIn = () => false, timeoutMs, targetAddressSpace, onResult } = {}) {
  const controller = new AbortController();
  const element = typeof button === "string" ? document.querySelector(button) : (button ?? null);
  const click = (event) => {
    event?.preventDefault?.();
    navigate({ issuer, exchange });
  };
  const reveal = () => {
    if (!element) return;
    element.hidden = false;
    element.addEventListener("click", click);
  };
  const unmount = () => {
    controller.abort();
    element?.removeEventListener("click", click);
  };
  const report = onResult ?? ((result, status) => result.ok && status >= 200 && status < 300 && location.reload());

  if (isSignedIn()) return unmount;
  if (!silent) {
    reveal();
    return unmount;
  }
  (async () => {
    const permission = await localNetworkPermission();
    if (permission === "denied" || (permission === "prompt" && !askPermission)) {
      reveal();
      report({ ok: false, reason: "unreachable", permission });
      return;
    }
    const result = await claim({ issuer, timeoutMs, targetAddressSpace, signal: controller.signal });
    if (controller.signal.aborted) return;
    if (!result.ok) {
      if (result.reason === "unreachable") reveal();
      report(result);
      return;
    }
    const status = await exchangeToken(exchange, result.token, controller.signal);
    if (!controller.signal.aborted) report(result, status);
  })();
  return unmount;
}

/** "1" when the page shows cheap signs of browser automation. Spoofable; the issuer decides per audience what it means. */
export function automationFlag() {
  const keys = [...Object.keys(globalThis), ...(typeof document === "undefined" ? [] : Object.keys(document))];
  const tells =
    navigator.webdriver === true ||
    "__playwright__binding__" in globalThis ||
    "__pwInitScripts" in globalThis ||
    keys.some((key) => /^\$?cdc_/.test(key)) ||
    /HeadlessChrome/.test(navigator.userAgent ?? "");
  return tells ? "1" : "0";
}

async function localNetworkPermission() {
  try {
    return (await navigator.permissions.query({ name: "local-network-access" })).state;
  } catch {
    return "unsupported";
  }
}

async function exchangeToken(exchange, token, signal) {
  try {
    const response = await fetch(exchange, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
      credentials: "same-origin",
      signal,
    });
    return response.status;
  } catch {
    return 0;
  }
}

function base(issuer) {
  return String(issuer).replace(/\/+$/, "");
}
