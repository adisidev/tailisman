import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";

import { InMemoryReplayStore, TailismanError, Verifier, extractToken, type ErrorCode } from "../src/index.ts";
import { deriveConsumerKey, formatKey } from "../src/token.ts";

const AUD = "https://heckle.example.com";
const KEY = deriveConsumerKey(Buffer.alloc(32, 7), AUD);
const NOW = 1_800_000_000;

function token(overrides: Record<string, unknown> = {}, key: Uint8Array = KEY): string {
  const payload = { nid: "nEXAMPLE1CNTRL", nn: "laptop", sub: "owner@example.com", aud: AUD, iat: NOW, exp: NOW + 60, nonce: randomBytes(16).toString("base64url"), ...overrides };
  const signingInput = `tsm1.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
  return `${signingInput}.${createHmac("sha256", key).update(signingInput).digest("base64url")}`;
}

function verifier(opts: { now?: number; devices?: string[]; replay?: InMemoryReplayStore } = {}): Verifier {
  const now = opts.now ?? NOW;
  return new Verifier({ key: formatKey(KEY), audience: AUD, clock: () => now, devices: opts.devices, replay: opts.replay });
}

function refuses(v: Verifier, t: string, code: ErrorCode): void {
  assert.throws(() => v.verify(t), (e: unknown) => e instanceof TailismanError && e.code === code);
}

test("valid token yields a frozen claim", () => {
  const claim = verifier().verify(token());
  assert.equal(claim.nodeName, "laptop");
  assert.equal(claim.login, "owner@example.com");
  assert.ok(Object.isFrozen(claim));
});

test("bad signature", () => refuses(verifier(), token({}, Buffer.alloc(32)), "bad_signature"));
test("wrong audience", () => refuses(verifier(), token({ aud: "https://notes.example.com" }), "wrong_audience"));
test("expired after leeway", () => {
  assert.ok(verifier({ now: NOW + 65 }).verify(token()));
  refuses(verifier({ now: NOW + 66 }), token(), "expired");
});
test("not yet valid", () => refuses(verifier({ now: NOW - 6 }), token(), "not_yet_valid"));
test("second use is replayed", () => {
  const v = verifier();
  const t = token();
  v.verify(t);
  refuses(v, t, "replayed");
});
test("a shared store refuses replay across verifiers", () => {
  const replay = new InMemoryReplayStore();
  const t = token();
  verifier({ replay }).verify(t);
  refuses(verifier({ replay }), t, "replayed");
});
test("device re-check", () => {
  assert.ok(verifier({ devices: ["laptop"] }).verify(token()));
  assert.ok(verifier({ devices: ["nEXAMPLE1CNTRL"] }).verify(token()));
  refuses(verifier({ devices: ["phone"] }), token(), "device_not_allowed");
});
test("malformed", () => {
  refuses(verifier(), "garbage", "malformed");
  refuses(verifier(), token({ iat: "1" }), "malformed");
  refuses(verifier(), formatKey(KEY), "malformed");
});
test("a token passed as the key fails at construction", () => {
  assert.throws(() => new Verifier({ key: token(), audience: AUD }), (e: unknown) => e instanceof TailismanError && e.code === "malformed");
});
test("extractToken reads both bodies and refuses others", () => {
  assert.equal(extractToken("application/json", '{"token":"tsm1.a.b"}'), "tsm1.a.b");
  assert.equal(extractToken("application/x-www-form-urlencoded", new TextEncoder().encode("token=tsm1.a.b")), "tsm1.a.b");
  for (const [ct, body] of [["text/plain", "tsm1.a.b"], ["application/json", "[1]"], ["application/json", '{"token":1}'], ["application/x-www-form-urlencoded", "token=a&token=b"], [undefined, "{}"]] as const) {
    assert.throws(() => extractToken(ct, body), (e: unknown) => e instanceof TailismanError && e.code === "malformed");
  }
});
