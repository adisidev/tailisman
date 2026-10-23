import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { TailismanError, Verifier } from "../src/index.ts";
import { deriveConsumerKey, formatKey, normaliseOrigin } from "../src/token.ts";

const vectors = JSON.parse(readFileSync(new URL("../../testdata/vectors.json", import.meta.url), "utf8"));

const camel: Record<string, string> = { node_id: "nodeId", node_name: "nodeName", login: "login", audience: "audience", issued_at: "issuedAt", expires_at: "expiresAt", nonce: "nonce" };

for (const c of vectors.cases) {
  test(`vector: ${c.name}`, () => {
    const verifier = new Verifier({ key: c.key, audience: c.audience, clock: () => vectors.now, leeway: vectors.leeway });
    if (c.expect.ok) {
      const expected = Object.fromEntries(Object.entries(c.expect.claim).map(([k, v]) => [camel[k], v]));
      assert.deepEqual({ ...verifier.verify(c.token) }, expected);
    } else {
      assert.throws(() => verifier.verify(c.token), (e: unknown) => e instanceof TailismanError && e.code === c.expect.code);
    }
  });
}

for (const o of vectors.origins) {
  test(`origin: ${JSON.stringify(o.input)}`, () => {
    if (o.expect === null) assert.throws(() => normaliseOrigin(o.input), TypeError);
    else assert.equal(normaliseOrigin(o.input), o.expect);
  });
}

test("consumer keys derive from the master as the issuer derives them", () => {
  const master = Buffer.from(vectors.master, "base64url");
  for (const [origin, key] of Object.entries(vectors.keys)) assert.equal(formatKey(deriveConsumerKey(master, origin)), key);
});
