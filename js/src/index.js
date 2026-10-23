import { SOURCE_TEXT, TailismanError, decode, normaliseOrigin, parseKey } from "./token.js";
import { InMemoryReplayStore } from "./replay.js";

export { ERROR_CODES, TailismanError } from "./token.js";
export { InMemoryReplayStore } from "./replay.js";

/** @typedef {import("../index.js").Claim} Claim */
/** @typedef {import("../index.js").ReplayStore} ReplayStore */
/** @typedef {import("../index.js").VerifierOptions} VerifierOptions */

export const MAX_BODY = 16 * 1024;
export const MAX_TOKEN = 4096;

export class Verifier {
  /** @type {Buffer} */
  #key;
  /** @type {string} */
  #audience;
  /** @type {ReplayStore} */
  #replay;
  /** @type {ReadonlySet<string> | null} */
  #devices;
  /** @type {number} */
  #leeway;
  /** @type {() => number} */
  #clock;

  /** @param {VerifierOptions} opts */
  constructor(opts) {
    if (!SOURCE_TEXT) throw new Error(`tailisman needs Node 22 or later; this is ${process.version}`);
    const leeway = opts.leeway ?? 5;
    if (!Number.isSafeInteger(leeway) || leeway < 0) throw new RangeError("leeway must be a non-negative integer number of seconds");
    this.#key = parseKey(opts.key);
    this.#audience = normaliseOrigin(opts.audience);
    this.#replay = opts.replay ?? new InMemoryReplayStore();
    this.#devices = opts.devices === undefined ? null : new Set(opts.devices);
    this.#leeway = leeway;
    this.#clock = opts.clock ?? (() => Date.now() / 1000);
  }

  /**
   * @param {string} token
   * @returns {Claim}
   */
  verify(token) {
    const claim = decode(token, this.#key);
    if (claim.audience !== this.#audience) throw new TailismanError("wrong_audience", `token is for ${claim.audience}`);
    const now = Math.floor(this.#clock());
    if (now > claim.expiresAt + this.#leeway) throw new TailismanError("expired");
    if (now < claim.issuedAt - this.#leeway) throw new TailismanError("not_yet_valid");
    if (!this.#replay.claim(claim.nonce, claim.expiresAt + this.#leeway, now)) throw new TailismanError("replayed");
    if (this.#devices !== null && !this.#devices.has(claim.nodeId) && !this.#devices.has(claim.nodeName)) {
      throw new TailismanError("device_not_allowed", `device ${claim.nodeName} is not in this verifier's list`);
    }
    return claim;
  }
}

/**
 * @param {string | undefined | null} contentType
 * @param {string | Uint8Array} body
 * @returns {string}
 */
export function extractToken(contentType, body) {
  const mediaType = (contentType ?? "").split(";")[0].trim().toLowerCase();
  const size = typeof body === "string" ? Buffer.byteLength(body) : body.byteLength;
  if (size > MAX_BODY) throw new TailismanError("malformed", `body is over ${MAX_BODY} bytes`);
  /** @type {unknown} */
  let token = null;
  try {
    const text = typeof body === "string" ? body : new TextDecoder("utf-8", { fatal: true }).decode(body);
    if (mediaType === "application/json") {
      /** @type {unknown} */
      const parsed = JSON.parse(text);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) token = /** @type {Record<string, unknown>} */ (parsed).token;
    } else if (mediaType === "application/x-www-form-urlencoded") {
      const values = new URLSearchParams(text).getAll("token");
      if (values.length === 1) token = values[0];
    }
  } catch {
    token = null;
  }
  if (typeof token !== "string" || token.length > MAX_TOKEN) {
    throw new TailismanError("malformed", `expected a JSON or form body with one token field of at most ${MAX_TOKEN} characters`);
  }
  return token;
}
