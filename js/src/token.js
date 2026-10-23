import { createHmac, timingSafeEqual } from "node:crypto";

export const TOKEN_PREFIX = "tsm1";
export const KEY_PREFIX = "tsk1";
const DERIVE_LABEL = "tailisman/v1/aud:";

/** @typedef {import("../index.js").ErrorCode} ErrorCode */
/** @typedef {import("../index.js").Claim} Claim */

/** @type {readonly ErrorCode[]} */
export const ERROR_CODES = Object.freeze(["malformed", "bad_signature", "wrong_audience", "expired", "not_yet_valid", "replayed", "device_not_allowed"]);

export class TailismanError extends Error {
  /**
   * @param {ErrorCode} code
   * @param {string} [message]
   */
  constructor(code, message) {
    super(message ?? code);
    this.name = "TailismanError";
    /** @readonly */
    this.code = code;
  }
}

const WIRE = /** @type {const} */ ({
  nid: ["nodeId", "string"],
  nn: ["nodeName", "string"],
  sub: ["login", "string"],
  aud: ["audience", "string"],
  iat: ["issuedAt", "integer"],
  exp: ["expiresAt", "integer"],
  nonce: ["nonce", "string"],
});

const ORIGIN = /^(https?):\/\/([a-z0-9.-]+|\[[0-9a-f:.]+\])(?::([0-9]{1,5}))?\/?$/i;
/** @type {Record<string, number>} */
const DEFAULT_PORT = { http: 80, https: 443 };
const B64URL = /^[A-Za-z0-9_-]*$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const INTEGER = /^[0-9]+$/;

/** Whether JSON.parse hands its reviver the source text (Node 21 and later); without it a float `iat` cannot be told from an integer. */
/** @typedef {(this: unknown, key: string, value: unknown, context?: {source?: string}) => unknown} SourceReviver */
const parseWithSource = /** @type {(text: string, reviver: SourceReviver) => unknown} */ (JSON.parse);

/** Whether JSON.parse hands its reviver the source text (Node 21 and later); without it a float `iat` cannot be told from an integer. */
export const SOURCE_TEXT = parseWithSource("1", (_key, _value, context) => context?.source === "1") === true;

/**
 * @param {string} text
 * @returns {string}
 */
export function normaliseOrigin(text) {
  const match = ORIGIN.exec(text);
  if (!match) throw new TypeError(`not an origin: ${JSON.stringify(text)}`);
  const scheme = match[1].toLowerCase();
  const host = match[2].toLowerCase();
  if (match[3] === undefined || Number(match[3]) === DEFAULT_PORT[scheme]) return `${scheme}://${host}`;
  const port = Number(match[3]);
  if (port < 1 || port > 65535) throw new TypeError(`bad port in origin: ${JSON.stringify(text)}`);
  return `${scheme}://${host}:${port}`;
}

/**
 * @param {Uint8Array} master
 * @param {string} origin
 * @returns {Buffer}
 */
export function deriveConsumerKey(master, origin) {
  return createHmac("sha256", master).update(DERIVE_LABEL + normaliseOrigin(origin)).digest();
}

/**
 * @param {Uint8Array} key
 * @returns {string}
 */
export function formatKey(key) {
  return `${KEY_PREFIX}.${Buffer.from(key).toString("base64url")}`;
}

/**
 * @param {string} text
 * @returns {Buffer}
 */
export function parseKey(text) {
  const [prefix, body, ...rest] = text.trim().split(".");
  const key = prefix === KEY_PREFIX && rest.length === 0 && body !== undefined ? b64decode(body) : null;
  if (key === null || key.length !== 32) throw new TailismanError("malformed", "a consumer key looks like tsk1.<43 base64url characters>");
  return key;
}

/**
 * @param {string} token
 * @param {Uint8Array} key
 * @returns {Claim}
 */
export function decode(token, key) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) throw new TailismanError("malformed", "a token looks like tsm1.<payload>.<mac>");
  const payload = b64decode(parts[1]);
  const mac = b64decode(parts[2]);
  if (payload === null || mac === null) throw new TailismanError("malformed", "token parts are not base64url");
  const expected = createHmac("sha256", key).update(`${parts[0]}.${parts[1]}`).digest();
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) throw new TailismanError("bad_signature");
  return parsePayload(payload);
}

/**
 * @param {Buffer} raw
 * @returns {Claim}
 */
function parsePayload(raw) {
  /** @type {Map<string, boolean>} */
  const integerSource = new Map();
  /** @type {unknown} */
  let payload;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    payload = parseWithSource(text, function (name, value, context) {
      if (typeof value === "number" && this !== null && typeof this === "object" && !Array.isArray(this)) {
        integerSource.set(name, INTEGER.test(context?.source ?? ""));
      }
      return value;
    });
  } catch {
    throw new TailismanError("malformed", "payload is not JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) throw new TailismanError("malformed", "payload is not an object");
  const record = /** @type {Record<string, unknown>} */ (payload);
  const keys = Object.keys(record);
  if (keys.length !== Object.keys(WIRE).length || !keys.every((k) => Object.hasOwn(WIRE, k))) {
    throw new TailismanError("malformed", `payload keys are not exactly ${Object.keys(WIRE).join(",")}`);
  }
  /** @type {Record<string, string | number>} */
  const fields = {};
  for (const [wire, [field, kind]] of Object.entries(WIRE)) {
    const value = record[wire];
    const good =
      kind === "string"
        ? typeof value === "string" && value.length > 0
        : typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && integerSource.get(wire) === true;
    if (!good) throw new TailismanError("malformed", `payload field ${wire} has the wrong type`);
    fields[field] = /** @type {string | number} */ (value);
  }
  if (!NONCE.test(/** @type {string} */ (fields.nonce))) throw new TailismanError("malformed", "nonce is not 16 bytes of base64url");
  return /** @type {Claim} */ (/** @type {unknown} */ (Object.freeze(fields)));
}

/**
 * @param {string} text
 * @returns {Buffer | null}
 */
function b64decode(text) {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  const raw = Buffer.from(text, "base64url");
  return raw.toString("base64url") === text ? raw : null;
}
