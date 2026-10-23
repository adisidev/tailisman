import { createHmac, timingSafeEqual } from "node:crypto";

export const TOKEN_PREFIX = "tsm1";
export const KEY_PREFIX = "tsk1";
const DERIVE_LABEL = "tailisman/v1/aud:";

export const ERROR_CODES = ["malformed", "bad_signature", "wrong_audience", "expired", "not_yet_valid", "replayed", "device_not_allowed"] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export class TailismanError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message?: string) {
    super(message ?? code);
    this.name = "TailismanError";
    this.code = code;
  }
}

export interface Claim {
  readonly nodeId: string;
  readonly nodeName: string;
  readonly login: string;
  readonly audience: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
}

const WIRE = {
  nid: ["nodeId", "string"],
  nn: ["nodeName", "string"],
  sub: ["login", "string"],
  aud: ["audience", "string"],
  iat: ["issuedAt", "integer"],
  exp: ["expiresAt", "integer"],
  nonce: ["nonce", "string"],
} as const;

const ORIGIN = /^(https?):\/\/([a-z0-9.-]+|\[[0-9a-f:.]+\])(?::([0-9]{1,5}))?\/?$/i;
const DEFAULT_PORT: Record<string, number> = { http: 80, https: 443 };
const B64URL = /^[A-Za-z0-9_-]*$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const INTEGER = /^[0-9]+$/;

export function normaliseOrigin(text: string): string {
  const match = ORIGIN.exec(text);
  if (!match) throw new TypeError(`not an origin: ${JSON.stringify(text)}`);
  const scheme = match[1]!.toLowerCase();
  const host = match[2]!.toLowerCase();
  if (match[3] === undefined || Number(match[3]) === DEFAULT_PORT[scheme]) return `${scheme}://${host}`;
  const port = Number(match[3]);
  if (port < 1 || port > 65535) throw new TypeError(`bad port in origin: ${JSON.stringify(text)}`);
  return `${scheme}://${host}:${port}`;
}

export function deriveConsumerKey(master: Uint8Array, origin: string): Buffer {
  return createHmac("sha256", master).update(DERIVE_LABEL + normaliseOrigin(origin)).digest();
}

export function formatKey(key: Uint8Array): string {
  return `${KEY_PREFIX}.${Buffer.from(key).toString("base64url")}`;
}

export function parseKey(text: string): Buffer {
  const [prefix, body, ...rest] = text.trim().split(".");
  const key = prefix === KEY_PREFIX && rest.length === 0 && body !== undefined ? b64decode(body) : null;
  if (key === null || key.length !== 32) throw new TailismanError("malformed", "a consumer key looks like tsk1.<43 base64url characters>");
  return key;
}

export function decode(token: string, key: Uint8Array): Claim {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) throw new TailismanError("malformed", "a token looks like tsm1.<payload>.<mac>");
  const payload = b64decode(parts[1]!);
  const mac = b64decode(parts[2]!);
  if (payload === null || mac === null) throw new TailismanError("malformed", "token parts are not base64url");
  const expected = createHmac("sha256", key).update(`${parts[0]}.${parts[1]}`).digest();
  if (mac.length !== expected.length || !timingSafeEqual(mac, expected)) throw new TailismanError("bad_signature");
  return parsePayload(payload);
}

function parsePayload(raw: Buffer): Claim {
  const integerSource = new Map<string, boolean>();
  let payload: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    payload = JSON.parse(text, function (this: unknown, name: string, value: unknown, context?: { source?: string }) {
      if (typeof value === "number" && this !== null && typeof this === "object" && !Array.isArray(this)) {
        integerSource.set(name, INTEGER.test(context?.source ?? ""));
      }
      return value;
    });
  } catch {
    throw new TailismanError("malformed", "payload is not JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) throw new TailismanError("malformed", "payload is not an object");
  const record = payload as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== Object.keys(WIRE).length || !keys.every((k) => Object.hasOwn(WIRE, k))) {
    throw new TailismanError("malformed", `payload keys are not exactly ${Object.keys(WIRE).join(",")}`);
  }
  const fields: Record<string, string | number> = {};
  for (const [wire, [field, kind]] of Object.entries(WIRE)) {
    const value = record[wire];
    const good =
      kind === "string"
        ? typeof value === "string" && value.length > 0
        : typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && integerSource.get(wire) === true;
    if (!good) throw new TailismanError("malformed", `payload field ${wire} has the wrong type`);
    fields[field] = value as string | number;
  }
  if (!NONCE.test(fields.nonce as string)) throw new TailismanError("malformed", "nonce is not 16 bytes of base64url");
  return Object.freeze(fields) as unknown as Claim;
}

function b64decode(text: string): Buffer | null {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  const raw = Buffer.from(text, "base64url");
  return raw.toString("base64url") === text ? raw : null;
}
