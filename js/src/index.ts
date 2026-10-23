import { type Claim, TailismanError, decode, normaliseOrigin, parseKey } from "./token.ts";
import { InMemoryReplayStore, type ReplayStore } from "./replay.ts";

export { type Claim, type ErrorCode, ERROR_CODES, TailismanError } from "./token.ts";
export { InMemoryReplayStore, type ReplayStore } from "./replay.ts";

export const MAX_BODY = 16 * 1024;
export const MAX_TOKEN = 4096;

export interface VerifierOptions {
  key: string;
  audience: string;
  replay?: ReplayStore;
  devices?: Iterable<string>;
  leeway?: number;
  /** Seconds since the epoch. */
  clock?: () => number;
}

export class Verifier {
  readonly #key: Buffer;
  readonly #audience: string;
  readonly #replay: ReplayStore;
  readonly #devices: ReadonlySet<string> | null;
  readonly #leeway: number;
  readonly #clock: () => number;

  constructor(opts: VerifierOptions) {
    const leeway = opts.leeway ?? 5;
    if (!Number.isSafeInteger(leeway) || leeway < 0) throw new RangeError("leeway must be a non-negative integer number of seconds");
    this.#key = parseKey(opts.key);
    this.#audience = normaliseOrigin(opts.audience);
    this.#replay = opts.replay ?? new InMemoryReplayStore();
    this.#devices = opts.devices === undefined ? null : new Set(opts.devices);
    this.#leeway = leeway;
    this.#clock = opts.clock ?? (() => Date.now() / 1000);
  }

  verify(token: string): Claim {
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

export function extractToken(contentType: string | undefined | null, body: string | Uint8Array): string {
  const mediaType = (contentType ?? "").split(";")[0]!.trim().toLowerCase();
  const size = typeof body === "string" ? Buffer.byteLength(body) : body.byteLength;
  if (size > MAX_BODY) throw new TailismanError("malformed", `body is over ${MAX_BODY} bytes`);
  let token: unknown = null;
  try {
    const text = typeof body === "string" ? body : new TextDecoder("utf-8", { fatal: true }).decode(body);
    if (mediaType === "application/json") {
      const parsed: unknown = JSON.parse(text);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) token = (parsed as Record<string, unknown>).token;
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
