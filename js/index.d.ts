export type ErrorCode = "malformed" | "bad_signature" | "wrong_audience" | "expired" | "not_yet_valid" | "replayed" | "device_not_allowed";

export const ERROR_CODES: readonly ErrorCode[];
export const MAX_BODY: number;
export const MAX_TOKEN: number;

export class TailismanError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message?: string);
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

export interface ReplayStore {
  /** True the first time `nonce` is seen, false on every later call before `until`. Must be atomic across whatever shares the store. */
  claim(nonce: string, until: number, now: number): boolean;
}

export class InMemoryReplayStore implements ReplayStore {
  claim(nonce: string, until: number, now: number): boolean;
}

export interface VerifierOptions {
  /** `tsk1.<base64url>`, from `tailisman key --aud <origin>`. */
  key: string;
  audience: string;
  replay?: ReplayStore;
  /** Stable IDs or short names, matched exactly and case-sensitively. */
  devices?: Iterable<string>;
  /** Seconds of clock skew allowed; a non-negative integer, default 5. */
  leeway?: number;
  /** Seconds since the epoch. */
  clock?: () => number;
}

export class Verifier {
  constructor(opts: VerifierOptions);
  verify(token: string): Claim;
}

export function extractToken(contentType: string | undefined | null, body: string | Uint8Array): string;
