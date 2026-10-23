export interface ReplayStore {
  /** True the first time `nonce` is seen, false on every later call before `until`. Must be atomic across whatever shares the store. */
  claim(nonce: string, until: number, now: number): boolean;
}

/** Correct for one process. A cluster of Node processes would each keep their own map. */
export class InMemoryReplayStore implements ReplayStore {
  #seen = new Map<string, number>();

  claim(nonce: string, until: number, now: number): boolean {
    for (const [seen, expiry] of this.#seen) if (expiry < now) this.#seen.delete(seen);
    if (this.#seen.has(nonce)) return false;
    this.#seen.set(nonce, until);
    return true;
  }
}
