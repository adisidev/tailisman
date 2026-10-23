/** @typedef {import("../index.js").ReplayStore} ReplayStore */

/**
 * Correct for one process. A cluster of Node processes would each keep their own map.
 * @implements {ReplayStore}
 */
export class InMemoryReplayStore {
  /** @type {Map<string, number>} */
  #seen = new Map();

  /**
   * @param {string} nonce
   * @param {number} until
   * @param {number} now
   * @returns {boolean}
   */
  claim(nonce, until, now) {
    for (const [seen, expiry] of this.#seen) if (expiry < now) this.#seen.delete(seen);
    if (this.#seen.has(nonce)) return false;
    this.#seen.set(nonce, until);
    return true;
  }
}
