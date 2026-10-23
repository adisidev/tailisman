"""One-time codes from the gate's tailnet listener to its public one. In memory only, so nothing signs or verifies them.

The tailnet listener hands the browser a random code after the device checks pass; the browser posts it to
/.tailisman/exchange on the gated site, which redeems it once. A code is bound to the site's origin and lives
`ttl` seconds. A redeemed code is remembered until it would have expired, so a second use is refused as replayed;
a code shown to the wrong site is burned.
"""

from __future__ import annotations

import dataclasses
import secrets
import threading

from .._token import ErrorCode, TailismanError

CODE_BYTES = 32


@dataclasses.dataclass(frozen=True)
class Device:
    node_id: str
    node_name: str
    login: str


@dataclasses.dataclass
class _Entry:
    origin: str
    device: Device
    expires_at: float
    used: bool = False


class CodeBook:
    def __init__(self, ttl: int) -> None:
        self.ttl = ttl
        self._lock = threading.Lock()
        self._codes: dict[str, _Entry] = {}

    def issue(self, origin: str, device: Device, now: float) -> str:
        code = secrets.token_urlsafe(CODE_BYTES)
        with self._lock:
            self._expire(now)
            self._codes[code] = _Entry(origin, device, now + self.ttl)
        return code

    def redeem(self, code: str, origin: str, now: float) -> Device:
        """The device a code was issued to, once. Raises TailismanError with the same codes a token refusal uses."""
        with self._lock:
            entry = self._codes.get(code)
            if entry is not None and now >= entry.expires_at:
                del self._codes[code]
                raise TailismanError(ErrorCode.EXPIRED)
            self._expire(now)
            if entry is None:
                raise TailismanError(ErrorCode.MALFORMED, "unknown code")
            if entry.used:
                raise TailismanError(ErrorCode.REPLAYED)
            if entry.origin != origin:
                entry.used = True
                raise TailismanError(ErrorCode.WRONG_AUDIENCE)
            entry.used = True
            return entry.device

    def _expire(self, now: float) -> None:
        for code in [code for code, entry in self._codes.items() if now >= entry.expires_at]:
            del self._codes[code]
