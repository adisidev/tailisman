"""Verify tailisman tokens. Standard library only.

    verifier = Verifier(key=os.environ["TAILISMAN_KEY"], audience="https://heckle.example.com")
    claim = verifier.verify(token)
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from urllib.parse import parse_qs

from ._replay import InMemoryReplayStore, ReplayStore
from ._token import Claim, ErrorCode, TailismanError, decode, normalise_origin, parse_key

__all__ = ["Verifier", "Claim", "ErrorCode", "TailismanError", "extract_token", "ReplayStore", "InMemoryReplayStore", "MAX_BODY", "MAX_TOKEN"]

MAX_BODY = 16 * 1024
MAX_TOKEN = 4096


class Verifier:
    def __init__(
        self,
        *,
        key: str,
        audience: str,
        replay: ReplayStore | None = None,
        devices: Iterable[str] | None = None,
        leeway: int = 5,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if type(leeway) is not int or leeway < 0:
            raise ValueError("leeway must be a non-negative integer number of seconds")
        self._key = parse_key(key)
        self._audience = normalise_origin(audience)
        self._replay = replay if replay is not None else InMemoryReplayStore()
        self._devices = frozenset(devices) if devices is not None else None
        self._leeway = leeway
        self._clock = clock

    def verify(self, token: str) -> Claim:
        claim = decode(token, self._key)
        if claim.audience != self._audience:
            raise TailismanError(ErrorCode.WRONG_AUDIENCE, f"token is for {claim.audience}")
        now = int(self._clock())
        if now > claim.expires_at + self._leeway:
            raise TailismanError(ErrorCode.EXPIRED)
        if now < claim.issued_at - self._leeway:
            raise TailismanError(ErrorCode.NOT_YET_VALID)
        if not self._replay.claim(claim.nonce, claim.expires_at + self._leeway, now):
            raise TailismanError(ErrorCode.REPLAYED)
        if self._devices is not None and not self._devices & {claim.node_id, claim.node_name}:
            raise TailismanError(ErrorCode.DEVICE_NOT_ALLOWED, f"device {claim.node_name} is not in this verifier's list")
        return claim


def extract_token(content_type: str | None, body: bytes) -> str:
    media_type = (content_type or "").split(";")[0].strip().lower()
    if len(body) > MAX_BODY:
        raise TailismanError(ErrorCode.MALFORMED, f"body is over {MAX_BODY} bytes")
    try:
        if media_type == "application/json":
            token = json.loads(body.decode("utf-8")).get("token")
        elif media_type == "application/x-www-form-urlencoded":
            values = parse_qs(body.decode("ascii"), strict_parsing=True).get("token", [])
            token = values[0] if len(values) == 1 else None
        else:
            token = None
    except (ValueError, AttributeError, RecursionError):
        token = None
    if not isinstance(token, str) or len(token) > MAX_TOKEN:
        raise TailismanError(ErrorCode.MALFORMED, f"expected a JSON or form body with one token field of at most {MAX_TOKEN} characters")
    return token
