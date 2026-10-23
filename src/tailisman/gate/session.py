"""The gate's session cookie. Pure; the only module that knows the cookie's wire keys.

Cookie: tailisman_gate=tsg1.<b64url(payload JSON)>.<b64url(HMAC-SHA256(K, "tsg1.<payload-b64>"))>
K = HMAC-SHA256(session_secret, "tailisman/gate/v1:" + password hash line), so a new password signs every session out.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
from collections.abc import Iterable

from .._token import _b64decode, b64encode

COOKIE = "tailisman_gate"
PREFIX = "tsg1"
_LABEL = b"tailisman/gate/v1:"
_MAX_INT = 2**53 - 1


class Method(enum.StrEnum):
    PASSWORD = "password"
    TAILNET = "tailnet"


@dataclasses.dataclass(frozen=True)
class Session:
    method: Method
    device: str | None
    scope: str
    issued_at: int
    expires_at: int

    def covers(self, host: str) -> bool:
        return host == self.scope or host.endswith("." + self.scope)


_WIRE = {"m": "method", "dev": "device", "scope": "scope", "iat": "issued_at", "exp": "expires_at"}


def session_key(secret: bytes, password_line: str) -> bytes:
    return hmac.new(secret, _LABEL + password_line.encode(), hashlib.sha256).digest()


def mint(session: Session, key: bytes) -> str:
    payload = {wire: getattr(session, field) for wire, field in _WIRE.items()}
    signing_input = f"{PREFIX}.{b64encode(json.dumps(payload, separators=(',', ':')).encode())}"
    return f"{signing_input}.{b64encode(_mac(key, signing_input))}"


def verify(value: str, key: bytes, host: str, now: int) -> Session | None:
    """The session in one cookie value, or None when it is malformed, forged, signed under another password, expired or for another host."""
    parts = value.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return None
    payload, mac = _b64decode(parts[1]), _b64decode(parts[2])
    if payload is None or mac is None or not hmac.compare_digest(mac, _mac(key, f"{parts[0]}.{parts[1]}")):
        return None
    session = _parse(payload)
    if session is None or not session.issued_at <= now < session.expires_at or not session.covers(host):
        return None
    return session


def first_valid(values: Iterable[str], key: bytes, host: str, now: int) -> Session | None:
    """A browser can hold a parent-domain cookie and a host-only one with the same name; either may be the live one."""
    for value in values:
        if session := verify(value, key, host, now):
            return session
    return None


def cookie_values(header: str | None, name: str) -> tuple[str, ...]:
    values = []
    for part in (header or "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            values.append(value.strip())
    return tuple(values)


def _parse(raw: bytes) -> Session | None:
    try:
        payload = json.loads(raw.decode("utf-8"), parse_constant=_reject, parse_float=_reject)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.keys() != _WIRE.keys():
        return None
    method, device, scope, issued, expires = (payload[k] for k in _WIRE)
    if method not in tuple(Method) or not isinstance(scope, str) or not scope:
        return None
    if (method == Method.TAILNET) != (isinstance(device, str) and bool(device)) or (method == Method.PASSWORD and device is not None):
        return None
    if not all(type(t) is int and 0 <= t <= _MAX_INT for t in (issued, expires)):
        return None
    return Session(Method(method), device, scope, issued, expires)


def _reject(text: str):
    raise ValueError(f"non-integer number {text}")


def _mac(key: bytes, signing_input: str) -> bytes:
    return hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
