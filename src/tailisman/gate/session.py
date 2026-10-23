"""The gate's session cookie. Pure; the only module that knows the cookie's wire keys.

Owner cookie: tailisman_gate=tsg1.<b64url(payload JSON)>.<b64url(HMAC-SHA256(K, "tsg1.<payload-b64>"))>
K = HMAC-SHA256(session_secret, "tailisman/gate/v1:" + password hash line), so a new password signs every owner session out.

Guest cookie: tailisman_gate=tsg1g.<NAME>.<b64url(payload JSON)>.<b64url(HMAC-SHA256(K_NAME, "tsg1g.<NAME>.<payload-b64>"))>
K_NAME = HMAC-SHA256(session_secret, "tailisman/gate/guest/v1:" + NAME + "\\n" + the guest's digest), so revoking or
replacing one guest's password signs out that guest alone. NAME is in clear because the key depends on it.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterable

from .._token import _b64decode, b64encode

COOKIE = "tailisman_gate"
CSRF_COOKIE = "tailisman_csrf"
PREFIX = "tsg1"
GUEST_PREFIX = "tsg1g"
GUEST_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}", re.ASCII)
_LABEL = b"tailisman/gate/v1:"
_GUEST_LABEL = b"tailisman/gate/guest/v1:"
_MAX_INT = 2**53 - 1


class Method(enum.StrEnum):
    PASSWORD = "password"
    TAILNET = "tailnet"
    GUEST = "guest"


@dataclasses.dataclass(frozen=True)
class Session:
    method: Method
    device: str | None
    scope: str
    issued_at: int
    expires_at: int
    guest: str | None = None

    def covers(self, host: str) -> bool:
        return host == self.scope or host.endswith("." + self.scope)


KeyFor = Callable[[str | None], bytes | None]
"""The MAC key for a cookie: None asks for the owner key, a name for that guest's key. None back refuses the cookie."""

_WIRE = {"m": "method", "dev": "device", "scope": "scope", "iat": "issued_at", "exp": "expires_at"}
_GUEST_WIRE = {"m": "method", "guest": "guest", "scope": "scope", "iat": "issued_at", "exp": "expires_at"}


def session_key(secret: bytes, password_line: str) -> bytes:
    return hmac.new(secret, _LABEL + password_line.encode(), hashlib.sha256).digest()


def guest_key(secret: bytes, name: str, digest: str) -> bytes:
    return hmac.new(secret, _GUEST_LABEL + f"{name}\n{digest}".encode(), hashlib.sha256).digest()


def mint(session: Session, key: bytes) -> str:
    head, wire = (f"{GUEST_PREFIX}.{session.guest}", _GUEST_WIRE) if session.method is Method.GUEST else (PREFIX, _WIRE)
    payload = {name: getattr(session, field) for name, field in wire.items()}
    signing_input = f"{head}.{b64encode(json.dumps(payload, separators=(',', ':')).encode())}"
    return f"{signing_input}.{b64encode(_mac(key, signing_input))}"


def verify(value: str, key_for: KeyFor, host: str, now: int) -> Session | None:
    """The session in one cookie value, or None when it is malformed, forged, signed under an old password, expired or for another host.

    The MAC is checked before the payload is parsed; the guest NAME it is keyed by comes from the cleartext segment."""
    parts = value.split(".")
    if len(parts) == 3 and parts[0] == PREFIX:
        guest = None
    elif len(parts) == 4 and parts[0] == GUEST_PREFIX and GUEST_NAME.fullmatch(parts[1]):
        guest = parts[1]
    else:
        return None
    key = key_for(guest)
    payload, mac = _b64decode(parts[-2]), _b64decode(parts[-1])
    if key is None or payload is None or mac is None or not hmac.compare_digest(mac, _mac(key, ".".join(parts[:-1]))):
        return None
    session = _parse(payload, guest)
    if session is None or not session.issued_at <= now < session.expires_at or not session.covers(host):
        return None
    return session


def first_valid(values: Iterable[str], key_for: KeyFor, host: str, now: int) -> Session | None:
    """A browser can hold a parent-domain cookie and a host-only one with the same name; either may be the live one."""
    for value in values:
        if session := verify(value, key_for, host, now):
            return session
    return None


def cookie_values(header: str | None, name: str) -> tuple[str, ...]:
    values = []
    for part in (header or "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            values.append(value.strip())
    return tuple(values)


def _parse(raw: bytes, guest: str | None) -> Session | None:
    try:
        payload = json.loads(raw.decode("utf-8"), parse_constant=_reject, parse_float=_reject)
    except (UnicodeDecodeError, ValueError):
        return None
    wire = _WIRE if guest is None else _GUEST_WIRE
    if not isinstance(payload, dict) or payload.keys() != wire.keys():
        return None
    method, scope, issued, expires = payload["m"], payload["scope"], payload["iat"], payload["exp"]
    if not isinstance(scope, str) or not scope or not all(type(t) is int and 0 <= t <= _MAX_INT for t in (issued, expires)):
        return None
    if guest is not None:
        return Session(Method.GUEST, None, scope, issued, expires, guest) if method == Method.GUEST and payload["guest"] == guest else None
    device = payload["dev"]
    if method == Method.PASSWORD and device is None:
        return Session(Method.PASSWORD, None, scope, issued, expires)
    if method == Method.TAILNET and isinstance(device, str) and device:
        return Session(Method.TAILNET, device, scope, issued, expires)
    return None


def _reject(text: str):
    raise ValueError(f"non-integer number {text}")


def _mac(key: bytes, signing_input: str) -> bytes:
    return hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
