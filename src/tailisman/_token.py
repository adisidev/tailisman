"""The wire format, the key derivation and origin normalisation. The only module that knows wire keys.

Token: tsm1.<b64url(payload JSON)>.<b64url(HMAC-SHA256(K_aud, "tsm1.<payload-b64>"))>
Key:   tsk1.<b64url(K_aud)>, K_aud = HMAC-SHA256(master, b"tailisman/v1/aud:" + origin)
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import hashlib
import hmac
import json
import re
import secrets

TOKEN_PREFIX = "tsm1"
KEY_PREFIX = "tsk1"
_DERIVE_LABEL = b"tailisman/v1/aud:"
_MAX_INT = 2**53 - 1


class ErrorCode(enum.StrEnum):
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    WRONG_AUDIENCE = "wrong_audience"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REPLAYED = "replayed"
    DEVICE_NOT_ALLOWED = "device_not_allowed"


class TailismanError(Exception):
    def __init__(self, code: ErrorCode, message: str = "") -> None:
        super().__init__(message or code.value)
        self.code = code


@dataclasses.dataclass(frozen=True)
class Claim:
    node_id: str
    node_name: str
    login: str
    audience: str
    issued_at: int
    expires_at: int
    nonce: str


_WIRE = {
    "nid": ("node_id", str),
    "nn": ("node_name", str),
    "sub": ("login", str),
    "aud": ("audience", str),
    "iat": ("issued_at", int),
    "exp": ("expires_at", int),
    "nonce": ("nonce", str),
}

_ORIGIN = re.compile(r"(https?)://([a-z0-9.-]+|\[[0-9a-f:.]+\])(?::([0-9]{1,5}))?/?", re.IGNORECASE)
_DEFAULT_PORT = {"http": 80, "https": 443}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_NONCE = re.compile(r"[A-Za-z0-9_-]{22}")


def normalise_origin(text: str) -> str:
    """'HTTPS://Heckle.Example.com:443/' -> 'https://heckle.example.com'. Raises ValueError for anything that is not a bare origin."""
    match = _ORIGIN.fullmatch(text)
    if not match:
        raise ValueError(f"not an origin: {text!r}")
    scheme, host, port = match.group(1).lower(), match.group(2).lower(), match.group(3)
    if port is None or int(port) == _DEFAULT_PORT[scheme]:
        return f"{scheme}://{host}"
    if not 0 < int(port) < 65536:
        raise ValueError(f"bad port in origin: {text!r}")
    return f"{scheme}://{host}:{int(port)}"


def derive_consumer_key(master: bytes, origin: str) -> bytes:
    return hmac.new(master, _DERIVE_LABEL + normalise_origin(origin).encode(), hashlib.sha256).digest()


def format_key(key: bytes) -> str:
    return f"{KEY_PREFIX}.{b64encode(key)}"


def parse_key(text: str) -> bytes:
    prefix, _, body = text.strip().partition(".")
    key = _b64decode(body) if prefix == KEY_PREFIX else None
    if key is None or len(key) != 32:
        raise TailismanError(ErrorCode.MALFORMED, "a consumer key looks like tsk1.<43 base64url characters>")
    return key


def new_nonce() -> str:
    return b64encode(secrets.token_bytes(16))


def encode(claim: Claim, key: bytes) -> str:
    payload = {wire: getattr(claim, field) for wire, (field, _) in _WIRE.items()}
    return sign(json.dumps(payload, separators=(",", ":")), key)


def sign(payload_json: str, key: bytes) -> str:
    """Signs any text. encode() is the issuer's path; the test vectors use this to build malformed payloads."""
    signing_input = f"{TOKEN_PREFIX}.{b64encode(payload_json.encode())}"
    return f"{signing_input}.{b64encode(_mac(key, signing_input))}"


def decode(token: str, key: bytes) -> Claim:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise TailismanError(ErrorCode.MALFORMED, "a token looks like tsm1.<payload>.<mac>")
    mac = _b64decode(parts[2])
    if mac is None or _b64decode(parts[1]) is None:
        raise TailismanError(ErrorCode.MALFORMED, "token parts are not base64url")
    if not hmac.compare_digest(mac, _mac(key, f"{parts[0]}.{parts[1]}")):
        raise TailismanError(ErrorCode.BAD_SIGNATURE)
    return _parse_payload(_b64decode(parts[1]))


def _parse_payload(raw: bytes) -> Claim:
    try:
        payload = json.loads(raw.decode("utf-8"), parse_constant=_reject, parse_float=_reject)
    except (UnicodeDecodeError, ValueError) as exc:
        raise TailismanError(ErrorCode.MALFORMED, "payload is not JSON") from exc
    if not isinstance(payload, dict) or payload.keys() != _WIRE.keys():
        raise TailismanError(ErrorCode.MALFORMED, "payload keys are not exactly " + ",".join(_WIRE))
    fields = {}
    for wire, (field, kind) in _WIRE.items():
        value = payload[wire]
        if type(value) is not kind or (kind is int and not 0 <= value <= _MAX_INT) or (kind is str and not value):
            raise TailismanError(ErrorCode.MALFORMED, f"payload field {wire} has the wrong type")
        fields[field] = value
    if not _NONCE.fullmatch(fields["nonce"]):
        raise TailismanError(ErrorCode.MALFORMED, "nonce is not 16 bytes of base64url")
    return Claim(**fields)


def _reject(text: str):
    raise ValueError(f"non-integer number {text}")


def _mac(key: bytes, signing_input: str) -> bytes:
    return hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()


def b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes | None:
    """Strict: base64url alphabet, no padding, canonical, so one byte string has exactly one spelling."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return raw if b64encode(raw) == text else None
