"""The backup password: a scrypt hash in a one-line file, and a passphrase generator.

Hash line: scrypt$<log2 N>$<r>$<p>$<b64 salt>$<b64 hash>
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import hmac
import os
import secrets
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

LOG_N, R, P = 15, 8, 1
SALT_BYTES = 16
HASH_BYTES = 32
CONSONANTS = "bcdfghjklmnprstvwxyz"
VOWELS = "aeiou"
GROUPS = 6
MAX_MEMORY = 256 * 1024 * 1024
T = TypeVar("T")


@dataclasses.dataclass(frozen=True)
class PasswordHash:
    line: str
    log_n: int
    r: int
    p: int
    salt: bytes
    digest: bytes

    def matches(self, password: str) -> bool:
        return hmac.compare_digest(_scrypt(password, self.salt, self.log_n, self.r, self.p, len(self.digest)), self.digest)


def hash_password(password: str, log_n: int = LOG_N, r: int = R, p: int = P) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(password, salt, log_n, r, p, HASH_BYTES)
    return f"scrypt${log_n}${r}${p}${_b64(salt)}${_b64(digest)}"


def parse_hash(line: str) -> PasswordHash | None:
    parts = line.strip().split("$")
    if len(parts) != 6 or parts[0] != "scrypt" or not all(p.isdigit() for p in parts[1:4]):
        return None
    log_n, r, p = (int(x) for x in parts[1:4])
    try:
        salt, digest = base64.b64decode(parts[4], validate=True), base64.b64decode(parts[5], validate=True)
    except binascii.Error:
        return None
    if not 10 <= log_n <= 20 or not 1 <= r <= 32 or not 1 <= p <= 16 or len(salt) < 8 or len(digest) < 16:
        return None
    if 128 * r << log_n > MAX_MEMORY:
        return None
    return PasswordHash(line.strip(), log_n, r, p, salt, digest)


class ReloadingFile(Generic[T]):
    """A parsed file, re-read when its mtime or size changes, so `tailisman passwd` takes effect without a restart."""

    def __init__(self, path: Path, parse: Callable[[str], T], missing: T) -> None:
        self.path = path
        self._parse = parse
        self._missing = missing
        self._lock = threading.Lock()
        self._stamp: tuple[int, int] | None = None
        self._value = missing

    def current(self) -> T:
        try:
            info = os.stat(self.path)
            stamp = (info.st_mtime_ns, info.st_size)
        except OSError:
            stamp = None
        with self._lock:
            if stamp != self._stamp:
                self._stamp = stamp
                self._value = self._read() if stamp is not None else self._missing
            return self._value

    def _read(self) -> T:
        try:
            return self._parse(self.path.read_text())
        except (OSError, UnicodeDecodeError):
            return self._missing


def parse_password_file(text: str) -> PasswordHash | None:
    """None when the file is malformed, which turns the password path off."""
    lines = text.splitlines()
    return parse_hash(lines[0]) if len(lines) == 1 else None


def generate_passphrase(groups: int = GROUPS) -> str:
    """Six consonant-vowel-consonant-vowel groups, such as bavu-tiko-relu-mazo-pine-dusa: 6 * log2(20*5*20*5) = 79.7 bits."""
    pick = secrets.choice
    return "-".join(pick(CONSONANTS) + pick(VOWELS) + pick(CONSONANTS) + pick(VOWELS) for _ in range(groups))


def write_private(path: Path, text: str, overwrite: bool) -> None:
    """Writes atomically with mode 0600: a temporary file in the same directory, then os.replace (or os.link when not overwriting)."""
    temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        if overwrite:
            os.replace(temp, path)
        else:
            os.link(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _scrypt(password: str, salt: bytes, log_n: int, r: int, p: int, length: int) -> bytes:
    n = 1 << log_n
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=length, maxmem=128 * r * (n + p + 2) + 1024 * 1024)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
