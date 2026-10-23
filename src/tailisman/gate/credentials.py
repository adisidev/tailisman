"""Who a password or a cookie signs in: the owner's scrypt hash and the named guests, both re-read when their files change.

Guest file, one line per guest: NAME SITES DIGEST, such as `alice tools.example.com,notes.example.com sha256$<b64>`.
DIGEST is SHA-256 over a fixed label and the passphrase. Guest passphrases are always generated (about 80 bits), so a
fast unsalted digest cannot be guessed back, and a login costs one dictionary lookup before the owner's scrypt.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import sys
from pathlib import Path

from .config import host_without_port, site_key
from .password import PasswordHash, ReloadingFile, parse_password_file
from .session import GUEST_NAME, Method, Session, first_valid, guest_key, session_key

_DIGEST_LABEL = b"tailisman/gate/guest-password/v1:"


@dataclasses.dataclass(frozen=True)
class Guest:
    name: str
    sites: tuple[str, ...]
    digest: str

    def line(self) -> str:
        return f"{self.name} {','.join(self.sites)} {self.digest}"


@dataclasses.dataclass(frozen=True)
class Guests:
    by_name: dict[str, Guest]

    def by_digest(self, digest: str) -> Guest | None:
        return next((guest for guest in self.by_name.values() if guest.digest == digest), None)


NO_GUESTS = Guests({})


@dataclasses.dataclass(frozen=True)
class Opened:
    """What a correct password opens: the owner's password session, or one guest's, with the key its cookie is signed under."""

    method: Method
    guest: str | None
    key: bytes


def guest_digest(passphrase: str) -> str:
    return "sha256$" + base64.b64encode(hashlib.sha256(_DIGEST_LABEL + passphrase.encode("utf-8")).digest()).decode("ascii")


def parse_guest_line(line: str) -> Guest | None:
    parts = line.split()
    if len(parts) != 3 or not GUEST_NAME.fullmatch(parts[0]) or not parts[2].startswith("sha256$") or len(parts[2]) != 51:
        return None
    sites = tuple(parts[1].split(","))
    if not all(site_key(site) == site for site in sites):
        return None
    return Guest(parts[0], sites, parts[2])


def parse_guests(text: str, path: Path | str = "guest file") -> Guests:
    """Skips a malformed or repeated line and says so once, on the read that found it; the rest of the file still counts."""
    guests: dict[str, Guest] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        guest = parse_guest_line(line)
        if guest is None or guest.name in guests:
            print(f"tailisman gate: {path} line {number} is not a new NAME SITES DIGEST record; skipped", file=sys.stderr)
            continue
        guests[guest.name] = guest
    return Guests(guests)


class Credentials:
    def __init__(self, secret: bytes, password_file: Path, guest_file: Path) -> None:
        self.secret = secret
        self.owner: ReloadingFile[PasswordHash | None] = ReloadingFile(password_file, parse_password_file, None)
        self.guests: ReloadingFile[Guests] = ReloadingFile(guest_file, lambda text: parse_guests(text, guest_file), NO_GUESTS)

    def opens(self, password: str | None, site: str) -> Opened | None:
        """The session a password opens on this site. A guest's password for another site falls through to scrypt and fails like any wrong one."""
        if not password:
            return None
        guest = self.guests.current().by_digest(guest_digest(password))
        if guest is not None and site in guest.sites:
            return Opened(Method.GUEST, guest.name, guest_key(self.secret, guest.name, guest.digest))
        owner = self.owner.current()
        return Opened(Method.PASSWORD, None, self.owner_key()) if owner is not None and owner.matches(password) else None

    def owner_key(self) -> bytes:
        owner = self.owner.current()
        return session_key(self.secret, owner.line if owner else "")

    def guest_key(self, name: str, site: str) -> bytes | None:
        """None unless the guest exists and may use this site, which is what keeps a parent-domain guest cookie off the owner's other sites."""
        guest = self.guests.current().by_name.get(name)
        return guest_key(self.secret, guest.name, guest.digest) if guest is not None and site in guest.sites else None

    def session_for(self, cookies: tuple[str, ...], site: str, now: int) -> Session | None:
        def key_for(guest: str | None) -> bytes | None:
            return self.owner_key() if guest is None else self.guest_key(guest, site)

        return first_valid(cookies, key_for, host_without_port(site), now)

    def guest_count(self, site: str) -> int:
        return sum(site in guest.sites for guest in self.guests.current().by_name.values())
