"""Who a password or a cookie signs in: the owner's scrypt hash and the named guests, both re-read when their files change.

Guest file, one line per guest: NAME GRANTS DIGEST, such as `alice tools.example.com,notes.example.com sha256$<b64>`.
GRANTS is comma-separated. A bare host opens the whole host; a host followed by a path opens only that folder
(`notes.example.com/reports/*`) or that exact link (`notes.example.com/reports/may.html`), and a host may appear with
several paths. The scope is read from this file on every request, so a share or unshare takes effect at once.
DIGEST is SHA-256 over a fixed label and the passphrase. Guest passphrases are always generated (about 80 bits), so a
fast unsalted digest cannot be guessed back, and a login costs one dictionary lookup before the owner's scrypt.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import sys
from pathlib import Path

from .config import ConfigError, OpenRule, host_without_port, is_plain_path, parse_guest_path, site_key
from .password import PasswordHash, ReloadingFile, parse_password_file, write_private
from .session import GUEST_NAME, Method, Session, first_valid, guest_key, session_key

_DIGEST_LABEL = b"tailisman/gate/guest-password/v1:"


Grants = dict[str, tuple[OpenRule, ...]]
"""Site key -> the paths a guest may use there, in the order given; an empty tuple is the whole host."""


@dataclasses.dataclass(frozen=True)
class Guest:
    name: str
    grants: Grants
    digest: str

    @property
    def sites(self) -> tuple[str, ...]:
        return tuple(self.grants)

    def allows(self, site: str, path: str | None) -> bool:
        """None for the path asks about the site alone. A path is matched raw and must be plain, so no spelling reaches outside."""
        if site not in self.grants:
            return False
        rules = self.grants[site]
        return not rules or path is None or (is_plain_path(path) and any(rule.matches("", path) for rule in rules))

    def landing(self, site: str) -> str:
        rules = self.grants.get(site, ())
        return rules[0].path if rules else "/"

    def line(self) -> str:
        return f"{self.name} {format_grants(self.grants)} {self.digest}"


def format_grants(grants: Grants) -> str:
    return ",".join(f"{site}{rule}" for site, rules in grants.items() for rule in (rules or ("",)))


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
    grants = parse_grants(parts[1])
    return Guest(parts[0], grants, parts[2]) if grants else None


def parse_grants(text: str) -> Grants | None:
    """None when any entry is malformed, so a typo never widens a guest to a whole host. A bare host beats its paths."""
    grants: dict[str, list[OpenRule]] = {}
    whole: set[str] = set()
    for entry in text.split(","):
        host, slash, path = entry.partition("/")
        if site_key(host) != host:
            return None
        if not slash:
            whole.add(host)
            grants.setdefault(host, [])
            continue
        try:
            rule = parse_guest_path(slash + path)
        except ConfigError:
            return None
        rules = grants.setdefault(host, [])
        if rule not in rules:
            rules.append(rule)
    return {host: () if host in whole else tuple(rules) for host, rules in grants.items()}


def parse_guests(text: str, path: Path | str = "guest file") -> Guests:
    """Skips a malformed or repeated line and says so once, on the read that found it; the rest of the file still counts."""
    guests: dict[str, Guest] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        guest = parse_guest_line(line)
        if guest is None or guest.name in guests:
            print(f"tailisman gate: {path} line {number} is not a new NAME GRANTS DIGEST record; skipped", file=sys.stderr)
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

    def guest_key(self, name: str, site: str, path: str | None = None) -> bytes | None:
        """None unless the guest exists and may use this site (and this path, when one is asked about), which is what keeps a
        parent-domain guest cookie off the owner's other sites and a path-scoped guest inside their paths."""
        guest = self.guests.current().by_name.get(name)
        return guest_key(self.secret, guest.name, guest.digest) if guest is not None and guest.allows(site, path) else None

    def destination(self, guest: str | None, site: str, next_path: str) -> str:
        """Where a sign-in goes: next when the session may open it, else a path-scoped guest's first path on this site."""
        record = self.guests.current().by_name.get(guest) if guest else None
        if record is None or record.allows(site, next_path.split("?", 1)[0]):
            return next_path
        return record.landing(site)

    def session_for(self, cookies: tuple[str, ...], site: str, now: int, path: str | None = None) -> Session | None:
        """The session the cookies hold on this site. With a path, a path-scoped guest's cookie counts only inside their paths;
        without one (the gate's own pages), it counts anywhere on a site they have."""

        def key_for(guest: str | None) -> bytes | None:
            return self.owner_key() if guest is None else self.guest_key(guest, site, path)

        return first_valid(cookies, key_for, host_without_port(site), now)

    def guest_count(self, site: str) -> int:
        return sum(site in guest.sites for guest in self.guests.current().by_name.values())


GUESTS_DIR = "guests"
"""Where guest passphrase files go, next to gate.toml: guests/NAME, mode 0600, in a 0700 directory."""


def read_guest_file(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def guest_records(path: Path) -> dict[str, str]:
    """Each record line by guest name, malformed lines kept under a key no name can take, so a rewrite never drops them."""
    records: dict[str, str] = {}
    for number, line in enumerate(read_guest_file(path).splitlines()):
        guest = parse_guest_line(line)
        records[guest.name if guest and guest.name not in records else f" {number}"] = line
    return records


def write_guest_records(path: Path, records: dict[str, str]) -> None:
    write_private(path, "".join(line + "\n" for line in records.values()), overwrite=True)
