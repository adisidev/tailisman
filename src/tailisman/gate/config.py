"""gate.toml, parsed once into frozen types. The `sites` table is the only list of gated hosts."""

from __future__ import annotations

import dataclasses
import re
import time
import tomllib
from collections.abc import Callable
from pathlib import Path

from .. import Verifier
from .._token import TailismanError, normalise_origin
from ..issuer.config import ConfigError, TcpListen, UnixListen, parse_listen

MAX_COOKIE_DAYS = 400
ADDRESS_SPACES = ("local", "loopback")


@dataclasses.dataclass(frozen=True)
class OpenRule:
    method: str | None
    path: str
    prefix: bool

    def matches(self, method: str, path: str) -> bool:
        if self.method is not None and method != self.method:
            return False
        return path.startswith(self.path) if self.prefix else path == self.path

    def __str__(self) -> str:
        path = self.path + "*" if self.prefix else self.path
        return f"{self.method} {path}" if self.method else path


@dataclasses.dataclass(frozen=True)
class Site:
    host: str
    origin: str
    cookie_domain: str | None
    verifier: Verifier | None
    open: tuple[OpenRule, ...]

    @property
    def scope(self) -> str:
        """The cookie's Domain when set, else the host name (no port: cookies ignore ports)."""
        return self.cookie_domain or host_without_port(self.host)


@dataclasses.dataclass(frozen=True)
class RateLimits:
    per_ip: int
    total: int
    window_seconds: int


@dataclasses.dataclass(frozen=True)
class GateConfig:
    listen: TcpListen
    session_secret: bytes
    password_file: Path
    session_days: int
    issuer: str | None
    issuer_address_space: str
    rate_limit: RateLimits
    sites: dict[str, Site]


_TOP_KEYS = {"listen", "session_secret_file", "password_file", "session_days", "issuer", "issuer_address_space", "rate_limit", "sites"}
_RATE_KEYS = {"per_ip", "global", "window_seconds"}
_SITE_KEYS = {"host", "cookie_domain", "tailisman_key", "open"}
_HOST = re.compile(r"([a-z0-9-]+(?:\.[a-z0-9-]+)+|localhost)\.?(?::([0-9]{1,5}))?", re.ASCII | re.IGNORECASE)
_OPEN = re.compile(r"(?:([A-Z]+) )?(/[^\s*?#]*)(\*)?")


def site_key(text: str) -> str | None:
    """'Tools.Example.com.:443' -> 'tools.example.com', 'tools.example.com:8443' keeps its port. None for anything else."""
    match = _HOST.fullmatch(text.strip())
    if not match:
        return None
    name, port = match.group(1).lower(), match.group(2)
    if port is None or int(port) == 443:
        return name
    return f"{name}:{int(port)}" if 0 < int(port) < 65536 else None


def host_without_port(key: str) -> str:
    return key.rsplit(":", 1)[0]


def load_config(path: str | Path, clock: Callable[[], float] = time.time) -> GateConfig:
    try:
        raw = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return parse_config(raw, base=Path(path).parent, clock=clock)


def parse_config(raw: dict, base: Path = Path("."), clock: Callable[[], float] = time.time) -> GateConfig:
    """`clock` drives each site's token Verifier; the gate passes its own so one clock rules every expiry check."""
    _no_unknown_keys(raw, _TOP_KEYS, "top level")
    secret_path = base / _required_str(raw, "session_secret_file")
    try:
        secret = secret_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"session_secret_file: {exc}") from exc
    if len(secret) != 32:
        raise ConfigError(f"session_secret_file {secret_path} must hold exactly 32 bytes; create it with `tailisman keygen`")
    listen = parse_listen(raw.get("listen", "127.0.0.1:8471"))
    if isinstance(listen, UnixListen):
        raise ConfigError("the gate listens on loopback TCP only, because Caddy's forward_auth and reverse_proxy both point at it")
    days = raw.get("session_days", 30)
    if type(days) is not int or not 1 <= days <= MAX_COOKIE_DAYS:
        raise ConfigError(f"session_days must be an integer from 1 to {MAX_COOKIE_DAYS} (browsers cap cookies at {MAX_COOKIE_DAYS} days)")
    issuer = raw.get("issuer")
    if issuer is not None:
        try:
            issuer = normalise_origin(issuer) if isinstance(issuer, str) else None
        except ValueError:
            issuer = None
        if issuer is None:
            raise ConfigError("issuer must be the issuer's origin, such as https://laptop.example-tailnet.ts.net:8443")
    space = raw.get("issuer_address_space", "local")
    if space not in ADDRESS_SPACES:
        raise ConfigError('issuer_address_space must be "local" (a tailnet issuer) or "loopback" (local testing only)')
    sites: dict[str, Site] = {}
    entries = raw.get("sites", [])
    if not isinstance(entries, list) or not entries:
        raise ConfigError("at least one [[sites]] table is required")
    for entry in entries:
        site = _site(entry, issuer, clock)
        if site.host in sites:
            raise ConfigError(f"site {site.host} is configured twice")
        sites[site.host] = site
    return GateConfig(
        listen=listen,
        session_secret=secret,
        password_file=base / _required_str(raw, "password_file"),
        session_days=days,
        issuer=issuer,
        issuer_address_space=space,
        rate_limit=_rate_limits(raw.get("rate_limit", {})),
        sites=sites,
    )


def parse_open_rule(text: object) -> OpenRule:
    match = _OPEN.fullmatch(text) if isinstance(text, str) else None
    if not match or (match.group(3) and not match.group(2).endswith("/")):
        raise ConfigError(f"open rule {text!r} must look like \"/healthz\", \"/api/*\" or \"POST /report\"; a * only ends a path after a /")
    method, path, star = match.groups()
    if not is_plain_path(path):
        raise ConfigError(f"open rule {text!r} has a .. segment, an encoded character that hides one, or a backslash")
    return OpenRule(method, path, bool(star))


def is_plain_path(path: str) -> bool:
    """False for anything an upstream might normalise into another path: .. segments, empty segments (//), ;params, %2e, %2f, %5c, backslashes."""
    lowered = path.lower()
    if "\\" in path or ";" in path or any(code in lowered for code in ("%2e", "%2f", "%5c")):
        return False
    segments = path.split("/")[1:]
    return ".." not in segments and "" not in segments[:-1]


def _site(entry: object, issuer: str | None, clock: Callable[[], float]) -> Site:
    if not isinstance(entry, dict):
        raise ConfigError("each [[sites]] entry must be a table")
    _no_unknown_keys(entry, _SITE_KEYS, "[[sites]]")
    text = _required_str(entry, "host")
    host = site_key(text)
    if host is None or text.strip().lower().startswith(("http:", "https:")):
        raise ConfigError(f"site host {text!r} must be a DNS name with an optional port, such as tools.example.com")
    name = host_without_port(host)
    cookie_domain = entry.get("cookie_domain")
    if cookie_domain is not None:
        domain = cookie_domain.strip().lower().removeprefix(".") if isinstance(cookie_domain, str) else ""
        if "." not in domain or not (name == domain or name.endswith("." + domain)):
            raise ConfigError(f"site {host} cookie_domain {cookie_domain!r} must be {name} or a parent domain of it")
        cookie_domain = domain
    verifier = None
    if "tailisman_key" in entry:
        if issuer is None:
            raise ConfigError(f"site {host} has a tailisman_key but the gate has no issuer; set issuer at the top level")
        try:
            verifier = Verifier(key=_required_str(entry, "tailisman_key"), audience="https://" + host, clock=clock)
        except TailismanError as exc:
            raise ConfigError(f"site {host} tailisman_key: {exc}") from exc
    rules = entry.get("open", [])
    if not isinstance(rules, list):
        raise ConfigError(f"site {host} open must be a list of rules")
    return Site(host, normalise_origin("https://" + host), cookie_domain, verifier, tuple(parse_open_rule(r) for r in rules))


def _rate_limits(table: object) -> RateLimits:
    if not isinstance(table, dict):
        raise ConfigError("rate_limit must be a table")
    _no_unknown_keys(table, _RATE_KEYS, "[rate_limit]")
    values = {"per_ip": 5, "global": 30, "window_seconds": 900} | table
    for key, value in values.items():
        if type(value) is not int or value < 1:
            raise ConfigError(f"rate_limit.{key} must be a positive integer")
    return RateLimits(values["per_ip"], values["global"], values["window_seconds"])


def _required_str(table: dict, key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{key} is required")
    return value


def _no_unknown_keys(table: dict, allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"unknown key(s) at {where}: {', '.join(sorted(unknown))}")
