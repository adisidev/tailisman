"""gate.toml, parsed once into frozen types. The `sites` table is the only list of gated hosts."""

from __future__ import annotations

import dataclasses
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

import secrets

from .._token import normalise_origin
from ..issuer.config import Audience, ConfigError, IssuerConfig, Listen, TcpListen, UnixListen, host_name, parse_audience, parse_listen, string_list

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
class Upstream:
    """The app a proxy site forwards to: plain HTTP on a host and port, because the gate is the hop that sees the browser."""

    host: str
    port: int

    def __str__(self) -> str:
        return f"http://{f'[{self.host}]' if ':' in self.host else self.host}:{self.port}"


@dataclasses.dataclass(frozen=True)
class Site:
    host: str
    origin: str
    cookie_domain: str | None
    tailnet: bool
    open: tuple[OpenRule, ...]
    upstream: Upstream | None = None
    bearers: frozenset[str] = frozenset()

    @property
    def scope(self) -> str:
        """The cookie's Domain when set, else the host name (no port: cookies ignore ports)."""
        return self.cookie_domain or host_without_port(self.host)


@dataclasses.dataclass(frozen=True)
class Tailnet:
    """The gate's tailnet listener. `checks` feeds the issuer's decide(): the serve name, whois and one audience per tailnet site."""

    checks: IssuerConfig
    origin: str
    address_space: str

    @property
    def listen(self) -> Listen:
        return self.checks.listen


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
    guest_file: Path
    session_days: int
    tailnet: Tailnet | None
    rate_limit: RateLimits
    sites: dict[str, Site]


_TOP_KEYS = {"listen", "session_secret_file", "password_file", "guest_file", "session_days", "tailnet", "rate_limit", "sites"}
_TAILNET_KEYS = {"listen", "serve_host", "port", "origin", "tailscale_bin", "devices", "users", "refuse_automation", "ttl_seconds", "address_space"}
_RATE_KEYS = {"per_ip", "global", "window_seconds"}
_SITE_KEYS = {"host", "cookie_domain", "tailnet", "open", "upstream", "bearers"}
_HOST = re.compile(r"([a-z0-9-]+(?:\.[a-z0-9-]+)+|localhost)\.?(?::([0-9]{1,5}))?", re.ASCII | re.IGNORECASE)
BEARER_DIGEST = re.compile(r"sha256\$[A-Za-z0-9+/]{43}=")
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


def load_config(path: str | Path) -> GateConfig:
    try:
        raw = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return parse_config(raw, base=Path(path).parent)


def parse_config(raw: dict, base: Path = Path(".")) -> GateConfig:
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
        raise ConfigError("the gate listens on loopback TCP only, because a tunnel's ingress or Caddy's forward_auth points at it over TCP")
    days = raw.get("session_days", 30)
    if type(days) is not int or not 1 <= days <= MAX_COOKIE_DAYS:
        raise ConfigError(f"session_days must be an integer from 1 to {MAX_COOKIE_DAYS} (browsers cap cookies at {MAX_COOKIE_DAYS} days)")
    sites: dict[str, Site] = {}
    entries = raw.get("sites", [])
    if not isinstance(entries, list) or not entries:
        raise ConfigError("at least one [[sites]] table is required")
    for entry in entries:
        site = _site(entry)
        if site.host in sites:
            raise ConfigError(f"site {site.host} is configured twice")
        sites[site.host] = site
    return GateConfig(
        listen=listen,
        session_secret=secret,
        password_file=base / _required_str(raw, "password_file"),
        guest_file=base / _optional_str(raw, "guest_file", "guest-passwords"),
        session_days=days,
        tailnet=_tailnet(raw["tailnet"], listen, sites) if "tailnet" in raw else None,
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


def _site(entry: object) -> Site:
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
    tailnet = entry.get("tailnet", True)
    if type(tailnet) is not bool:
        raise ConfigError(f"site {host} tailnet must be true or false")
    rules = entry.get("open", [])
    if not isinstance(rules, list):
        raise ConfigError(f"site {host} open must be a list of rules")
    upstream = parse_upstream(entry["upstream"], host) if "upstream" in entry else None
    bearers = entry.get("bearers", [])
    if not isinstance(bearers, list) or not all(isinstance(b, str) and BEARER_DIGEST.fullmatch(b) for b in bearers):
        raise ConfigError(f"site {host} bearers must be a list of sha256$<base64> digests from `tailisman gate bearer-hash`")
    return Site(host, normalise_origin("https://" + host), cookie_domain, tailnet, tuple(parse_open_rule(r) for r in rules), upstream, frozenset(bearers))


def parse_upstream(text: object, host: str) -> Upstream:
    message = f"site {host} upstream {text!r} must be http://HOST:PORT with nothing else, such as http://127.0.0.1:9000"
    if not isinstance(text, str):
        raise ConfigError(message)
    try:
        url = urlsplit(text.strip())
        port = url.port
    except ValueError as exc:
        raise ConfigError(message) from exc
    if url.scheme == "https":
        raise ConfigError(message + "; the gate speaks plain HTTP to the app, so put the app on a loopback port")
    if url.username is not None or url.password is not None:
        raise ConfigError(message + "; a user name or password is not allowed")
    if url.path not in ("", "/") or url.query or url.fragment or "?" in text or "#" in text:
        raise ConfigError(message + "; a path, query or fragment is not allowed, the browser's own path is forwarded as is")
    if url.scheme != "http" or not url.hostname or port is None:
        raise ConfigError(message)
    return Upstream(url.hostname, port)


def _tailnet(table: object, public: TcpListen, sites: dict[str, Site]) -> Tailnet:
    """Parsed with the issuer's own parsers; the audiences are the gated sites themselves."""
    if not isinstance(table, dict):
        raise ConfigError("tailnet must be a table")
    _no_unknown_keys(table, _TAILNET_KEYS, "[tailnet]")
    listen = parse_listen(table.get("listen", "127.0.0.1:8470"))
    if listen == public:
        raise ConfigError("[tailnet] listen must differ from the gate's own listen; tailscale serve fronts it, the public side never does")
    serve_host = table.get("serve_host")
    if not isinstance(serve_host, str) or ":" in serve_host or host_name(serve_host) is None:
        raise ConfigError("[tailnet] serve_host must be this machine's MagicDNS name, such as gate.example-tailnet.ts.net, with no port")
    port = table.get("port", 8443)
    if type(port) is not int or not 0 < port < 65536:
        raise ConfigError("[tailnet] port must be the HTTPS port tailscale serve uses, such as 8443")
    try:
        origin = normalise_origin(table["origin"] if "origin" in table else f"https://{host_name(serve_host)}:{port}")
    except (TypeError, ValueError) as exc:
        raise ConfigError("[tailnet] origin must be scheme://host[:port], the address browsers reach the tailnet listener at") from exc
    ttl = table.get("ttl_seconds", 60)
    if type(ttl) is not int or not 10 <= ttl <= 300:
        raise ConfigError("[tailnet] ttl_seconds must be an integer from 10 to 300")
    space = table.get("address_space", "local")
    if space not in ADDRESS_SPACES:
        raise ConfigError('[tailnet] address_space must be "local" (a tailnet address) or "loopback" (local testing only)')
    tailscale_bin = table.get("tailscale_bin", "auto")
    if not isinstance(tailscale_bin, str) or not tailscale_bin:
        raise ConfigError('[tailnet] tailscale_bin must be "auto" or a path')
    devices = string_list(table.get("devices", []), "[tailnet] devices")
    if not devices:
        raise ConfigError("[tailnet] devices is required: the stable IDs or names of the devices that may sign in this way")
    policy = {key: table[key] for key in ("users", "refuse_automation") if key in table}
    audiences: dict[str, Audience] = {}
    for site in sites.values():
        if site.tailnet:
            audiences[site.origin] = parse_audience({"origin": site.origin} | policy, devices)
    # The gate never signs tokens; a random master means a stray mint() could not produce anything a verifier accepts.
    checks = IssuerConfig(secrets.token_bytes(32), listen, ttl, tailscale_bin, host_name(serve_host), audiences)
    return Tailnet(checks, origin, space)


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


def _optional_str(table: dict, key: str, default: str) -> str:
    return _required_str(table, key) if key in table else default


def _no_unknown_keys(table: dict, allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"unknown key(s) at {where}: {', '.join(sorted(unknown))}")
