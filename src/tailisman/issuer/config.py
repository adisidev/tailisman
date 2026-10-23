"""issuer.toml, parsed once into frozen types. Every invariant the request path relies on is checked here."""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import shutil
import tomllib
from pathlib import Path

from .._token import normalise_origin

MACOS_APP_BINARY = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"


class ConfigError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class TcpListen:
    host: str
    port: int

    def serve_target(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"


@dataclasses.dataclass(frozen=True)
class UnixListen:
    path: str

    def serve_target(self) -> str:
        return f"unix:{self.path}"


Listen = TcpListen | UnixListen


@dataclasses.dataclass(frozen=True)
class Audience:
    origin: str
    devices: frozenset[str]
    users: frozenset[str] | None
    refuse_automation: bool


@dataclasses.dataclass(frozen=True)
class IssuerConfig:
    master: bytes
    listen: Listen
    ttl_seconds: int
    tailscale_bin: str
    serve_host: str | None
    audiences: dict[str, Audience]


_TOP_KEYS = {"secret_file", "listen", "ttl_seconds", "tailscale_bin", "serve_host", "devices", "audiences"}
_HOST = re.compile(r"([a-z0-9-]+(?:\.[a-z0-9-]+)*)\.?(?::[0-9]{1,5})?", re.ASCII | re.IGNORECASE)


def host_name(text: str) -> str | None:
    """'Laptop.Example-Tailnet.ts.net.:8443' -> 'laptop.example-tailnet.ts.net'; None for anything that is not a DNS name with an optional port."""
    match = _HOST.fullmatch(text)
    return match.group(1).lower() if match else None
_AUDIENCE_KEYS = {"origin", "devices", "users", "refuse_automation"}


def load_config(path: str | Path) -> IssuerConfig:
    try:
        raw = tomllib.loads(Path(path).read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return parse_config(raw, base=Path(path).parent)


def parse_config(raw: dict, base: Path = Path(".")) -> IssuerConfig:
    _no_unknown_keys(raw, _TOP_KEYS, "top level")
    secret_path = base / _required(raw, "secret_file", str)
    try:
        master = secret_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"secret_file: {exc}") from exc
    if len(master) != 32:
        raise ConfigError(f"secret_file {secret_path} must hold exactly 32 bytes; create it with `tailisman keygen`")
    ttl = raw.get("ttl_seconds", 60)
    if type(ttl) is not int or not 10 <= ttl <= 300:
        raise ConfigError("ttl_seconds must be an integer from 10 to 300")
    default_devices = string_list(raw.get("devices", []), "devices")
    audiences: dict[str, Audience] = {}
    entries = raw.get("audiences", [])
    if not isinstance(entries, list) or not entries:
        raise ConfigError("at least one [[audiences]] table is required")
    for entry in entries:
        audience = parse_audience(entry, default_devices)
        if audience.origin in audiences:
            raise ConfigError(f"audience {audience.origin} is configured twice")
        audiences[audience.origin] = audience
    tailscale_bin = raw.get("tailscale_bin", "auto")
    if not isinstance(tailscale_bin, str) or not tailscale_bin:
        raise ConfigError('tailscale_bin must be "auto" or a path')
    serve_host = raw.get("serve_host")
    if serve_host is not None and (not isinstance(serve_host, str) or ":" in serve_host or host_name(serve_host) is None):
        raise ConfigError("serve_host must be the issuer's MagicDNS name, such as issuer.example-tailnet.ts.net, with no port")
    return IssuerConfig(
        master=master,
        listen=parse_listen(raw.get("listen", "127.0.0.1:8470")),
        ttl_seconds=ttl,
        tailscale_bin=tailscale_bin,
        serve_host=host_name(serve_host) if serve_host is not None else None,
        audiences=audiences,
    )


def parse_listen(text: object) -> Listen:
    if not isinstance(text, str):
        raise ConfigError("listen must be a string")
    if text.startswith("unix:"):
        if not text[5:].startswith("/"):
            raise ConfigError("listen = \"unix:/absolute/path\" needs an absolute socket path")
        return UnixListen(text[5:])
    host, sep, port = text.rpartition(":")
    host = host.removeprefix("[").removesuffix("]")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not sep or not loopback or not port.isdigit() or not 0 < int(port) < 65536:
        raise ConfigError(f"listen must be a loopback address and port such as 127.0.0.1:8470, or unix:/path; got {text!r}")
    return TcpListen(host, int(port))


def resolve_tailscale_bin(setting: str) -> str:
    if setting != "auto":
        if not Path(setting).is_file():
            raise ConfigError(f"tailscale_bin {setting} does not exist")
        return setting
    if Path(MACOS_APP_BINARY).is_file():
        return MACOS_APP_BINARY
    found = shutil.which("tailscale")
    if found is None:
        raise ConfigError("no tailscale binary found; set tailscale_bin")
    return found


def parse_audience(entry: object, default_devices: frozenset[str]) -> Audience:
    if not isinstance(entry, dict):
        raise ConfigError("each [[audiences]] entry must be a table")
    _no_unknown_keys(entry, _AUDIENCE_KEYS, "[[audiences]]")
    text = _required(entry, "origin", str)
    try:
        origin = normalise_origin(text)
    except ValueError as exc:
        raise ConfigError(f"audience origin {text!r} must be scheme://host[:port] with no path") from exc
    devices = string_list(entry["devices"], f"{origin} devices") if "devices" in entry else default_devices
    if not devices:
        raise ConfigError(f"audience {origin} has no devices; set devices at the top level or on the audience")
    users = string_list(entry["users"], f"{origin} users") if "users" in entry else None
    if users is not None and not users:
        raise ConfigError(f"audience {origin} users is empty; leave it out to accept any user of an allowed device")
    refuse_automation = entry.get("refuse_automation", False)
    if type(refuse_automation) is not bool:
        raise ConfigError(f"audience {origin} refuse_automation must be true or false")
    return Audience(origin, devices, users, refuse_automation)


def _required(table: dict, key: str, kind: type):
    value = table.get(key)
    if type(value) is not kind or not value:
        raise ConfigError(f"{key} is required")
    return value


def string_list(value: object, name: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(f"{name} must be a list of non-empty strings")
    return frozenset(value)


def _no_unknown_keys(table: dict, allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"unknown key(s) at {where}: {', '.join(sorted(unknown))}")
