"""The gate's commands: gate run, gate status, passwd."""

from __future__ import annotations

import argparse
import getpass
import http.client
import json
import socket
import socketserver
import subprocess
import threading
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from ..issuer.cli import serve_hosts_for
from ..issuer.config import ConfigError, UnixListen, host_name, resolve_tailscale_bin
from ..issuer.http import make_server as make_issuer_server
from ..issuer.tailscale import cli_whois
from .config import GateConfig, Site, Tailnet, load_config, site_key
from .decision import LOGIN_PATH, bearer_digest
from .http import GateApp, make_server
from .credentials import Credentials, Guest, guest_digest, parse_guest_line, parse_guests
from .password import generate_passphrase, hash_password, write_private
from .session import GUEST_NAME

MIN_PASSWORD = 12
GUESTS_DIR = "guests"


def add_commands(commands: argparse._SubParsersAction) -> dict[str, Callable[[argparse.Namespace], int]]:
    gate = commands.add_parser("gate", help="the password-or-tailnet gate in front of Caddy sites")
    gate_commands = gate.add_subparsers(dest="gate_command", required=True)
    run = gate_commands.add_parser("run", help="serve the gate on its loopback address, in the foreground")
    run.add_argument("--config", required=True)
    status = gate_commands.add_parser("status", help="list the gated sites and check each one refuses an anonymous visitor")
    status.add_argument("--config", required=True)
    status.add_argument("--base-url-for", action="append", default=[], metavar="HOST=URL", help="send HOST's checks to URL instead of https://HOST, with HOST as the Host header")
    gate_commands.add_parser("bearer-hash", help="read one machine bearer token from stdin, without echo, and print the digest for a site's bearers list")
    passwd = commands.add_parser("passwd", help="set the gate's backup password, or add, revoke and list guest passwords; changes take effect without a restart")
    passwd.add_argument("--config", required=True)
    action = passwd.add_mutually_exclusive_group()
    action.add_argument("--generate", action="store_true", help="make the owner passphrase instead of prompting, and write it to --out")
    action.add_argument("--add", metavar="NAME", help="give guest NAME a generated passphrase for --sites, written to guests/NAME next to the config")
    action.add_argument("--revoke", metavar="NAME", help="remove guest NAME; their sessions end at once")
    action.add_argument("--list", action="store_true", help="list guests and their sites")
    passwd.add_argument("--out", help="where --generate writes the passphrase, mode 0600")
    passwd.add_argument("--sites", help="with --add: comma-separated [[sites]] hosts the guest may sign in to")
    passwd.add_argument("--force", action="store_true", help="let --generate overwrite --out, or --add replace an existing guest's password")
    return {"gate": lambda args: {"run": _run, "status": _status, "bearer-hash": _bearer_hash}[args.gate_command](args), "passwd": _passwd}


def make_servers(config: GateConfig) -> list[socketserver.BaseServer]:
    """The public listener, then the tailnet listener when [tailnet] is set. One process, so the codes one hands out the other redeems."""
    app = GateApp(config)
    password = "on" if app.credentials.owner.current() else f"off (no valid hash in {config.password_file}; run `tailisman passwd`)"
    servers = [make_server(app)]
    print(f"tailisman gate: listening on {config.listen.serve_target()} for {', '.join(config.sites)}; password {password}", file=sys.stderr)
    if config.tailnet is not None:
        tailnet = app.tailnet_app(cli_whois(resolve_tailscale_bin(config.tailnet.checks.tailscale_bin)))
        servers.append(make_issuer_server(tailnet))
        target = config.tailnet.listen.serve_target()
        print(f"tailisman gate: tailnet listener on {target} as {config.tailnet.origin}; front it with `tailscale serve --bg --https={_port(config.tailnet.origin)} {target}`, never Funnel", file=sys.stderr)
    return servers


def _run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    public, *others = make_servers(config)
    for server in others:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        public.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for server in (public, *others):
            server.server_close()
        if config.tailnet is not None and isinstance(config.tailnet.listen, UnixListen):
            Path(config.tailnet.listen.path).unlink(missing_ok=True)
    return 0


def _port(origin: str) -> int:
    return urlsplit(origin).port or 443


def _passwd(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.sites is not None and args.add is None:
        raise ConfigError("--sites goes with --add NAME")
    if args.add is not None:
        return _add_guest(config, Path(args.config).parent / GUESTS_DIR, args.add, args.sites, args.force)
    if args.revoke is not None:
        return _revoke_guest(config, Path(args.config).parent / GUESTS_DIR, args.revoke)
    if args.list:
        return _list_guests(config)
    if args.generate:
        if not args.out:
            raise ConfigError("--generate needs --out PATH for the passphrase")
        password = generate_passphrase()
        try:
            write_private(Path(args.out), password + "\n", overwrite=args.force)
        except FileExistsError:
            print(f"tailisman: {args.out} already exists; pass --force to overwrite it", file=sys.stderr)
            return 1
        print(f"wrote the passphrase to {args.out}")
    else:
        password = getpass.getpass("New gate password: ")
        if getpass.getpass("Again: ") != password:
            print("tailisman: the two passwords differ; nothing written", file=sys.stderr)
            return 1
        if len(password) < MIN_PASSWORD:
            print(f"tailisman: use at least {MIN_PASSWORD} characters, or --generate; nothing written", file=sys.stderr)
            return 1
    write_private(config.password_file, hash_password(password) + "\n", overwrite=True)
    print(f"wrote the password hash to {config.password_file}")
    return 0


def _add_guest(config: GateConfig, directory: Path, name: str, sites_text: str | None, force: bool) -> int:
    if not GUEST_NAME.fullmatch(name):
        raise ConfigError(f"guest name {name!r} must be 1 to 32 of a-z, 0-9, _ and -, starting with a letter or digit")
    sites = _guest_sites(config, sites_text)
    records = _guest_records(config)
    if name in records and not force:
        print(f"tailisman: guest {name} already exists; pass --force to replace their password, which signs them out", file=sys.stderr)
        return 1
    passphrase = generate_passphrase()
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    try:
        write_private(directory / name, passphrase + "\n", overwrite=force)
    except FileExistsError:
        print(f"tailisman: {directory / name} already exists; pass --force to overwrite it", file=sys.stderr)
        return 1
    records[name] = Guest(name, sites, guest_digest(passphrase)).line()
    _write_guests(config, records)
    print(f"guest {name} may sign in to {', '.join(sites)}")
    print(f"wrote the passphrase to {directory / name}; hand it over, then delete the file")
    print(f"wrote the guest record to {config.guest_file}")
    return 0


def _revoke_guest(config: GateConfig, directory: Path, name: str) -> int:
    records = _guest_records(config)
    plaintext = directory / name if GUEST_NAME.fullmatch(name) else None
    if name not in records and not (plaintext and plaintext.exists()):
        known = ", ".join(sorted(records)) or "none"
        print(f"tailisman: no guest named {name!r} (guests: {known})", file=sys.stderr)
        return 1
    if name in records:
        del records[name]
        _write_guests(config, records)
        print(f"revoked guest {name}; their sessions have ended")
    if plaintext is not None and plaintext.exists():
        plaintext.unlink()
        print(f"deleted {plaintext}")
    return 0


def _list_guests(config: GateConfig) -> int:
    guests = parse_guests(_read_guest_file(config), config.guest_file).by_name
    for guest in guests.values():
        print(f"{guest.name}: {', '.join(guest.sites)}")
    if not guests:
        print(f"no guests in {config.guest_file}")
    return 0


def _guest_sites(config: GateConfig, text: str | None) -> tuple[str, ...]:
    """A guest is only ever given the sites named here; there is no default of every site."""
    configured = ", ".join(config.sites)
    if not text or not text.strip():
        raise ConfigError(f"--add needs --sites HOST[,HOST...]; this gate's sites are {configured}")
    sites = []
    for host in text.split(","):
        key = site_key(host)
        if key not in config.sites:
            raise ConfigError(f"--sites {host.strip()!r} is not a [[sites]] host of this gate; its sites are {configured}")
        if key not in sites:
            sites.append(key)
    return tuple(sites)


def _read_guest_file(config: GateConfig) -> str:
    try:
        return config.guest_file.read_text()
    except FileNotFoundError:
        return ""


def _guest_records(config: GateConfig) -> dict[str, str]:
    """Each record line by guest name, malformed lines kept under a key no name can take, so a rewrite never drops them."""
    records: dict[str, str] = {}
    for number, line in enumerate(_read_guest_file(config).splitlines()):
        guest = parse_guest_line(line)
        records[guest.name if guest and guest.name not in records else f" {number}"] = line
    return records


def _write_guests(config: GateConfig, records: dict[str, str]) -> None:
    write_private(config.guest_file, "".join(line + "\n" for line in records.values()), overwrite=True)


def _bearer_hash(args: argparse.Namespace) -> int:
    """The token comes from stdin, never argv, so it stays out of shell history and the process list."""
    token = (getpass.getpass("Bearer token: ") if sys.stdin.isatty() else sys.stdin.readline()).strip()
    if not token:
        print("tailisman: no token on stdin; nothing printed", file=sys.stderr)
        return 1
    print(bearer_digest(token.removeprefix("Bearer ").strip()))
    return 0


def _status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    bases = _base_urls(args.base_url_for, config)
    credentials = Credentials(config.session_secret, config.password_file, config.guest_file)
    tailnet_problems = _tailnet_problems(config.tailnet) if config.tailnet else []
    failed = bool(tailnet_problems)
    if config.tailnet is None:
        print("tailnet: off, password paths only")
    else:
        print(f"tailnet: listener {config.tailnet.listen.serve_target()}, origin {config.tailnet.origin}: {'; '.join(tailnet_problems) or 'ok, served, Funnel off'}")
    for site in config.sites.values():
        problems = _probe(site, bases.get(site.host, f"https://{site.host}")) + _probe_upstream(site)
        failed = failed or bool(problems)
        tailnet = "on" if config.tailnet and site.tailnet else "off"
        rules = ", ".join(str(rule) for rule in site.open) or "none"
        guests = credentials.guest_count(site.host)
        mode = f"upstream {site.upstream}" if site.upstream else "forward_auth"
        print(f"{site.host}: {mode}, scope {site.scope}, tailnet {tailnet}, guests {guests}, bearers {len(site.bearers)}, open {rules}: {'; '.join(problems) or 'ok'}")
    return 1 if failed else 0


def _tailnet_problems(tailnet: Tailnet) -> list[str]:
    """What `tailisman check` asks of an issuer: the listener answers, serve fronts it under serve_host, and Funnel is off."""
    listen = tailnet.listen
    try:
        if isinstance(listen, UnixListen):
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(3)
                probe.connect(listen.path)
        else:
            socket.create_connection((listen.host, listen.port), timeout=3).close()
    except OSError as exc:
        return [f"the tailnet listener is not accepting connections: {exc}"]
    try:
        binary = resolve_tailscale_bin(tailnet.checks.tailscale_bin)
        result = subprocess.run([binary, "serve", "status", "--json"], capture_output=True, text=True, check=False, timeout=10)
        serve = json.loads(result.stdout or "{}")
    except (ConfigError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return [f"could not read `tailscale serve status --json`: {exc}"]
    hosts = serve_hosts_for(serve, listen)
    if not hosts:
        return [f"no serve handler proxies to it; run `tailscale serve --bg --https={_port(tailnet.origin)} {listen.serve_target()}`"]
    if not any(host_name(h) == tailnet.checks.serve_host for h in hosts):
        return [f"serve fronts it as {', '.join(hosts)}, but serve_host is {tailnet.checks.serve_host}"]
    funnel = [h for h in hosts if (serve.get("AllowFunnel") or {}).get(h)]
    if funnel:
        return [f"Funnel is ON for {', '.join(funnel)}; the tailnet listener must only be reachable on the tailnet (`tailscale funnel reset`)"]
    return []


def _base_urls(pairs: list[str], config: GateConfig) -> dict[str, str]:
    bases = {}
    for pair in pairs:
        host, sep, url = pair.partition("=")
        key = site_key(host)
        if not sep or key not in config.sites or urlsplit(url).scheme not in ("http", "https"):
            raise ConfigError(f"--base-url-for {pair!r} must be HOST=http(s)://ADDRESS for a configured site")
        bases[key] = url.rstrip("/")
    return bases


def _probe(site: Site, base: str) -> list[str]:
    problems = []
    try:
        status, location, _ = _get(base, "/", site.host)
        if not (status == 302 and location.startswith(LOGIN_PATH)) and status != 401:
            problems.append(f"anonymous GET / answered {status}" + (f" to {location}" if location else ""))
        status, _, body = _get(base, "/.tailisman/healthz", site.host)
        if status != 200 or body.strip() != b"ok":
            problems.append(f"GET /.tailisman/healthz answered {status} {body[:40]!r}")
    except (OSError, http.client.HTTPException) as exc:
        problems.append(f"could not reach {base}: {exc}")
    return problems


def _probe_upstream(site: Site) -> list[str]:
    if site.upstream is None:
        return []
    try:
        socket.create_connection((site.upstream.host, site.upstream.port), timeout=3).close()
    except OSError as exc:
        return [f"upstream {site.upstream} is not accepting connections: {exc}"]
    return []


def _get(base: str, path: str, host: str) -> tuple[int, str, bytes]:
    url = urlsplit(base)
    connection = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = connection(url.netloc, timeout=10)
    try:
        conn.request("GET", path, headers={"Host": host, "Accept": "text/html"})
        response = conn.getresponse()
        return response.status, response.getheader("Location") or "", response.read()
    finally:
        conn.close()
