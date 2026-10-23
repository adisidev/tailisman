"""The gate's commands: gate run, gate status, passwd."""

from __future__ import annotations

import argparse
import getpass
import http.client
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from ..issuer.config import ConfigError
from .config import GateConfig, Site, load_config, site_key
from .decision import LOGIN_PATH
from .http import GateApp, make_server
from .password import generate_passphrase, hash_password, write_private

MIN_PASSWORD = 12


def add_commands(commands: argparse._SubParsersAction) -> dict[str, Callable[[argparse.Namespace], int]]:
    gate = commands.add_parser("gate", help="the password-or-tailnet gate in front of Caddy sites")
    gate_commands = gate.add_subparsers(dest="gate_command", required=True)
    run = gate_commands.add_parser("run", help="serve the gate on its loopback address, in the foreground")
    run.add_argument("--config", required=True)
    status = gate_commands.add_parser("status", help="list the gated sites and check each one refuses an anonymous visitor")
    status.add_argument("--config", required=True)
    status.add_argument("--base-url-for", action="append", default=[], metavar="HOST=URL", help="send HOST's checks to URL instead of https://HOST, with HOST as the Host header")
    passwd = commands.add_parser("passwd", help="set the gate's backup password; it takes effect without a restart and signs every session out")
    passwd.add_argument("--config", required=True)
    passwd.add_argument("--generate", action="store_true", help="make a passphrase instead of prompting, and write it to --out")
    passwd.add_argument("--out", help="where --generate writes the passphrase, mode 0600")
    passwd.add_argument("--force", action="store_true", help="let --generate overwrite an existing --out file")
    return {"gate": lambda args: {"run": _run, "status": _status}[args.gate_command](args), "passwd": _passwd}


def _run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    app = GateApp(config)
    server = make_server(app)
    password = "on" if app.password.current() else f"off (no valid hash in {config.password_file}; run `tailisman passwd`)"
    print(f"tailisman gate: listening on {config.listen.serve_target()} for {', '.join(config.sites)}; password {password}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _passwd(args: argparse.Namespace) -> int:
    config = load_config(args.config)
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


def _status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    bases = _base_urls(args.base_url_for, config)
    failed = False
    for site in config.sites.values():
        problems = _probe(site, bases.get(site.host, f"https://{site.host}"))
        failed = failed or bool(problems)
        tailnet = "on" if config.issuer and site.verifier else "off"
        rules = ", ".join(str(rule) for rule in site.open) or "none"
        print(f"{site.host}: scope {site.scope}, tailnet {tailnet}, open {rules}: {'; '.join(problems) or 'ok'}")
    return 1 if failed else 0


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
