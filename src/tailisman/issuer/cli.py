"""The issuer's commands: keygen, key, run, check."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from collections.abc import Callable

from .._token import derive_consumer_key, format_key, normalise_origin
from .config import ConfigError, IssuerConfig, TcpListen, UnixListen, host_name, load_config, resolve_tailscale_bin
from .http import IssuerApp, make_server
from .tailscale import cli_self_dns_name, cli_whois


def add_commands(commands: argparse._SubParsersAction) -> dict[str, Callable[[argparse.Namespace], int]]:
    keygen = commands.add_parser("keygen", help="write a new 32-byte secret, mode 0600 (the issuer's master secret or the gate's session secret)")
    keygen.add_argument("path")
    key = commands.add_parser("key", help="print the key a consumer origin uses to verify tokens")
    key.add_argument("--config", required=True)
    key.add_argument("--aud", required=True, help="a configured audience origin, e.g. https://heckle.example.com")
    run = commands.add_parser("run", help="serve the issuer on the configured loopback address or unix socket")
    run.add_argument("--config", required=True)
    check = commands.add_parser("check", help="check the config, the tailscale binary and that serve, not Funnel, fronts the issuer")
    check.add_argument("--config", required=True)
    return {"keygen": _keygen, "key": _key, "run": _run, "check": _check}


def _keygen(args: argparse.Namespace) -> int:
    try:
        fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"tailisman: {args.path} already exists; refusing to overwrite a secret", file=sys.stderr)
        return 1
    with os.fdopen(fd, "wb") as out:
        out.write(secrets.token_bytes(32))
    print(f"wrote a new secret to {args.path}")
    return 0


def _key(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    try:
        origin = normalise_origin(args.aud)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if origin not in config.audiences:
        raise ConfigError(f"{origin} is not a configured audience; add an [[audiences]] entry first")
    print(format_key(derive_consumer_key(config.master, origin)))
    return 0


def app_for(config: IssuerConfig) -> IssuerApp:
    binary = resolve_tailscale_bin(config.tailscale_bin)
    return IssuerApp(config, cli_whois(binary), config.serve_host or cli_self_dns_name(binary))


def _run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    app = app_for(config)
    server = make_server(app)
    target = config.listen.serve_target()
    print(f"tailisman: listening on {target} for {', '.join(config.audiences)}, answering only Host {app.serve_host}", file=sys.stderr)
    print(f"tailisman: front it with `tailscale serve --bg --https=8443 {target}` and never with Funnel", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if isinstance(config.listen, UnixListen):
            os.unlink(config.listen.path)
    return 0


def _check(args: argparse.Namespace) -> int:
    """Reads `tailscale serve status --json`: the hosts whose handlers proxy to our listener, and AllowFunnel for each."""
    config = load_config(args.config)
    binary = resolve_tailscale_bin(config.tailscale_bin)
    print(f"config: ok, {len(config.audiences)} audience(s), listen {config.listen.serve_target()}")
    print(f"tailscale: {binary}")
    human = subprocess.run([binary, "serve", "status"], capture_output=True, text=True, check=False)
    print(human.stdout.rstrip() or human.stderr.rstrip())
    status = subprocess.run([binary, "serve", "status", "--json"], capture_output=True, text=True, check=False)
    try:
        serve = json.loads(status.stdout or "{}")
    except ValueError:
        print("check: could not parse `tailscale serve status --json`", file=sys.stderr)
        return 1
    hosts = _hosts_proxying_to(serve, config)
    if not hosts:
        print(f"check: no serve handler proxies to {config.listen.serve_target()}; run `tailscale serve --bg --https=8443 {config.listen.serve_target()}`", file=sys.stderr)
        return 1
    serve_host = config.serve_host or cli_self_dns_name(binary)
    if not any(host_name(h) == serve_host for h in hosts):
        print(f"check: the issuer only answers Host {serve_host}, but serve fronts it as {', '.join(hosts)}; set serve_host to the name serve uses", file=sys.stderr)
        return 1
    funnel = [h for h in hosts if (serve.get("AllowFunnel") or {}).get(h)]
    if funnel:
        print(f"check: Funnel is ON for {', '.join(funnel)}; the issuer must only be reachable on the tailnet. Run `tailscale funnel reset` or turn Funnel off for that port.", file=sys.stderr)
        return 1
    print(f"check: served at {', '.join('https://' + h for h in hosts)}, Funnel off")
    return 0


def _hosts_proxying_to(serve: dict, config: IssuerConfig) -> list[str]:
    targets = {config.listen.serve_target()}
    if isinstance(config.listen, TcpListen) and config.listen.host == "127.0.0.1":
        targets.add(f"http://localhost:{config.listen.port}")
    hosts = []
    for host, web in (serve.get("Web") or {}).items():
        proxies = {str(h.get("Proxy", "")).rstrip("/") for h in (web.get("Handlers") or {}).values()}
        if proxies & targets:
            hosts.append(host)
    return hosts

