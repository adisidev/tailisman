"""The issuer's HTTP surface. Stateless; every route is a pure function of the request, the config and whois."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import html
import http.server
import json
import os
import socket
import socketserver
import stat
import sys
import time
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .._token import normalise_origin
from .config import IssuerConfig, TcpListen, UnixListen
from .decision import HTTP_STATUS, Grant, Refusal, RefusalCode, ServeFacts, Whois, decide, lookup_peer, mint, serve_refusal

SUBMIT_SCRIPT = "document.forms[0].submit()"
SUBMIT_SCRIPT_HASH = base64.b64encode(hashlib.sha256(SUBMIT_SCRIPT.encode()).digest()).decode()
PAGE_CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"


@dataclasses.dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class IssuerApp:
    def __init__(self, config: IssuerConfig, whois: Whois, serve_host: str, clock: Callable[[], float] = time.time) -> None:
        self.config = config
        self.whois = whois
        self.serve_host = serve_host
        self.clock = clock

    def respond(self, method: str, target: str, headers: Message) -> tuple[Response, Refusal | Grant | None]:
        url = urlsplit(target)
        query = parse_qs(url.query)
        routes = {
            "/healthz": {"GET": lambda: (_text(200, "ok\n"), None)},
            "/v1/claim": {"GET": lambda: self._claim(headers, query), "OPTIONS": lambda: (self._preflight(headers), None)},
            "/v1/start": {"GET": lambda: self._start(headers, query)},
            "/": {"GET": lambda: (self._status_page(headers), None)},
        }
        methods = routes.get(url.path)
        if methods is None:
            return _text(404, "not found\n"), None
        if method not in methods:
            return _text(405, "method not allowed\n"), None
        return methods[method]()

    def _preflight(self, headers: Message) -> Response:
        origin = _origin_or_none(headers.get("Origin"))
        if origin not in self.config.audiences:
            return _json(403, {"error": RefusalCode.UNKNOWN_AUDIENCE})
        cors = _cors_headers(origin) + (("Access-Control-Allow-Methods", "GET"), ("Access-Control-Max-Age", "600"))
        return Response(204, cors, b"")

    def _claim(self, headers: Message, query: dict) -> tuple[Response, Refusal | Grant]:
        origin = _origin_or_none(headers.get("Origin"))
        outcome = decide(ServeFacts.from_headers(headers), origin, _automation(query), self.config, self.whois, self.serve_host)
        cors = _cors_headers(origin) if origin in self.config.audiences else ()
        if isinstance(outcome, Refusal):
            return _json(HTTP_STATUS[outcome.code], {"error": outcome.code}, cors), outcome
        return _json(200, {"token": mint(outcome, self.config, int(self.clock()))}, cors), outcome

    def _start(self, headers: Message, query: dict) -> tuple[Response, Refusal | Grant]:
        return_to = _single(query, "return_to")
        origin = _origin_of_url(return_to) if return_to else None
        outcome = decide(ServeFacts.from_headers(headers), origin, _automation(query), self.config, self.whois, self.serve_host)
        if isinstance(outcome, Refusal):
            back = origin if origin in self.config.audiences else None
            return _refusal_page(outcome, back), outcome
        token = mint(outcome, self.config, int(self.clock()))
        body = (
            "<!doctype html><meta charset=utf-8><title>Signing in</title>"
            f'<form method=post action="{html.escape(return_to)}">'
            f'<input type=hidden name=token value="{html.escape(token)}">'
            f"<p>Signing you in to {html.escape(origin)}.</p><button type=submit>Continue</button></form>"
            f"<script>{SUBMIT_SCRIPT}</script>"
        )
        csp = f"default-src 'none'; script-src 'sha256-{SUBMIT_SCRIPT_HASH}'; form-action {origin}; base-uri 'none'; frame-ancestors 'none'"
        return _html(200, body, csp), outcome

    def _status_page(self, headers: Message) -> Response:
        facts = ServeFacts.from_headers(headers)
        if refusal := serve_refusal(facts, self.serve_host):
            return _refusal_page(refusal, None)
        raw = self.whois(facts.peer_ip())
        peer = lookup_peer(facts, lambda _ip: raw)
        if peer is None:
            return _refusal_page(Refusal(RefusalCode.UNKNOWN_PEER), None)
        rows = [("Device", peer.node_name), ("MagicDNS name", peer.dns_name), ("Stable ID", peer.node_id), ("Login", peer.login), ("Tagged", ", ".join(peer.tags) or "no")]
        verdicts = {
            origin: decide(facts, origin, False, self.config, lambda _ip: raw, self.serve_host) for origin in self.config.audiences
        }
        parts = ["<!doctype html><meta charset=utf-8><title>tailisman</title><h1>This device</h1><table>"]
        parts += [f"<tr><th>{html.escape(k)}<td>{html.escape(v)}" for k, v in rows]
        parts.append("</table>")
        allowed = any(isinstance(v, Grant) for v in verdicts.values())
        if allowed:
            parts.append("<h2>Sites that would accept it</h2><ul>")
            for origin, verdict in verdicts.items():
                result = "accepts" if isinstance(verdict, Grant) else f"refuses: {verdict.code}"
                parts.append(f"<li>{html.escape(origin)}: {html.escape(result)}")
            parts.append("</ul>")
        if peer.tags:
            parts.append("<p>Tagged devices are always refused, because they have no user identity.</p>")
        elif not allowed or any(isinstance(v, Refusal) and v.code is RefusalCode.NOT_ON_ALLOWLIST for v in verdicts.values()):
            line = f"devices = [{json.dumps(peer.node_id)}]  # {peer.node_name}"
            parts.append(f"<p>To allow this device, add its stable ID to <code>devices</code> in issuer.toml:</p><pre>{html.escape(line)}</pre>")
        return _html(200, "".join(parts), PAGE_CSP)


def _automation(query: dict) -> bool:
    return _single(query, "a") == "1"


def _single(query: dict, name: str) -> str | None:
    values = query.get(name, [])
    return values[0] if len(values) == 1 else None


def _origin_or_none(text: str | None) -> str | None:
    try:
        return normalise_origin(text) if text else None
    except ValueError:
        return None


def _origin_of_url(url: str) -> str | None:
    parts = urlsplit(url)
    return _origin_or_none(f"{parts.scheme}://{parts.netloc}") if parts.scheme and parts.netloc else None


def _cors_headers(origin: str) -> tuple[tuple[str, str], ...]:
    return (
        ("Access-Control-Allow-Origin", origin),
        ("Vary", "Origin"),
        ("Access-Control-Allow-Private-Network", "true"),
    )


def _refusal_page(refusal: Refusal, back_to: str | None) -> Response:
    link = f'<p><a href="{html.escape(back_to)}">Back to {html.escape(back_to)}</a></p>' if back_to else ""
    body = f"<!doctype html><meta charset=utf-8><title>Refused</title><p>tailisman refused this device: <code>{html.escape(refusal.code)}</code></p>{link}"
    return _html(HTTP_STATUS[refusal.code], body, PAGE_CSP)


def _base_headers(content_type: str) -> tuple[tuple[str, str], ...]:
    return (("Content-Type", content_type), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"))


def _json(status: int, body: dict, extra: tuple[tuple[str, str], ...] = ()) -> Response:
    return Response(status, _base_headers("application/json") + extra, json.dumps(body).encode())


def _text(status: int, body: str) -> Response:
    return Response(status, _base_headers("text/plain; charset=utf-8"), body.encode())


def _html(status: int, body: str, csp: str) -> Response:
    headers = _base_headers("text/html; charset=utf-8") + (("Content-Security-Policy", csp), ("Referrer-Policy", "no-referrer"))
    return Response(status, headers, body.encode())


def handler_for(app: IssuerApp) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "tailisman"
        sys_version = ""

        def _dispatch(self) -> None:
            response, outcome = app.respond(self.command, self.path, self.headers)
            self.send_response(response.status)
            for name, value in response.headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            self.wfile.write(response.body)
            if isinstance(outcome, Refusal):
                print(f"tailisman: refused {outcome.code}" + (f" for {outcome.node}" if outcome.node else ""), file=sys.stderr)
            elif isinstance(outcome, Grant):
                print(f"tailisman: issued for {outcome.peer.node_name} to {outcome.audience.origin}", file=sys.stderr)

        do_GET = do_OPTIONS = do_POST = do_PUT = do_DELETE = _dispatch

        def log_message(self, format: str, *args) -> None:
            pass

    return Handler


class _ThreadingHTTPServerV6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


class _ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def make_server(app: IssuerApp) -> socketserver.BaseServer:
    listen = app.config.listen
    handler = handler_for(app)
    if isinstance(listen, TcpListen):
        server_class = _ThreadingHTTPServerV6 if ":" in listen.host else http.server.ThreadingHTTPServer
        return server_class((listen.host, listen.port), handler)
    assert isinstance(listen, UnixListen)
    path = Path(listen.path)
    if path.exists():
        if not stat.S_ISSOCK(path.stat().st_mode):
            raise SystemExit(f"tailisman: {path} exists and is not a socket")
        path.unlink()
    previous = os.umask(0o117)
    try:
        server = _ThreadingUnixHTTPServer(str(path), handler)
    finally:
        os.umask(previous)
    os.chmod(path, 0o660)
    return server
