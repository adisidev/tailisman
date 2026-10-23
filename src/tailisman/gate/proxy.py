"""Proxy mode: the gate forwards an allowed request to the site's app and streams the answer back.

For a tunnel (cloudflared) that terminates TLS but cannot ask the gate first. Bodies stream both ways without buffering:
uploads of any size, chunked and unknown-length answers, server-sent events, long polls with no read timeout, and
websockets, which are spliced byte for byte once the request has been allowed and the app has answered 101.
"""

from __future__ import annotations

import http.client
import http.server
import re
import socket
import threading
from collections.abc import Iterator
from email.message import Message

from .config import Upstream
from .decision import Allow
from .session import COOKIE, CSRF_COOKIE

SESSION_HEADER = "X-Tailisman-Session"
USER_HEADER = "X-Tailisman-User"
CONNECT_TIMEOUT = 10
CHUNK = 64 * 1024
Headers = tuple[tuple[str, str], ...]

_HOP_BY_HOP = frozenset({"connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"})
_SET_BY_GATE = frozenset({SESSION_HEADER.lower(), USER_HEADER.lower(), "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "expect", "content-length"})
_GATE_COOKIES = frozenset({COOKIE, CSRF_COOKIE})
_PUBLIC = re.compile(r"\bpublic\b", re.IGNORECASE)
_NO_BODY = frozenset({204, 304})


class BadRequest(Exception):
    pass


def identity_headers(allow: Allow) -> Headers:
    """What the app behind is told about the visitor. Client-sent copies never reach it: the proxy strips them, as Caddy's copy_headers does."""
    if allow.bearer:
        return ((SESSION_HEADER, "bearer"),)
    session = allow.session
    if session is None:
        return ()
    return ((SESSION_HEADER, session.method.value),) + (((USER_HEADER, session.guest),) if session.guest else ())


def is_websocket(headers: Message) -> bool:
    return (headers.get("Upgrade") or "").strip().lower() == "websocket" and "upgrade" in _tokens(headers.get_all("Connection") or [])


def body_length(headers: Message) -> int | str | None:
    """The request body's framing: a byte count, "chunked", or None for no body."""
    encodings = headers.get_all("Transfer-Encoding") or []
    if encodings:
        if _tokens(encodings)[-1:] != ["chunked"]:
            raise BadRequest("a Transfer-Encoding must end in chunked")
        return "chunked"
    lengths = {value.strip() for value in headers.get_all("Content-Length") or []}
    if not lengths:
        return None
    if len(lengths) != 1 or not next(iter(lengths)).isdigit():
        raise BadRequest("Content-Length must be one number")
    return int(lengths.pop()) or None


def upstream_headers(headers: Message, identity: Headers, peer: str, body: int | str | None, websocket: bool) -> list[tuple[str, str]]:
    """The client's headers minus hop-by-hop ones, the gate's cookies and any client-sent identity, plus the gate's own."""
    dropped = _HOP_BY_HOP | _SET_BY_GATE | set(_tokens(headers.get_all("Connection") or []))
    sent = []
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in dropped or lowered.startswith("proxy-"):
            continue
        if lowered == "cookie":
            value = "; ".join(part.strip() for part in value.split(";") if part.strip() and part.strip().partition("=")[0] not in _GATE_COOKIES)
            if not value:
                continue
        sent.append((name, value))
    forwarded = [part.strip() for value in headers.get_all("X-Forwarded-For") or [] for part in value.split(",") if part.strip()]
    sent += [
        ("X-Forwarded-For", ", ".join(forwarded + [peer])),
        ("X-Forwarded-Proto", (headers.get("X-Forwarded-Proto") or "").strip() or "https"),
        ("X-Forwarded-Host", headers.get("Host") or ""),
        *identity,
    ]
    if websocket:
        sent += [("Connection", "Upgrade"), ("Upgrade", "websocket")]
    elif body == "chunked":
        sent.append(("Transfer-Encoding", "chunked"))
    elif body is not None:
        sent.append(("Content-Length", str(body)))
    return sent


def client_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The app's headers minus hop-by-hop ones, with the cache rule the Caddy snippet applies: no Cache-Control becomes private, public becomes private."""
    dropped = _HOP_BY_HOP | set(_tokens(value for name, value in headers if name.lower() == "connection"))
    kept = [(name, value) for name, value in headers if name.lower() not in dropped and not name.lower().startswith("proxy-")]
    if not any(name.lower() == "cache-control" for name, _ in kept):
        return kept + [("Cache-Control", "private")]
    return [(name, _PUBLIC.sub("private", value) if name.lower() == "cache-control" else value) for name, value in kept]


def relay(handler: http.server.BaseHTTPRequestHandler, upstream: Upstream, identity: Headers) -> str | None:
    """Forwards the handler's request to the app and its answer back. Returns why the app could not be reached, or None."""
    try:
        body = body_length(handler.headers)
    except BadRequest as exc:
        handler.send_error(400, str(exc))
        return None
    websocket = is_websocket(handler.headers)
    if websocket and body is not None:
        handler.send_error(400, "a websocket upgrade has no body")
        return None
    headers = upstream_headers(handler.headers, identity, handler.client_address[0], body, websocket)
    try:
        sock = socket.create_connection((upstream.host, upstream.port), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        _bad_gateway(handler)
        return str(exc)
    sock.settimeout(None)
    if websocket:
        return _upgrade(handler, sock, headers)
    conn = http.client.HTTPConnection(upstream.host, upstream.port)
    conn.sock = sock
    try:
        conn.putrequest(handler.command, handler.path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers:
            conn.putheader(name, value)
        conn.endheaders()
        for piece in _request_body(handler, body):
            conn.send(piece)
        response = conn.getresponse()
    except (OSError, ValueError, http.client.HTTPException, BadRequest) as exc:
        conn.close()
        _bad_gateway(handler)
        return f"request failed: {exc}"
    try:
        _answer(handler, response)
    except (OSError, http.client.HTTPException):
        handler.close_connection = True
    finally:
        conn.close()
    return None


def _request_body(handler: http.server.BaseHTTPRequestHandler, body: int | str | None) -> Iterator[bytes]:
    if body == "chunked":
        for piece in _read_chunks(handler.rfile):
            yield b"%x\r\n%s\r\n" % (len(piece), piece)
        yield b"0\r\n\r\n"
    elif isinstance(body, int):
        remaining = body
        while remaining:
            piece = handler.rfile.read(min(remaining, CHUNK))
            if not piece:
                raise BadRequest("the client closed before sending its whole body")
            remaining -= len(piece)
            yield piece


def _read_chunks(rfile) -> Iterator[bytes]:
    while True:
        line = rfile.readline(1024)
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            raise BadRequest("malformed chunk size") from None
        if size == 0:
            while rfile.readline(8192) not in (b"\r\n", b"\n", b""):
                pass
            return
        while size:
            piece = rfile.read(min(size, CHUNK))
            if not piece:
                raise BadRequest("the client closed inside a chunk")
            size -= len(piece)
            yield piece
        rfile.readline(3)


def _answer(handler: http.server.BaseHTTPRequestHandler, response: http.client.HTTPResponse) -> None:
    """Relays the status, headers and body as they arrive. An answer of unknown length goes to the client chunked."""
    no_body = handler.command == "HEAD" or response.status in _NO_BODY or response.status < 200
    rechunk = not no_body and response.length is None and handler.request_version == "HTTP/1.1"
    handler.send_response_only(response.status, response.reason)
    for name, value in client_headers(response.getheaders()):
        if not (rechunk and name.lower() == "content-length"):
            handler.send_header(name, value)
    if rechunk:
        handler.send_header("Transfer-Encoding", "chunked")
    if handler.close_connection or (not rechunk and not no_body and response.length is None):
        handler.send_header("Connection", "close")
    handler.end_headers()
    if no_body:
        return
    while piece := response.read1(CHUNK):
        handler.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece) if rechunk else piece)
    if rechunk:
        handler.wfile.write(b"0\r\n\r\n")


def _upgrade(handler: http.server.BaseHTTPRequestHandler, sock: socket.socket, headers: list[tuple[str, str]]) -> str | None:
    """Sends the upgrade on and reads the app's answer. Only a 101 to websocket is spliced; any other answer is relayed and both connections close, since bytes the client pipelined behind the upgrade were never judged by the gate."""
    handler.close_connection = True
    head = f"{handler.command} {handler.path} HTTP/1.1\r\n" + "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n"
    try:
        sock.sendall(head.encode("latin-1"))
        response = http.client.HTTPResponse(sock, method=handler.command)
        response.begin()
    except (OSError, http.client.HTTPException) as exc:
        sock.close()
        _bad_gateway(handler)
        return f"upgrade failed: {exc}"
    try:
        if response.status != 101:
            _answer(handler, response)
        elif (response.getheader("Upgrade") or "").strip().lower() != "websocket":
            _bad_gateway(handler)
            return f"the app switched to {response.getheader('Upgrade')!r}, not websocket"
        else:
            handler.send_response_only(101, response.reason)
            for name, value in response.getheaders():
                handler.send_header(name, value)
            handler.end_headers()
            _splice(handler.connection, handler.rfile, sock, response.fp)
    except (OSError, http.client.HTTPException):
        pass
    finally:
        sock.close()
    return None


def _splice(client: socket.socket, client_in, upstream: socket.socket, upstream_in) -> None:
    """Copies bytes both ways, the app's already-buffered first frames included, until either side closes."""

    def pump(source, target: socket.socket) -> None:
        try:
            while data := source.read1(CHUNK):
                target.sendall(data)
        except OSError:
            pass
        finally:
            for end in (client, upstream):
                try:
                    end.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    other = threading.Thread(target=pump, args=(client_in, upstream), daemon=True)
    other.start()
    pump(upstream_in, client)
    other.join()


def _bad_gateway(handler: http.server.BaseHTTPRequestHandler) -> None:
    body = b"the app behind this gate is not answering\n"
    handler.close_connection = True
    try:
        handler.send_response_only(502)
        for name, value in (("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"), ("Connection", "close")):
            handler.send_header(name, value)
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)
    except OSError:
        pass


def _tokens(values) -> list[str]:
    return [token.strip().lower() for value in values for token in value.split(",") if token.strip()]
