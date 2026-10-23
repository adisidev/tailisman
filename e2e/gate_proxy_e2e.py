"""End to end for proxy mode: the gate in front of a real standard-library app, with no Caddy, as behind a Cloudflare Tunnel.

    uv run python e2e/gate_proxy_e2e.py [--keep]

The client talks plain HTTP to the gate with the site's Host header, which is what cloudflared does. Prints one line per
check and exits 1 on any failure.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

from gate_e2e import ROOT, Checks, Reply, free_port, wait_for_port

from tailisman.gate.decision import bearer_digest
from tailisman.gate.proxy import CONNECT_TIMEOUT

APP = "app.example.com"
OTHER = "other.example.com"
DOWN = "down.example.com"
CADDY_SITE = "caddy.example.com"
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC11B76"
VIDEO = bytes((i * 7919) % 251 for i in range(5_000_000))
UPLOAD = 40 * 1024 * 1024
FIRST = 1024 * 1024
LONG_POLL = CONNECT_TIMEOUT + 2
BEARER = "e2e-machine-caller-token"


class State:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.release = threading.Event()
        self.received_first = threading.Event()


STATE = State()


def ws_frame(payload: bytes, opcode: int = 1, mask: bool = False) -> bytes:
    size = len(payload)
    bit = 0x80 if mask else 0
    head = bytes([0x80 | opcode]) + (bytes([bit | size]) if size < 126 else bytes([bit | 126]) + size.to_bytes(2, "big") if size < 65536 else bytes([bit | 127]) + size.to_bytes(8, "big"))
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_read(stream) -> tuple[int, bytes]:
    first, second = stream.read(2)
    size = second & 0x7F
    if size == 126:
        size = int.from_bytes(stream.read(2), "big")
    elif size == 127:
        size = int.from_bytes(stream.read(8), "big")
    key = stream.read(4) if second & 0x80 else None
    data = stream.read(size)
    return first & 0x0F, bytes(b ^ key[i % 4] for i, b in enumerate(data)) if key else data


class App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes = b"", headers: tuple = (), length: bool = True) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        if length:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _route(self) -> None:
        STATE.paths.append(self.path)
        path = self.path.split("?")[0]
        handler = {
            "/sse": self._sse,
            "/unknown-length": self._unknown_length,
            "/long-poll": self._long_poll,
            "/upload": self._upload,
            "/video": self._video,
            "/no-content": lambda: self._send(204, length=False),
            "/etag": self._etag,
            "/cache-public": lambda: self._send(200, b"cached", (("Cache-Control", "public, max-age=60"),)),
            "/cookies": lambda: self._send(200, b"two", (("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/"))),
            "/ws": self._websocket,
            "/public/gone": lambda: self._send(404, b"gone"),
        }.get(path, self._echo)
        handler()

    do_GET = do_HEAD = do_POST = do_PUT = do_PROPFIND = _route

    def _echo(self) -> None:
        seen = {name.lower(): self.headers.get_all(name) for name in set(self.headers.keys())}
        self._send(200, json.dumps({"method": self.command, "path": self.path, "headers": seen}).encode(), (("Content-Type", "application/json"),))

    def _sse(self) -> None:
        self._send(200, headers=(("Content-Type", "text/event-stream"), ("Transfer-Encoding", "chunked")), length=False)
        for event in (b"data: first\n\n", b"data: second\n\n"):
            self.wfile.write(b"%x\r\n%s\r\n" % (len(event), event))
            STATE.release.wait(10)
        self.wfile.write(b"0\r\n\r\n")

    def _unknown_length(self) -> None:
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"part one;")
        STATE.release.wait(10)
        self.wfile.write(b"part two")

    def _long_poll(self) -> None:
        time.sleep(LONG_POLL)
        self._send(200, b"done")

    def _upload(self) -> None:
        digest, total = hashlib.sha256(), 0

        def take(piece: bytes) -> None:
            nonlocal total
            digest.update(piece)
            total += len(piece)
            if total >= FIRST:
                STATE.received_first.set()

        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            while size := int(self.rfile.readline().split(b";")[0], 16):
                while size:
                    piece = self.rfile.read(min(size, 65536))
                    take(piece)
                    size -= len(piece)
                self.rfile.readline()
            self.rfile.readline()
        else:
            remaining = int(self.headers["Content-Length"])
            while remaining:
                piece = self.rfile.read(min(remaining, 65536))
                take(piece)
                remaining -= len(piece)
        self._send(200, json.dumps({"bytes": total, "sha256": digest.hexdigest(), "length": self.headers.get("Content-Length"), "te": self.headers.get("Transfer-Encoding")}).encode())

    def _video(self) -> None:
        match = re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers.get("Range") or "")
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            self._send(206, VIDEO[start : end + 1], (("Content-Type", "video/mp4"), ("Content-Range", f"bytes {start}-{end}/{len(VIDEO)}"), ("Accept-Ranges", "bytes")))
        else:
            self._send(200, VIDEO, (("Content-Type", "video/mp4"), ("Accept-Ranges", "bytes")))

    def _etag(self) -> None:
        if self.headers.get("If-None-Match") == '"v1"':
            self._send(304, headers=(("ETag", '"v1"'),), length=False)
        else:
            self._send(200, b"fresh", (("ETag", '"v1"'),))

    def _websocket(self) -> None:
        accept = base64.b64encode(hashlib.sha1(self.headers["Sec-WebSocket-Key"].encode() + WS_GUID).digest()).decode()
        self.send_response_only(101)
        for name, value in (("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", accept)):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(ws_frame(b"welcome"))
        self.close_connection = True
        while True:
            opcode, payload = ws_read(self.rfile)
            if opcode == 8:
                self.wfile.write(ws_frame(payload, 8))
                return
            self.wfile.write(ws_frame(payload))

    def log_message(self, format: str, *args) -> None:
        pass


class Stack:
    def __init__(self, keep: bool) -> None:
        self.keep = keep
        self.dir = Path(tempfile.mkdtemp(prefix="tailisman-proxy-e2e-"))
        self.ports = {name: free_port() for name in ("gate", "app", "closed")}
        self.env = os.environ | {"PYTHONPATH": str(ROOT / "src")}
        self.process: subprocess.Popen | None = None

    def tailisman(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "tailisman.cli", *args], env=self.env, capture_output=True, text=True, check=False)

    def start(self) -> Stack:
        d, p = self.dir, self.ports
        self.tailisman("keygen", str(d / "gate-secret"))
        up = f"http://127.0.0.1:{p['app']}"
        (d / "gate.toml").write_text(
            f'listen = "127.0.0.1:{p["gate"]}"\nsession_secret_file = "gate-secret"\npassword_file = "gate-password"\n\n'
            f'[[sites]]\nhost = "{APP}"\ncookie_domain = "example.com"\nupstream = "{up}"\nopen = ["/public/*"]\nbearers = ["{bearer_digest(BEARER)}"]\n\n'
            f'[[sites]]\nhost = "{OTHER}"\ncookie_domain = "example.com"\nupstream = "{up}/"\n\n'
            f'[[sites]]\nhost = "{DOWN}"\nupstream = "http://127.0.0.1:{p["closed"]}"\n\n'
            f'[[sites]]\nhost = "{CADDY_SITE}"\n'
        )
        self.tailisman("passwd", "--config", str(d / "gate.toml"), "--generate", "--out", str(d / "passphrase"))
        app = http.server.ThreadingHTTPServer(("127.0.0.1", p["app"]), App)
        app.daemon_threads = True
        threading.Thread(target=app.serve_forever, daemon=True).start()
        self.log = open(d / "gate.log", "w")
        self.process = subprocess.Popen([sys.executable, "-m", "tailisman.cli", "gate", "run", "--config", str(d / "gate.toml")], env=self.env, stdout=self.log, stderr=subprocess.STDOUT, cwd=d)
        wait_for_port(p["gate"], self.process, "gate")
        return self

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=5)
        if not self.keep:
            shutil.rmtree(self.dir)


def run(stack: Stack) -> int:
    port, d = stack.ports["gate"], stack.dir
    c = Checks()
    html = {"Accept": "text/html"}

    def connect(timeout: float = 15) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)

    def send(method: str, path: str, host: str = APP, headers: dict | None = None, body: bytes | None = None, conn: http.client.HTTPConnection | None = None) -> Reply:
        own = conn is None
        conn = conn or connect()
        try:
            conn.request(method, path, body=body, headers={"Host": host} | (headers or {}))
            return Reply(conn.getresponse())
        finally:
            if own:
                conn.close()

    def cookie(value: str, extra: str = "") -> dict:
        return {"Cookie": f"tailisman_gate={value}" + extra}

    def sign_in(password: str, host: str = APP, ip: str = "198.51.100.1") -> str | None:
        csrf = send("GET", "/.tailisman/login", host, html).cookie("tailisman_csrf")
        form = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": f"tailisman_csrf={csrf}", "CF-Connecting-IP": ip}
        return send("POST", "/.tailisman/login", host, form, urlencode({"csrf": csrf, "password": password, "next": "/"}).encode()).cookie("tailisman_gate")

    poll: dict = {}

    def long_poll() -> None:
        started = time.monotonic()
        reply = send("GET", "/long-poll", headers=cookie(owner), conn=connect(timeout=LONG_POLL + 15))
        poll.update(status=reply.status, body=reply.body, seconds=time.monotonic() - started)

    r = send("GET", "/notes", headers=html)
    c.check("anonymous navigation on a proxy site gets 302 to the login page", r.status == 302 and r.header("Location") == "/.tailisman/login?next=%2Fnotes", (r.status, r.header("Location")))
    r = send("GET", "/data", headers={"Accept": "application/json", "X-Forwarded-Uri": "/public/x", "X-Forwarded-Method": "GET"})
    c.check("anonymous API call gets 401 JSON, and X-Forwarded-Uri from the client does not open a path", r.status == 401 and r.json() == {"error": "sign_in_required"}, (r.status, r.body))
    c.check("refused requests never reached the app", STATE.paths == [], STATE.paths)
    r = send("GET", "/", CADDY_SITE, html)
    c.check("a forward_auth site on the same listener gets 404 outside /.tailisman/", r.status == 404, r.status)
    r = send("GET", "/.tailisman/verify", CADDY_SITE, {"X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/x", "Accept": "text/html"})
    c.check("the same listener still answers forward_auth's verify for it", r.status == 302, r.status)

    r = send("GET", "/feed.xml", headers={"Authorization": f"Bearer {BEARER}", "X-Tailisman-Session": "password"})
    seen = r.json()["headers"] if r.status == 200 else {}
    c.check("a listed bearer on a non-open path reaches the app with no cookie, Authorization intact, as session bearer", (seen.get("authorization"), seen.get("x-tailisman-session")) == ([f"Bearer {BEARER}"], ["bearer"]), (r.status, seen.get("authorization"), seen.get("x-tailisman-session")))
    r = send("GET", "/feed.xml", headers={"Authorization": f"Bearer {BEARER}-wrong", "Accept": "text/html"})
    c.check("an unlisted bearer falls through to the sign-in redirect", r.status == 302, r.status)
    STATE.paths.clear()

    owner = sign_in((d / "passphrase").read_text().strip())
    c.check("the owner signs in on the proxy site", owner is not None)
    poller = threading.Thread(target=long_poll, daemon=True)
    poller.start()

    r = send("GET", "/echo?q=1", headers=cookie(owner, "; theme=dark; tailisman_csrf=" + "A" * 32) | {"X-Tailisman-Session": "forged", "X-Tailisman-User": "forged", "X_Tailisman_Session": "forged", "X-Forwarded-For": "203.0.113.5"})
    seen = r.json()["headers"] if r.status == 200 else {}
    c.check("the app sees the request with the gate's cookies removed and the others kept", r.status == 200 and r.json()["path"] == "/echo?q=1" and seen.get("cookie") == ["theme=dark"], seen.get("cookie"))
    c.check("the app sees X-Tailisman-Session password, no client-sent X-Tailisman-User and no underscore look-alike", seen.get("x-tailisman-session") == ["password"] and "x-tailisman-user" not in seen and not any("_" in name for name in seen), (seen.get("x-tailisman-session"), seen.get("x-tailisman-user"), sorted(seen)))
    c.check("Host is kept and X-Forwarded-For/Proto/Host are set", seen.get("host") == [APP] and seen.get("x-forwarded-for") == ["203.0.113.5, 127.0.0.1"] and seen.get("x-forwarded-proto") == ["https"] and seen.get("x-forwarded-host") == [APP], {k: seen.get(k) for k in ("host", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host")})
    c.check("a gated answer with no Cache-Control is marked private", r.header("Cache-Control") == "private", r.header("Cache-Control"))
    r = send("GET", "/echo", headers=cookie(owner) | {"X-Forwarded-Proto": "http"})
    c.check("an X-Forwarded-Proto from the tunnel is kept", r.json()["headers"].get("x-forwarded-proto") == ["http"], r.json()["headers"].get("x-forwarded-proto"))
    r = send("PROPFIND", "/dav/", headers=cookie(owner) | {"Depth": "1"})
    c.check("a method beyond the usual ones (PROPFIND) reaches the app", r.status == 200 and r.json()["method"] == "PROPFIND", r.status)
    r = send("GET", "/cache-public", headers=cookie(owner))
    c.check("an app's public Cache-Control becomes private", r.header("Cache-Control") == "private, max-age=60", r.header("Cache-Control"))
    r = send("GET", "/cookies", headers=cookie(owner))
    c.check("two Set-Cookie lines from the app stay two lines", sorted(r.cookies()) == ["a", "b"], [v for k, v in r.headers if k.lower() == "set-cookie"])

    r = send("GET", "/public/x", headers={"X-Tailisman-Session": "forged"})
    c.check("an open path reaches the app with no session and no client-sent X-Tailisman-Session", r.status == 200 and "x-tailisman-session" not in r.json()["headers"], r.body[:120])
    before = list(STATE.paths)
    statuses = {path: send("GET", path, headers=html).status for path in ("/public/../secret", "/public/%2e%2e/secret", "/public//x", "/public/x;y", "/public/x%2fy")}
    c.check("open-rule paths with .., an encoded ., //, ; or an encoded / still need a session", set(statuses.values()) == {302} and STATE.paths == before, statuses)

    conn = connect(timeout=5)
    conn.request("GET", "/sse", headers={"Host": APP} | cookie(owner))
    response = conn.getresponse()
    first = response.read1(1024)
    c.check("the first server-sent event arrives while the app still holds the response open", first == b"data: first\n\n" and not STATE.release.is_set() and response.getheader("Transfer-Encoding") == "chunked", (first, response.getheader("Transfer-Encoding")))
    STATE.release.set()
    rest = response.read()
    c.check("the rest of the event stream follows once the app sends it", rest == b"data: second\n\n", rest)
    conn.close()
    STATE.release.clear()
    conn = connect(timeout=5)
    conn.request("GET", "/unknown-length", headers={"Host": APP} | cookie(owner))
    response = conn.getresponse()
    first = response.read1(1024)
    held = not STATE.release.is_set()
    STATE.release.set()
    c.check("an answer of unknown length is relayed chunked as it arrives", held and first == b"part one;" and response.read() == b"part two" and response.getheader("Transfer-Encoding") == "chunked", (first, response.getheader("Transfer-Encoding")))
    conn.close()

    for framing in ("Content-Length", "chunked"):
        STATE.received_first.clear()
        sock = socket.create_connection(("127.0.0.1", port), timeout=30)
        payload = hashlib.sha256(framing.encode()).digest() * (UPLOAD // 32)
        head = f"POST /upload HTTP/1.1\r\nHost: {APP}\r\nCookie: tailisman_gate={owner}\r\n" + (f"Content-Length: {UPLOAD}\r\n" if framing == "Content-Length" else "Transfer-Encoding: chunked\r\n") + "\r\n"

        def framed(piece: bytes) -> bytes:
            return piece if framing == "Content-Length" else b"%x\r\n%s\r\n" % (len(piece), piece)

        sock.sendall(head.encode() + framed(payload[:FIRST]))
        streamed = STATE.received_first.wait(10)
        for offset in range(FIRST, UPLOAD, 4 * FIRST):
            sock.sendall(framed(payload[offset : offset + 4 * FIRST]))
        if framing == "chunked":
            sock.sendall(b"0\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        answer = json.loads(response.read())
        sock.close()
        c.check(f"a {UPLOAD // 1024 // 1024} MB {framing} upload streams to the app (its first MB arrives before the client sends the rest)", streamed and answer["bytes"] == UPLOAD and answer["sha256"] == hashlib.sha256(payload).hexdigest(), {k: answer[k] for k in ("bytes", "length", "te")} | {"first MB seen before the rest was sent": streamed})
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.sendall(f"POST /upload HTTP/1.1\r\nHost: {APP}\r\nContent-Length: {UPLOAD}\r\n\r\n".encode())
    response = http.client.HTTPResponse(sock)
    response.begin()
    c.check("an anonymous upload is refused with 401 before its body is read, and the connection closes", response.status == 401 and response.getheader("Connection") == "close", (response.status, response.getheader("Connection")))
    sock.close()

    r = send("GET", "/video", headers=cookie(owner) | {"Range": "bytes=1000-1999"})
    c.check("a Range request gets 206 with Content-Range passed through", r.status == 206 and r.header("Content-Range") == f"bytes 1000-1999/{len(VIDEO)}" and r.body == VIDEO[1000:2000], (r.status, r.header("Content-Range"), len(r.body)))
    r = send("GET", "/video", headers=cookie(owner))
    c.check("a 5 MB answer arrives whole with its Content-Length", r.status == 200 and r.header("Content-Length") == str(len(VIDEO)) and r.body == VIDEO, (r.status, r.header("Content-Length")))

    conn = connect()
    requests = {
        "gate login page": ("GET", "/.tailisman/login", html),
        "HEAD /video": ("HEAD", "/video", cookie(owner)),
        "204": ("GET", "/no-content", cookie(owner)),
        "304": ("GET", "/etag", cookie(owner) | {"If-None-Match": '"v1"'}),
        "200 echo": ("GET", "/echo", cookie(owner)),
        "chunked SSE": ("GET", "/sse", cookie(owner)),
        "401": ("GET", "/x", {"Accept": "application/json"}),
    }
    replies, ports = {}, set()
    for name, (method, path, headers) in requests.items():
        replies[name] = send(method, path, headers=headers, conn=conn)
        ports.add(conn.sock.getsockname()[1] if conn.sock else None)
    summary = {name: (reply.status, reply.header("Content-Length"), len(reply.body)) for name, reply in replies.items()}
    c.check("the gate's own page sends Content-Length over HTTP/1.1", replies["gate login page"].header("Content-Length") == str(len(replies["gate login page"].body)), summary["gate login page"])
    c.check("HEAD keeps the app's Content-Length and sends no body; 204 and 304 have no body", summary["HEAD /video"] == (200, str(len(VIDEO)), 0) and summary["204"][0::2] == (204, 0) and summary["304"][0::2] == (304, 0), summary)
    c.check(f"{len(requests)} requests of every kind share one keep-alive connection", len(ports) == 1 and None not in ports, ports)
    conn.close()

    def websocket(extra: str) -> tuple[int, str, socket.socket, object]:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(f"GET /ws HTTP/1.1\r\nHost: {APP}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n".encode())
        stream = sock.makefile("rb")
        status = int(stream.readline().split()[1])
        headers = {}
        while (line := stream.readline()) not in (b"\r\n", b""):
            name, _, value = line.decode().partition(":")
            headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
        return status, headers.get("sec-websocket-accept") == expected, sock, stream

    status, _, sock, _ = websocket("")
    c.check("an anonymous websocket upgrade is refused with 401", status == 401, status)
    sock.close()
    status, accepted, sock, stream = websocket(f"Cookie: tailisman_gate={owner}\r\n")
    welcome = ws_read(stream)
    big = os.urandom(100_000)
    sock.sendall(ws_frame(b"hello", mask=True) + ws_frame(big, opcode=2, mask=True))
    echoes = [ws_read(stream), ws_read(stream)]
    sock.sendall(ws_frame(b"", opcode=8, mask=True))
    closing = ws_read(stream)
    sock.close()
    c.check("a signed-in websocket gets 101, the app's first frame, both echoes (5 B and 100 kB) and the close", status == 101 and accepted and welcome == (1, b"welcome") and echoes == [(1, b"hello"), (1, big)] and closing[0] == 8, (status, accepted, welcome, [(op, len(p)) for op, p in echoes], closing[0]))

    def raw(data: bytes) -> tuple[bytes, bool]:
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock.sendall(data)
        answer, closed = b"", False
        try:
            while piece := sock.recv(65536):
                answer += piece
            closed = True
        except TimeoutError:
            pass
        sock.close()
        return answer, closed

    STATE.paths.clear()
    upgrade = f"Host: {APP}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\nSec-WebSocket-Version: 13\r\n"
    answer, closed = raw(f"GET /public/gone HTTP/1.1\r\n{upgrade}\r\nGET /secret HTTP/1.1\r\nHost: {APP}\r\nX-Tailisman-Session: password\r\n\r\n".encode())
    c.check("an upgrade on an open path the app answers with a keep-alive 404 is relayed and closed, and a request pipelined behind it never reaches the app", answer.startswith(b"HTTP/1.1 404") and answer.count(b"HTTP/1.1 ") == 1 and closed and STATE.paths == ["/public/gone"], (answer[:200], closed, STATE.paths))
    STATE.paths.clear()
    answer, closed = raw(f"GET /public/x HTTP/1.1\r\n{upgrade}Content-Length: 5\r\n\r\nhello".encode())
    c.check("an upgrade request with a body is refused with 400 and never reaches the app", answer.startswith(b"HTTP/1.1 400") and closed and STATE.paths == [], (answer[:80], closed, STATE.paths))

    added = stack.tailisman("passwd", "--config", str(d / "gate.toml"), "--add", "visitor", "--sites", APP)
    guest = sign_in((d / "guests" / "visitor").read_text().strip(), ip="198.51.100.2")
    r = send("GET", "/echo", headers=cookie(guest) | {"X-Tailisman-User": "owner"})
    c.check("a guest's request carries X-Tailisman-Session guest and X-Tailisman-User visitor", added.returncode == 0 and r.status == 200 and (r.json()["headers"].get("x-tailisman-session"), r.json()["headers"].get("x-tailisman-user")) == (["guest"], ["visitor"]), r.body[:200])
    r = send("GET", "/", OTHER, html | cookie(guest))
    c.check("the guest's example.com cookie is refused on other.example.com", r.status == 302, r.status)
    c.check("the owner's example.com cookie opens other.example.com", send("GET", "/echo", OTHER, cookie(owner)).status == 200)

    first, second = send("GET", "/", DOWN, html | cookie(owner)), send("GET", "/x", DOWN, html | cookie(owner))
    c.check("a site whose app is down answers 502 with a short text body", (first.status, second.status) == (502, 502) and first.body == b"the app behind this gate is not answering\n", (first.status, first.body))

    poller.join(LONG_POLL + 20)
    c.check(f"a long poll that waits {LONG_POLL} s (past the {CONNECT_TIMEOUT} s connect timeout) gets its answer", poll.get("status") == 200 and poll.get("body") == b"done" and poll.get("seconds", 0) >= LONG_POLL, {k: round(v, 1) if isinstance(v, float) else v for k, v in poll.items()})

    bases = [arg for host in (APP, OTHER, DOWN, CADDY_SITE) for arg in ("--base-url-for", f"{host}=http://127.0.0.1:{port}")]
    status = stack.tailisman("gate", "status", "--config", str(d / "gate.toml"), *bases)
    tailnet_line, *lines = status.stdout.strip().splitlines()
    c.check("`gate status` prints each site's upstream or forward_auth, passes the live proxy sites and flags the dead one", status.returncode == 1 and lines[0].startswith(f"{APP}: upstream http://127.0.0.1:") and lines[0].endswith(": ok") and lines[1].endswith(": ok") and "is not accepting connections" in lines[2] and lines[3].startswith(f"{CADDY_SITE}: forward_auth") and tailnet_line == "tailnet: off, password paths only", " | ".join([tailnet_line, *lines]))

    log = (d / "gate.log").read_text()
    c.check("the dead app is logged once for two requests, without secrets", log.count("is not answering") == 1 and owner not in log and (d / "passphrase").read_text().strip() not in log, [line for line in log.splitlines() if "upstream" in line])
    print("all checks passed" if not c.failed else f"{c.failed} check(s) failed")
    return 1 if c.failed else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory and the gate's log")
    args = parser.parse_args()
    stack = Stack(args.keep)
    try:
        print(f"gate on 127.0.0.1:{stack.ports['gate']}, app on 127.0.0.1:{stack.ports['app']}, no Caddy")
        stack.start()
        return run(stack)
    finally:
        stack.stop()


if __name__ == "__main__":
    sys.exit(main())
