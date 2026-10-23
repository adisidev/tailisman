import http.client
import http.server
import socket
import threading
import time

import pytest
from conftest import free_port
from test_gate import SECRET
from test_tailnet_listener import gate_dir, served

from tailisman.gate.cli import make_servers
from tailisman.gate.config import load_config, parse_config
from tailisman.gate.http import GateApp, make_server
from tailisman.issuer import http as issuer_http

IDLE = 0.5
SLOW = 3 * IDLE


class Slow(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        time.sleep(SLOW)
        self.send_response(200)
        self.send_header("Content-Length", "4")
        self.end_headers()
        self.wfile.write(b"done")

    def do_POST(self) -> None:
        while size := int(self.rfile.readline(), 16):
            self.rfile.read(size + 2)
        while self.rfile.readline() not in (b"\r\n", b""):
            pass
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args) -> None:
        pass


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def closed_within(address, seconds: float, sock: socket.socket | None = None) -> float | None:
    """How long an idle connection took to be closed by the server, or None if it stayed open past `seconds`."""
    sock = sock or socket.create_connection(address)
    sock.settimeout(seconds)
    started = time.monotonic()
    try:
        data = sock.recv(1)
    except TimeoutError:
        return None
    finally:
        sock.close()
    return time.monotonic() - started if data == b"" else None


@pytest.fixture
def short_timeout(monkeypatch):
    monkeypatch.setattr(issuer_http, "HEADER_TIMEOUT", IDLE)


@pytest.fixture
def gate(tmp_path, short_timeout):
    app = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow))
    (tmp_path / "gate-secret").write_bytes(SECRET)
    raw = {"listen": f"127.0.0.1:{free_port()}", "session_secret_file": "gate-secret", "password_file": "p", "sites": [{"host": "app.example.com", "upstream": f"http://127.0.0.1:{app.server_port}", "open": ["/public/*"]}]}
    server = serve(make_server(GateApp(parse_config(raw, base=tmp_path))))
    yield server.server_address[:2]
    for running in (server, app):
        running.shutdown()
        running.server_close()


def test_the_public_listener_closes_a_connection_that_sends_nothing(gate):
    took = closed_within(gate, 10 * IDLE)
    assert took is not None and IDLE * 0.8 <= took < 5 * IDLE


def test_an_allowed_proxied_request_may_wait_past_the_timeout_and_the_idle_timeout_returns_after_it(gate):
    conn = http.client.HTTPConnection(*gate, timeout=10)
    conn.request("GET", "/public/slow", headers={"Host": "app.example.com"})
    response = conn.getresponse()
    assert (response.status, response.read()) == (200, b"done")
    took = closed_within(gate, 10 * IDLE, conn.sock)
    assert took is not None and took < 5 * IDLE


def test_the_tailnet_listener_closes_a_connection_that_sends_nothing(tmp_path, monkeypatch, short_timeout):
    port = free_port()
    servers = [serve(server) for server in make_servers(load_config(gate_dir(tmp_path, monkeypatch, port, served(port))))]
    try:
        took = closed_within(servers[1].server_address[:2], 10 * IDLE)
        assert took is not None and took < 5 * IDLE
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


@pytest.mark.parametrize("trailers,status", [(2, 200), (33, 502)])
def test_a_chunked_body_may_carry_a_few_trailer_lines_but_not_an_endless_stream(gate, trailers, status):
    sock = socket.create_connection(gate, timeout=10)
    lines = "".join(f"X-Sum-{n}: {n}\r\n" for n in range(trailers))
    sock.sendall(f"POST /public/upload HTTP/1.1\r\nHost: app.example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n{lines}\r\n".encode())
    response = http.client.HTTPResponse(sock)
    response.begin()
    sock.close()
    assert response.status == status
