import http.client
import json
import os
import shutil
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from tailisman.issuer.cli import app_for
from tailisman.issuer.config import load_config
from tailisman.issuer.http import make_server

ROOT = Path(__file__).resolve().parent.parent
FAKE_TAILSCALE = str(ROOT / "e2e" / "fake_tailscale.py")
SERVE_HOST = "issuer.example-tailnet.ts.net"
SERVE_HOST_HEADER = f"{SERVE_HOST}:8443"


def node(ip, stable_id, name, login, tags=None):
    return ip, {
        "Node": {"ID": 1, "StableID": stable_id, "Name": f"{name}.example-tailnet.ts.net.", "ComputedName": name, "Tags": tags, "Addresses": [f"{ip}/32"]},
        "UserProfile": {"ID": 2, "LoginName": login, "DisplayName": "Owner", "ProfilePicURL": ""},
        "CapMap": None,
    }


PEERS = dict([
    node("192.0.2.1", "nEXAMPLE1CNTRL", "laptop", "owner@example.com"),
    node("192.0.2.2", "nEXAMPLE2CNTRL", "phone", "owner@example.com"),
    node("192.0.2.3", "nEXAMPLE3CNTRL", "tablet", "owner@example.com"),
    node("192.0.2.4", "nEXAMPLE4CNTRL", "server", "tagged-devices", ["tag:server"]),
    node("192.0.2.5", "nEXAMPLE5CNTRL", "guest", "guest@example.com"),
    node("192.0.2.6", "nEXAMPLE6CNTRL", "desk", "owner@example.com"),
    node("192.0.2.7", "nEXAMPLE7CNTRL", "evil<script>x", "owner@example.com"),
])

CONFIG = """
secret_file = "secret"
listen = "{listen}"
tailscale_bin = "{tailscale_bin}"
devices = ["laptop", "nEXAMPLE2CNTRL", "guest.example-tailnet.ts.net.", "desk.example-tailnet.ts.net"]

[[audiences]]
origin = "https://heckle.example.com"

[[audiences]]
origin = "https://notes.example.com"
users = ["owner@example.com"]
refuse_automation = true

[[audiences]]
origin = "http://localhost:8080"
"""


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def write_issuer_dir(directory: Path, listen=None, serve_status=None, status=None, extra="") -> Path:
    listen = listen or f"127.0.0.1:{free_port()}"
    status = {"Self": {"DNSName": SERVE_HOST + "."}} if status is None else status
    (directory / "secret").write_bytes(bytes(range(32)))
    (directory / "state.json").write_text(json.dumps({"whois": PEERS, "status": status, "serve_status": serve_status or {}}))
    config = directory / "issuer.toml"
    config.write_text(extra + CONFIG.format(listen=listen, tailscale_bin=FAKE_TAILSCALE))
    return config


@pytest.fixture(scope="session")
def issuer_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("issuer")
    os.environ["FAKE_TAILSCALE_STATE"] = str(directory / "state.json")
    write_issuer_dir(directory)
    return directory


class Issuer:
    def __init__(self, config_path: Path):
        self.config = load_config(config_path)
        self.app = app_for(self.config)
        self.server = make_server(self.app)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def request(self, method, path, peer="192.0.2.1", origin=None, headers=None, serve=True, login=None):
        sent = {}
        if serve:
            sent.update({"Host": SERVE_HOST_HEADER, "X-Forwarded-Host": SERVE_HOST_HEADER, "X-Forwarded-For": peer, "X-Forwarded-Proto": "https"})
            ip, raw = peer, PEERS.get(peer)
            if raw and not raw["Node"]["Tags"]:
                sent["Tailscale-User-Login"] = login or raw["UserProfile"]["LoginName"]
        if origin:
            sent["Origin"] = origin
        sent.update(headers or {})
        conn = self.connect()
        conn.request(method, path, headers={k: v for k, v in sent.items() if v is not None})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response, body

    def connect(self):
        host, port = self.server.server_address[:2]
        return http.client.HTTPConnection(host, port, timeout=10)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="session")
def issuer(issuer_dir):
    running = Issuer(issuer_dir / "issuer.toml")
    yield running
    running.close()


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.unix_path)


@pytest.fixture
def short_tmp():
    directory = Path(tempfile.mkdtemp(dir="/tmp", prefix="tsm-"))
    yield directory
    shutil.rmtree(directory)
