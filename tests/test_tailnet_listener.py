import http.client
import json
import socket
import threading

import pytest
from conftest import FAKE_TAILSCALE, PEERS, free_port
from test_gate import SECRET

from tailisman.cli import main
from tailisman.gate.cli import make_servers
from tailisman.gate.config import load_config

SERVE_HOST = "gate.example-tailnet.ts.net"
TOOLS = "tools.example.com"


def gate_dir(directory, monkeypatch, tailnet_port, serve_status=None):
    monkeypatch.setenv("FAKE_TAILSCALE_STATE", str(directory / "state.json"))
    (directory / "state.json").write_text(json.dumps({"whois": PEERS, "serve_status": serve_status or {}}))
    (directory / "gate-secret").write_bytes(SECRET)
    path = directory / "gate.toml"
    path.write_text(
        f'listen = "127.0.0.1:{free_port()}"\nsession_secret_file = "gate-secret"\npassword_file = "gate-password"\n\n'
        f'[tailnet]\nlisten = "127.0.0.1:{tailnet_port}"\nserve_host = "{SERVE_HOST}"\ntailscale_bin = "{FAKE_TAILSCALE}"\ndevices = ["laptop"]\n\n'
        f'[[sites]]\nhost = "{TOOLS}"\ncookie_domain = "example.com"\n'
    )
    return path


def served(port, funnel=False):
    web = f"{SERVE_HOST}:8443"
    return {"Web": {web: {"Handlers": {"/": {"Proxy": f"http://127.0.0.1:{port}"}}}}, "AllowFunnel": {web: True} if funnel else {}}


@pytest.fixture
def running(tmp_path, monkeypatch):
    port = free_port()
    servers = make_servers(load_config(gate_dir(tmp_path, monkeypatch, port, served(port))))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield servers, tmp_path
    for server in servers:
        server.shutdown()
        server.server_close()


def ask(address, method, path, headers, body=None):
    conn = http.client.HTTPConnection(*address, timeout=10)
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    return response.status, response.read()


def test_one_process_hands_out_a_code_on_the_tailnet_listener_and_redeems_it_on_the_public_one(running):
    (public, tailnet), _ = running
    serve = {"Host": f"{SERVE_HOST}:8443", "X-Forwarded-Host": f"{SERVE_HOST}:8443", "X-Forwarded-For": "192.0.2.1", "X-Forwarded-Proto": "https", "Tailscale-User-Login": "owner@example.com"}
    status, body = ask(tailnet.server_address[:2], "GET", "/v1/claim", serve | {"Origin": f"https://{TOOLS}"})
    code = json.loads(body)["token"]
    assert status == 200
    status, body = ask(public.server_address[:2], "POST", "/.tailisman/exchange", {"Host": TOOLS, "Content-Type": "application/json"}, json.dumps({"token": code}))
    assert (status, json.loads(body)) == (200, {"device": "laptop", "next": "/"})
    status, body = ask(public.server_address[:2], "POST", "/.tailisman/exchange", {"Host": TOOLS, "Content-Type": "application/json"}, json.dumps({"token": code}))
    assert (status, json.loads(body)) == (403, {"error": "replayed"})
    status, body = ask(tailnet.server_address[:2], "GET", "/v1/claim", {"Host": "127.0.0.1", "Origin": f"https://{TOOLS}"})
    assert (status, json.loads(body)) == (421, {"error": "wrong_host"})


def test_status_reports_the_tailnet_listener_served_without_funnel(running, capsys):
    _, directory = running
    main(["gate", "status", "--config", str(directory / "gate.toml"), "--base-url-for", f"{TOOLS}=http://127.0.0.1:9"])
    tailnet_port = running[0][1].server_address[1]
    assert capsys.readouterr().out.splitlines()[0] == f"tailnet: listener http://127.0.0.1:{tailnet_port}, origin https://{SERVE_HOST}:8443: ok, served, Funnel off"


@pytest.mark.parametrize(
    "serve_status,listening,problem",
    [
        (lambda port: served(port), False, "the tailnet listener is not accepting connections"),
        (lambda port: {}, True, "no serve handler proxies to it; run `tailscale serve --bg --https=8443 http://127.0.0.1:"),
        (lambda port: served(port, funnel=True), True, "Funnel is ON for gate.example-tailnet.ts.net:8443"),
        (lambda port: served(port) | {"Web": {"other.example-tailnet.ts.net:8443": served(port)["Web"][f"{SERVE_HOST}:8443"]}}, True, "serve fronts it as other.example-tailnet.ts.net:8443"),
    ],
)
def test_status_flags_a_tailnet_listener_that_is_down_unserved_funnelled_or_misnamed(tmp_path, monkeypatch, capsys, serve_status, listening, problem):
    port = free_port()
    path = gate_dir(tmp_path, monkeypatch, port, serve_status(port))
    listener = socket.create_server(("127.0.0.1", port)) if listening else None
    try:
        assert main(["gate", "status", "--config", str(path), "--base-url-for", f"{TOOLS}=http://127.0.0.1:9"]) == 1
    finally:
        if listener:
            listener.close()
    assert problem in capsys.readouterr().out.splitlines()[0]


def test_the_tailnet_status_page_points_an_unlisted_device_at_gate_toml(running):
    (_, tailnet), _ = running
    serve = {"Host": f"{SERVE_HOST}:8443", "X-Forwarded-Host": f"{SERVE_HOST}:8443", "X-Forwarded-For": "192.0.2.2", "X-Forwarded-Proto": "https", "Tailscale-User-Login": "owner@example.com"}
    status, body = ask(tailnet.server_address[:2], "GET", "/", serve)
    page = body.decode()
    assert status == 200 and "<code>[tailnet] devices</code> in gate.toml" in page and "issuer.toml" not in page
