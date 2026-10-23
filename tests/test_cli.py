import json
import os
import stat

from tailisman import Verifier
from tailisman.issuer.cli import main

from conftest import write_issuer_dir

WEB_HOST = "laptop.example-tailnet.ts.net:8443"


def test_keygen_writes_a_private_secret_and_refuses_to_overwrite(tmp_path, capsys):
    path = tmp_path / "secret"
    assert main(["keygen", str(path)]) == 0
    assert len(path.read_bytes()) == 32
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    before = path.read_bytes()
    assert main(["keygen", str(path)]) == 1
    assert path.read_bytes() == before


def test_key_prints_the_key_that_verifies_issued_tokens(issuer, issuer_dir, capsys):
    assert main(["key", "--config", str(issuer_dir / "issuer.toml"), "--aud", "HTTPS://heckle.example.com"]) == 0
    key = capsys.readouterr().out.strip()
    assert key.startswith("tsk1.")
    response, body = issuer.request("GET", "/v1/claim", origin="https://heckle.example.com")
    assert Verifier(key=key, audience="https://heckle.example.com").verify(json.loads(body)["token"]).node_name == "laptop"


def test_key_refuses_an_unconfigured_audience(issuer_dir, capsys):
    assert main(["key", "--config", str(issuer_dir / "issuer.toml"), "--aud", "https://evil.example.com"]) == 2
    assert "not a configured audience" in capsys.readouterr().err


def serve_status(port, funnel):
    return {
        "TCP": {"8443": {"HTTPS": True}},
        "Web": {WEB_HOST: {"Handlers": {"/": {"Proxy": f"http://127.0.0.1:{port}"}}}},
        "AllowFunnel": {WEB_HOST: True} if funnel else {},
    }


def run_check(tmp_path, monkeypatch, status_for_port):
    monkeypatch.setenv("FAKE_TAILSCALE_STATE", str(tmp_path / "state.json"))
    config = write_issuer_dir(tmp_path, listen="127.0.0.1:8470", serve_status=status_for_port(8470))
    return main(["check", "--config", str(config)])


def test_check_passes_when_serve_fronts_the_issuer_without_funnel(tmp_path, monkeypatch, capsys):
    assert run_check(tmp_path, monkeypatch, lambda port: serve_status(port, funnel=False)) == 0
    assert f"served at https://{WEB_HOST}, Funnel off" in capsys.readouterr().out


def test_check_fails_when_funnel_is_on(tmp_path, monkeypatch, capsys):
    assert run_check(tmp_path, monkeypatch, lambda port: serve_status(port, funnel=True)) == 1
    assert "Funnel is ON" in capsys.readouterr().err


def test_check_fails_when_nothing_proxies_to_the_issuer(tmp_path, monkeypatch, capsys):
    assert run_check(tmp_path, monkeypatch, lambda port: serve_status(port + 1, funnel=False)) == 1
    assert "no serve handler proxies to http://127.0.0.1:8470" in capsys.readouterr().err
