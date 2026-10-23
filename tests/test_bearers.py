import base64
import hashlib
import io
import re

import pytest
from test_gate import NOTES, SECRET, TOOLS, call, header, write_gate_dir

from tailisman.cli import main
from tailisman.gate.config import ConfigError, load_config, parse_config
from tailisman.gate.http import GateApp

TOKEN = "machine-caller-token-1"
DIGEST = "sha256$" + base64.b64encode(hashlib.sha256(TOKEN.encode()).digest()).decode()


@pytest.fixture
def gate(tmp_path):
    path = write_gate_dir(tmp_path)
    path.write_text(path.read_text().replace(f'host = "{NOTES}"\n', f'host = "{NOTES}"\nbearers = ["{DIGEST}"]\n'))
    return GateApp(load_config(path))


def verify(app, host=NOTES, uri="/feed.xml", accept="application/json", authorization=None):
    extra = {"X_Forwarded_Method": "GET", "X_Forwarded_Uri": uri, "Accept": accept}
    if authorization is not None:
        extra["Authorization"] = authorization
    return call(app, "GET", "/.tailisman/verify", host=host, **extra)


def test_a_listed_bearer_passes_a_non_open_path_with_no_cookie(gate):
    allowed = verify(gate, authorization=f"Bearer {TOKEN}")
    assert allowed.status == 200 and header(allowed, "X-Tailisman-Session") == ["bearer"] and header(allowed, "X-Tailisman-User") == []
    assert verify(gate, uri="/api/../admin", authorization=f"bearer {TOKEN}").status == 200


@pytest.mark.parametrize("authorization", [f"Bearer {TOKEN}x", "Bearer ", f"Basic {TOKEN}", TOKEN, f"Bearer{TOKEN}", ""])
def test_an_unlisted_or_malformed_bearer_falls_through_to_sign_in(gate, authorization):
    assert verify(gate, authorization=authorization).status == 401
    assert verify(gate, authorization=authorization, accept="text/html").status == 302


def test_a_bearer_counts_only_on_the_site_that_lists_it(gate):
    assert verify(gate, host=TOOLS, uri="/private", authorization=f"Bearer {TOKEN}").status == 401


def test_two_authorization_headers_are_no_bearer(gate):
    from email.message import Message

    message = Message()
    for name, value in (("Host", NOTES), ("X-Forwarded-Method", "GET"), ("X-Forwarded-Uri", "/x"), ("Authorization", f"Bearer {TOKEN}"), ("Authorization", "Bearer other")):
        message[name] = value
    response, _ = gate.respond("GET", "/.tailisman/verify", message)
    assert response.status == 401


@pytest.mark.parametrize("bearers", [["sha256$short="], [TOKEN], "sha256$x", [DIGEST.replace("sha256", "md5")]])
def test_config_refuses_anything_but_digests(tmp_path, bearers):
    (tmp_path / "gate-secret").write_bytes(SECRET)
    raw = {"session_secret_file": "gate-secret", "password_file": "p", "sites": [{"host": NOTES, "bearers": bearers}]}
    with pytest.raises(ConfigError, match=re.escape("bearers must be a list of sha256$<base64> digests")):
        parse_config(raw, base=tmp_path)


def test_bearer_hash_reads_stdin_and_prints_only_the_digest(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(TOKEN + "\n"))
    assert main(["gate", "bearer-hash"]) == 0
    out = capsys.readouterr()
    assert out.out == DIGEST + "\n" and TOKEN not in out.out + out.err
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["gate", "bearer-hash"]) == 1


def test_status_counts_bearers_per_site(gate, tmp_path, capsys):
    main(["gate", "status", "--config", str(tmp_path / "gate.toml"), *[a for h in (TOOLS, NOTES, "solo.example.net") for a in ("--base-url-for", f"{h}=http://127.0.0.1:9")]])
    out = capsys.readouterr().out
    assert f"{NOTES}: forward_auth, scope example.com, tailnet off, guests 0, bearers 1," in out and f"{TOOLS}: forward_auth" in out and "bearers 0" in out
