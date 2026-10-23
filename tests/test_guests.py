import json
import os
import stat

import pytest
from test_gate import PASSWORD, SECRET, Clock, call, cookie_from, header, post_login, verify_request

from tailisman.cli import main
from tailisman.gate.config import load_config
from tailisman.gate.http import GateApp
from tailisman.gate import session as session_module
from tailisman.gate.password import hash_password
from tailisman.gate.session import GUEST_PREFIX, Method, Session, guest_key, mint

A = "a.example.com"
B = "b.example.com"

CONFIG = f"""
session_secret_file = "gate-secret"
password_file = "gate-password"

[[sites]]
host = "{A}"
cookie_domain = "example.com"

[[sites]]
host = "{B}"
cookie_domain = "example.com"
"""


@pytest.fixture
def gate_dir(tmp_path):
    (tmp_path / "gate-secret").write_bytes(SECRET)
    (tmp_path / "gate-password").write_text(hash_password(PASSWORD, log_n=10) + "\n")
    (tmp_path / "gate.toml").write_text(CONFIG)
    return tmp_path


@pytest.fixture
def gate(gate_dir):
    clock = Clock()
    app = GateApp(load_config(gate_dir / "gate.toml", clock=clock), clock=clock)
    app.clock_ref = clock
    return app


def passwd(gate_dir, *args):
    return main(["passwd", "--config", str(gate_dir / "gate.toml"), *args])


def add_guest(gate_dir, name="alice", sites=A, *extra):
    assert passwd(gate_dir, "--add", name, "--sites", sites, *extra) == 0
    return (gate_dir / "guests" / name).read_text().strip()


def touch(path):
    """Guarantees the gate sees a new mtime even on filesystems with coarse timestamps."""
    info = os.stat(path)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000))


def sign_in(app, password, host=A, ip="198.51.100.1"):
    return cookie_from(post_login(app, password, host=host, ip=ip), "tailisman_gate")


def test_a_guest_cookie_on_the_shared_parent_domain_is_refused_on_the_owners_other_site(gate, gate_dir):
    phrase = add_guest(gate_dir, "alice", A)
    response = post_login(gate, phrase, host=A)
    assert response.status == 303
    set_cookie = [c for c in header(response, "Set-Cookie") if c.startswith("tailisman_gate=")][0]
    assert "; Domain=example.com;" in set_cookie
    guest = cookie_from(response, "tailisman_gate")
    assert guest.startswith(f"{GUEST_PREFIX}.alice.")
    allowed = verify_request(gate, host=A, cookie=guest)
    assert allowed.status == 200 and header(allowed, "X-Tailisman-Session") == ["guest"] and header(allowed, "X-Tailisman-User") == ["alice"]
    assert verify_request(gate, host=B, cookie=guest).status == 302
    assert verify_request(gate, host=B, cookie=guest, accept="application/json").status == 401
    owner = sign_in(gate, PASSWORD, host=A, ip="198.51.100.2")
    for host in (A, B):
        assert verify_request(gate, host=host, cookie=owner).status == 200
        assert header(verify_request(gate, host=host, cookie=owner), "X-Tailisman-User") == []


def test_a_guest_password_typed_into_another_sites_form_is_a_wrong_password(gate, gate_dir):
    phrase = add_guest(gate_dir, "alice", A)
    refused = post_login(gate, phrase, host=B, ip="198.51.100.3")
    assert refused.status == 401 and b"That password did not work." in refused.body and cookie_from(refused, "tailisman_gate") is None
    for _ in range(4):
        post_login(gate, phrase, host=B, ip="198.51.100.3")
    assert post_login(gate, phrase, host=A, ip="198.51.100.3").status == 429


def test_a_guest_with_several_sites_signs_in_once_for_all_of_them(gate, gate_dir):
    phrase = add_guest(gate_dir, "bob", f"{A},{B}")
    cookie = sign_in(gate, phrase, host=B)
    assert all(verify_request(gate, host=host, cookie=cookie).status == 200 for host in (A, B))
    page = call(gate, "GET", "/.tailisman/", host=A, Cookie=f"tailisman_gate={cookie}")
    assert b"Signed in as bob (guest), until" in page.body


def test_revoking_a_guest_ends_their_session_on_the_next_request(gate, gate_dir, capsys):
    phrase = add_guest(gate_dir, "alice", A)
    cookie = sign_in(gate, phrase)
    owner = sign_in(gate, PASSWORD, ip="198.51.100.2")
    assert verify_request(gate, cookie=cookie, host=A).status == 200
    assert passwd(gate_dir, "--revoke", "alice") == 0
    touch(gate_dir / "guest-passwords")
    assert verify_request(gate, cookie=cookie, host=A).status == 302
    assert verify_request(gate, cookie=owner, host=A).status == 200
    assert not (gate_dir / "guests" / "alice").exists()
    assert post_login(gate, phrase, host=A, ip="198.51.100.4").status == 401
    assert passwd(gate_dir, "--revoke", "alice") == 1
    assert "no guest named 'alice'" in capsys.readouterr().err


def test_force_re_adding_a_guest_ends_their_old_session_and_plain_re_adding_is_refused(gate, gate_dir):
    phrase = add_guest(gate_dir, "alice", A)
    cookie = sign_in(gate, phrase)
    assert passwd(gate_dir, "--add", "alice", "--sites", A) == 1
    assert (gate_dir / "guests" / "alice").read_text().strip() == phrase
    new_phrase = add_guest(gate_dir, "alice", A, "--force")
    touch(gate_dir / "guest-passwords")
    assert new_phrase != phrase
    assert verify_request(gate, cookie=cookie, host=A).status == 302
    assert verify_request(gate, cookie=sign_in(gate, new_phrase, ip="198.51.100.5"), host=A).status == 200


def test_changing_the_owner_password_keeps_guest_sessions(gate, gate_dir):
    cookie = sign_in(gate, add_guest(gate_dir, "alice", A))
    owner = sign_in(gate, PASSWORD, ip="198.51.100.2")
    (gate_dir / "gate-password").write_text(hash_password("a brand new password", log_n=10) + "\n")
    touch(gate_dir / "gate-password")
    assert verify_request(gate, cookie=owner, host=A).status == 302
    assert verify_request(gate, cookie=cookie, host=A).status == 200


def test_passwd_guest_files_are_private_and_nothing_printed_holds_a_secret(gate_dir, capsys):
    phrase = add_guest(gate_dir, "alice", f"{A},{B}")
    other = add_guest(gate_dir, "carol", B.upper())
    assert stat.S_IMODE(os.stat(gate_dir / "guests").st_mode) == 0o700
    for path in (gate_dir / "guests" / "alice", gate_dir / "guests" / "carol", gate_dir / "guest-passwords"):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert passwd(gate_dir, "--list") == 0
    printed = capsys.readouterr()
    record = (gate_dir / "guest-passwords").read_text()
    assert record.splitlines()[1].startswith(f"carol {B} sha256$")
    assert f"alice: {A}, {B}" in printed.out and f"carol: {B}" in printed.out
    for secret in (phrase, other, "sha256$", *[line.split()[2] for line in record.splitlines()]):
        assert secret not in printed.out + printed.err


def test_passwd_add_needs_configured_sites_and_a_plain_name(gate_dir, capsys):
    assert passwd(gate_dir, "--add", "alice") == 2
    assert f"this gate's sites are {A}, {B}" in capsys.readouterr().err
    assert passwd(gate_dir, "--add", "alice", "--sites", "c.example.com") == 2
    assert f"'c.example.com' is not a [[sites]] host of this gate; its sites are {A}, {B}" in capsys.readouterr().err
    assert passwd(gate_dir, "--add", "Alice!", "--sites", A) == 2
    assert passwd(gate_dir, "--sites", A) == 2
    assert not (gate_dir / "guest-passwords").exists() and not (gate_dir / "guests").exists()


def test_a_malformed_guest_line_is_skipped_once_and_kept_on_rewrite(gate, gate_dir, capsys):
    phrase = add_guest(gate_dir, "alice", A)
    path = gate_dir / "guest-passwords"
    path.write_text("not a record\n" + path.read_text())
    touch(path)
    assert verify_request(gate, host=A, cookie=sign_in(gate, phrase)).status == 200
    assert verify_request(gate, host=A).status == 302
    assert capsys.readouterr().err.count("line 1 is not a new NAME SITES DIGEST record") == 1
    add_guest(gate_dir, "bob", B)
    assert path.read_text().startswith("not a record\nalice ")


def test_a_forged_name_segment_or_a_payload_name_that_differs_is_refused(gate, gate_dir):
    add_guest(gate_dir, "alice", A)
    add_guest(gate_dir, "mallory", A)
    cookie = sign_in(gate, (gate_dir / "guests" / "mallory").read_text().strip())
    prefix, name, payload, mac = cookie.split(".")
    assert verify_request(gate, host=A, cookie=f"{prefix}.alice.{payload}.{mac}").status == 302
    assert verify_request(gate, host=A, cookie=f"{prefix}.Mallory.{payload}.{mac}").status == 302
    digest = (gate_dir / "guest-passwords").read_text().splitlines()[1].split()[2]
    now = int(gate.clock_ref())
    claims_alice = json.dumps({"m": "guest", "guest": "alice", "scope": "example.com", "iat": now, "exp": now + 3600}, separators=(",", ":"))
    signing_input = f"{GUEST_PREFIX}.mallory.{session_module.b64encode(claims_alice.encode())}"
    signed = f"{signing_input}.{session_module.b64encode(session_module._mac(guest_key(SECRET, 'mallory', digest), signing_input))}"
    assert verify_request(gate, host=A, cookie=signed).status == 302
    honest = mint(Session(Method.GUEST, None, "example.com", now, now + 3600, "mallory"), guest_key(SECRET, "mallory", digest))
    assert verify_request(gate, host=A, cookie=honest).status == 200


def test_status_counts_guests_per_site_without_naming_them(gate_dir, capsys):
    add_guest(gate_dir, "alice", f"{A},{B}")
    add_guest(gate_dir, "bob", B)
    capsys.readouterr()
    main(["gate", "status", "--config", str(gate_dir / "gate.toml"), "--base-url-for", f"{A}=http://127.0.0.1:9", "--base-url-for", f"{B}=http://127.0.0.1:9"])
    out = capsys.readouterr().out
    assert "a.example.com: forward_auth, scope example.com, tailnet off, guests 1," in out and "b.example.com: forward_auth, scope example.com, tailnet off, guests 2," in out
    assert "alice" not in out and "bob" not in out
