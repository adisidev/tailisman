import http.client
import http.server
import json
import threading
from functools import partial
from urllib.parse import urlencode

import pytest
from conftest import free_port
from test_gate import PASSWORD, SECRET

from tailisman.cli import main
from tailisman.gate.config import load_config
from tailisman.gate.credentials import guest_digest
from tailisman.gate.http import GateApp, make_server
from tailisman.gate.password import hash_password
from tailisman.gate.share import Exit

HOST = "files.example.com"
OTHER = "other.example.com"

GATE_TOML = """# a comment that must survive
listen = "127.0.0.1:{port}"
session_secret_file = "gate-secret"
password_file = "gate-password"

[[sites]]
host = "{host}"
upstream = "http://127.0.0.1:{upstream}"
cookie_domain = "example.com"
open = ["/healthz", "/reports/*"]   # the old secret-link share

[[sites]]
host = "{other}"
upstream = "http://127.0.0.1:{upstream}"
open = ["/api/*"]   # machines
"""

FILES = {
    "index.html": "<p>the root</p>",
    "reports/index.html": '<link rel=stylesheet href="style.css"><script src="/shared/app.js"></script><img src="q3/chart.png"><a href="/elsewhere.html">x</a><a href="https://cdn.example.net/x.js">cdn</a>',
    "reports/style.css": "p{}",
    "reports/q3/chart.png": "png",
    "shared/app.js": "1",
    "notes/today.html": '<link rel=stylesheet href="today.css"><p>today</p>',
    "notes/today.css": "p{}",
}


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def live(tmp_path):
    site = tmp_path / "site"
    for name, body in FILES.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_text(body)
    upstream = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(site))))
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "gate-secret").write_bytes(SECRET)
    (conf / "gate-password").write_text(hash_password(PASSWORD, log_n=10) + "\n")
    port = free_port()
    (conf / "gate.toml").write_text(GATE_TOML.format(port=port, host=HOST, other=OTHER, upstream=upstream.server_port))
    gate = serve(make_server(GateApp(load_config(conf / "gate.toml"))))
    yield conf, f"http://127.0.0.1:{port}"
    gate.shutdown()
    upstream.shutdown()


def run(capsys, conf, *args, base=None):
    capsys.readouterr()
    extra = ["--base-url", base] if base else []
    code = main([*args, "--config", str(conf / "gate.toml"), "--json", *extra])
    report = json.loads(capsys.readouterr().out)
    assert report["exit"] == code
    return code, report


def checks(report):
    return {check["name"]: check["ok"] for check in report["checks"]}


def test_share_a_folder_closes_only_the_open_rule_inside_it_and_proves_it_live(live, capsys):
    conf, base = live
    code, report = run(capsys, conf, "share", f"https://{HOST}/reports/", "--to", "carol", base=base)
    assert code == Exit.STILL_PUBLIC and report["open_rules"]["inside"] == ["/reports/*"]
    assert checks(report)["anonymous_gets_sign_in"] is False
    assert any("--close-open-rule" in step for step in report["next_steps"])

    code, report = run(capsys, conf, "share", f"https://{HOST}/reports/", "--to", "carol", "--close-open-rule", base=base)
    assert code == Exit.OK, report
    assert checks(report) == {"anonymous_gets_sign_in": True, "guest_signs_in": True, "guest_opens_scope": True, "guest_refused_outside": True}
    assert report["created"] is False and report["changed"] is False
    assert report["scopes"] == [{"url": f"https://{HOST}/reports/", "host": HOST, "path": "/reports/", "kind": "folder"}]
    assert report["outside_scope"] == {"assets": ["/shared/app.js"], "links": ["/elsewhere.html"]}
    assert report["password_file"] == str(conf / "guests" / "carol") and "password" not in report
    toml = (conf / "gate.toml").read_text()
    assert toml.startswith("# a comment that must survive") and 'open = ["/healthz"]   # the old secret-link share\n' in toml and 'open = ["/api/*"]   # machines' in toml
    assert "/reports/*" in open(report["open_rules"]["backup"]).read()


def test_share_twice_changes_nothing_and_a_second_url_adds_a_scope(live, capsys):
    conf, base = live
    assert run(capsys, conf, "share", f"https://{HOST}/notes/today.html", "--to", "carol", base=base)[0] == Exit.OK
    record = (conf / "guest-passwords").read_text()
    phrase = (conf / "guests" / "carol").read_text()
    code, report = run(capsys, conf, "share", f"https://{HOST}/notes/today.html", "--to", "carol", base=base)
    assert code == Exit.OK and report["changed"] is False
    assert (conf / "guest-passwords").read_text() == record and (conf / "guests" / "carol").read_text() == phrase
    code, report = run(capsys, conf, "share", f"https://{OTHER}/docs/", "--to", "carol", "--no-check")
    assert code == Exit.OK and [entry["url"] for entry in report["scopes"]] == [f"https://{HOST}/notes/today.html", f"https://{OTHER}/docs/"]
    assert (conf / "guests" / "carol").read_text() == phrase


def test_an_exact_link_names_the_assets_beside_it_that_the_guest_cannot_load(live, capsys):
    conf, base = live
    code, report = run(capsys, conf, "share", f"https://{HOST}/notes/today.html?ref=mail#top", "--to", "ana", base=base)
    assert code == Exit.OK and all(checks(report).values())
    assert report["scope"]["kind"] == "link" and report["scope"]["path"] == "/notes/today.html"
    assert report["outside_scope"]["assets"] == ["/notes/today.css"]
    assert any("today.css" in warning for warning in report["warnings"])


def test_dry_run_writes_nothing(live, capsys):
    conf, base = live
    before = (conf / "gate.toml").read_text()
    code, report = run(capsys, conf, "share", f"https://{HOST}/reports/", "--to", "carol", "--close-open-rule", "--dry-run", base=base)
    assert code == Exit.OK and report["dry_run"] and report["checks"] == []
    assert (conf / "gate.toml").read_text() == before and not (conf / "guest-passwords").exists() and not (conf / "guests").exists()


def test_print_once_shows_the_passphrase_deletes_the_file_and_the_passphrase_works(live, capsys):
    conf, base = live
    code, report = run(capsys, conf, "share", f"https://{HOST}/notes/today.html", "--to", "ana", "--print-once", base=base)
    assert code == Exit.OK and report["password_file"] is None and not (conf / "guests" / "ana").exists()
    assert guest_digest(report["password"]) in (conf / "guest-passwords").read_text()
    assert all(checks(report).values())
    code, report = run(capsys, conf, "share", f"https://{HOST}/notes/today.html", "--to", "ana", "--print-once", base=base)
    assert code == Exit.NOT_FOUND and report["error"] == "no_passphrase_file" and "--new-password" in report["next_steps"][0]


def test_a_wider_open_rule_is_reported_and_never_removed(live, capsys):
    conf, base = live
    code, report = run(capsys, conf, "share", f"https://{OTHER}/api/v1/", "--to", "carol", "--close-open-rule", "--no-check")
    assert code == Exit.STILL_PUBLIC and report["open_rules"]["wider"] == ["/api/*"] and report["open_rules"]["closed"] == []
    assert 'open = ["/api/*"]' in (conf / "gate.toml").read_text()


def test_unshare_takes_back_one_url_then_the_guest_and_guests_lists_them(live, capsys):
    conf, base = live
    run(capsys, conf, "share", f"https://{HOST}/notes/today.html", "--to", "carol", "--no-check")
    run(capsys, conf, "share", f"https://{OTHER}/docs/", "--to", "carol", "--no-check")
    code, report = run(capsys, conf, "guests")
    assert code == Exit.OK and report["guests"][0]["name"] == "carol" and len(report["guests"][0]["scopes"]) == 2
    assert run(capsys, conf, "unshare", f"https://{OTHER}/elsewhere/", "--from", "carol")[0] == Exit.NOT_FOUND
    code, report = run(capsys, conf, "unshare", f"https://{OTHER}/docs/", "--from", "carol")
    assert code == Exit.OK and [entry["url"] for entry in report["scopes"]] == [f"https://{HOST}/notes/today.html"]
    code, report = run(capsys, conf, "unshare", "--from", "carol", "--dry-run")
    assert code == Exit.OK and report["removed_guest"] and (conf / "guests" / "carol").exists()
    code, report = run(capsys, conf, "unshare", "--from", "carol")
    assert code == Exit.OK and report["removed_guest"] and not (conf / "guests" / "carol").exists()
    assert run(capsys, conf, "guests", "carol")[0] == Exit.NOT_FOUND
    assert run(capsys, conf, "unshare", "--from", "carol")[0] == Exit.NOT_FOUND


@pytest.mark.parametrize(("url", "code", "error"), [
    ("files.example.com/reports/", Exit.USAGE, "bad_url"),
    (f"https://{HOST}/reports/../x/", Exit.USAGE, "bad_url"),
    ("https://unknown.example.com/x/", Exit.CONFIG, "not_gated"),
])
def test_bad_input_has_its_own_exit_code_and_says_what_to_do(live, capsys, url, code, error):
    conf, _ = live
    got, report = run(capsys, conf, "share", url, "--to", "carol")
    assert got == code and report["error"] == error and report["ok"] is False


def test_an_unreachable_gate_is_its_own_exit_code(live, capsys):
    conf, _ = live
    code, report = run(capsys, conf, "share", f"https://{HOST}/notes/today.html", "--to", "carol", base=f"http://127.0.0.1:{free_port()}")
    assert code == Exit.UNREACHABLE and report["next_steps"]


def test_human_output_never_holds_the_passphrase(live, capsys):
    conf, base = live
    capsys.readouterr()
    assert main(["share", f"https://{HOST}/notes/today.html", "--to", "carol", "--config", str(conf / "gate.toml"), "--base-url", base]) == 0
    out = capsys.readouterr()
    phrase = (conf / "guests" / "carol").read_text().strip()
    assert phrase not in out.out + out.err and "check guest_opens_scope /notes/today.html: ok" in out.out


class KeepAliveIgnoresBodies(http.server.BaseHTTPRequestHandler):
    """An HTTP/1.1 app that never reads a request body, the shape that turns a leftover body into a second request."""

    protocol_version = "HTTP/1.1"
    seen: list = []

    def handle_any(self):
        self.seen.append((self.command, self.path))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = handle_any

    def log_message(self, format, *args):
        pass


def test_a_body_carrying_a_second_request_never_reaches_a_keep_alive_app(tmp_path, capsys):
    upstream = serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), KeepAliveIgnoresBodies))
    (tmp_path / "gate-secret").write_bytes(SECRET)
    (tmp_path / "gate-password").write_text(hash_password(PASSWORD, log_n=10) + "\n")
    port = free_port()
    (tmp_path / "gate.toml").write_text(GATE_TOML.format(port=port, host=HOST, other=OTHER, upstream=upstream.server_port))
    gate = serve(make_server(GateApp(load_config(tmp_path / "gate.toml"))))
    code, report = run(capsys, tmp_path, "share", f"https://{HOST}/K/", "--to", "carol", "--no-check")
    phrase = (tmp_path / "guests" / "carol").read_text().strip()
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("GET", "/.tailisman/login", headers={"Host": HOST})
    form = conn.getresponse()
    form.read()
    csrf = form.getheader("Set-Cookie").split(";")[0].split("=", 1)[1]
    conn.request("POST", "/.tailisman/login", body=urlencode({"csrf": csrf, "password": phrase, "next": "/K/"}), headers={"Host": HOST, "Cookie": f"tailisman_csrf={csrf}", "Content-Type": "application/x-www-form-urlencoded"})
    login = conn.getresponse()
    login.read()
    cookie = login.getheader("Set-Cookie").split(";")[0]
    smuggled = b"POST /admin/delete HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\nX-Tailisman-Session: password\r\nContent-Length: 0\r\n\r\n"
    conn.request("POST", "/K/in.html", body=smuggled, headers={"Host": HOST, "Cookie": cookie})
    assert conn.getresponse().status == 200
    conn.close()
    gate.shutdown()
    upstream.shutdown()
    assert KeepAliveIgnoresBodies.seen == [("POST", "/K/in.html")]


def test_the_passphrase_never_goes_to_a_plain_http_address_off_this_machine(live, capsys):
    conf, _ = live
    code, report = run(capsys, conf, "share", f"http://{HOST}/notes/today.html", "--to", "carol", base="http://0.0.0.0:9")
    assert any("did not send the passphrase" in warning for warning in report["warnings"])
    assert [check["name"] for check in report["checks"]] == ["gate_reachable"]


def test_a_non_ascii_path_is_stored_as_the_browser_sends_it(live, capsys):
    conf, base = live
    code, report = run(capsys, conf, "share", f"https://{HOST}/caf\u00e9/", "--to", "carol", "--no-check")
    assert code == Exit.OK and report["scope"]["path"] == "/caf%C3%A9/"
