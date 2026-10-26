import pytest
from test_gate import PASSWORD, call, cookie_from, header, post_login, verify_request
from test_guests import A, B, add_guest, gate, gate_dir, passwd, sign_in, touch  # noqa: F401

from tailisman.gate.config import load_config
from tailisman.gate.http import GateApp

FOLDER = "/reports/"
PAGE = "/notes/today.html"


def scoped(gate_dir, name="carol", paths=f"{FOLDER}*", sites=A):
    return add_guest(gate_dir, name, sites, "--paths", paths)


def status(gate, cookie, uri, host=A, accept="text/html"):
    return verify_request(gate, host=host, uri=uri, cookie=cookie, accept=accept).status


def test_a_folder_guest_opens_the_folder_and_gets_the_sign_in_page_everywhere_else(gate, gate_dir):
    cookie = sign_in(gate, scoped(gate_dir))
    for uri in (FOLDER, f"{FOLDER}q3/summary.html", f"{FOLDER}data.json?v=2"):
        assert status(gate, cookie, uri) == 200, uri
    for uri in ("/", "/reports", "/reportsx/", "/other/page.html", "/.peek-index.json"):
        refused = verify_request(gate, host=A, uri=uri, cookie=cookie)
        assert refused.status == 302 and header(refused, "Location")[0].startswith("/.tailisman/login?next="), uri
        assert status(gate, cookie, uri, accept="application/json") == 401, uri
    assert status(gate, cookie, FOLDER, host=B) == 302


@pytest.mark.parametrize("uri", [
    "/reports/../secret.html",
    "/reports/..",
    "/reports/%2e%2e/secret.html",
    "/reports/%2E%2E/secret.html",
    "/reports/.%2e/secret.html",
    "/reports/..%2fsecret.html",
    "/reports/..%2Fsecret.html",
    "/reports/%5c..%5csecret.html",
    "/reports/..\\secret.html",
    "/reports//etc/passwd",
    "//reports/x",
    "/reports/;/../secret.html",
    "/reports;/x",
    "/REPORTS/x.html",
    "/Reports/x.html",
    "/%72eports/x.html",
    "/reports/%00/../x",
    "/reports/x%00.html",
])
def test_traversal_encoding_slash_and_case_tricks_never_reach_outside_the_folder(gate, gate_dir, uri):
    cookie = sign_in(gate, scoped(gate_dir))
    assert status(gate, cookie, uri) == 302


def test_an_exact_link_guest_opens_only_that_link_with_any_query(gate, gate_dir):
    cookie = sign_in(gate, scoped(gate_dir, paths=PAGE))
    assert status(gate, cookie, PAGE) == 200
    assert status(gate, cookie, f"{PAGE}?print=1") == 200
    for uri in ("/notes/", "/notes/today.html/", "/notes/today.htm", "/notes/today.html.bak", "/notes/style.css", "/notes/TODAY.html"):
        assert status(gate, cookie, uri) == 302, uri


def test_folders_and_links_mix_and_comma_and_repeat_forms_agree(gate, gate_dir):
    cookie = sign_in(gate, add_guest(gate_dir, "carol", A, "--paths", f"{FOLDER}*,{PAGE}", "--paths", "/extra.css"))
    assert all(status(gate, cookie, uri) == 200 for uri in (f"{FOLDER}a", PAGE, "/extra.css"))
    assert status(gate, cookie, "/notes/") == 302
    assert (gate_dir / "guest-passwords").read_text().split()[1] == f"{A}{FOLDER}*,{A}{PAGE},{A}/extra.css"


def test_sign_in_lands_on_the_first_allowed_path_unless_the_deep_link_is_inside(gate, gate_dir):
    phrase = scoped(gate_dir)
    assert header(post_login(gate, phrase, host=A, next_path="/"), "Location") == [FOLDER]
    assert header(post_login(gate, phrase, host=A, next_path="/elsewhere/x"), "Location") == [FOLDER]
    assert header(post_login(gate, phrase, host=A, next_path=f"{FOLDER}q3/x.html?a=1"), "Location") == [f"{FOLDER}q3/x.html?a=1"]
    assert header(post_login(gate, phrase, host=A, next_path="/reports/../x"), "Location") == [FOLDER]
    assert header(post_login(gate, PASSWORD, host=A, next_path="/elsewhere/x", ip="198.51.100.7"), "Location") == ["/elsewhere/x"]


def test_a_signed_in_scoped_guest_sent_to_sign_in_from_outside_sees_the_form_not_a_redirect_loop(gate, gate_dir):
    cookie = sign_in(gate, scoped(gate_dir))
    outside = call(gate, "GET", "/.tailisman/login?next=%2Fother", host=A, Cookie=f"tailisman_gate={cookie}")
    assert outside.status == 200 and b"<form" in outside.body
    inside = call(gate, "GET", f"/.tailisman/login?next={FOLDER}", host=A, Cookie=f"tailisman_gate={cookie}")
    assert inside.status == 303 and header(inside, "Location") == [FOLDER]
    page = call(gate, "GET", "/.tailisman/", host=A, Cookie=f"tailisman_gate={cookie}")
    assert b"Signed in as carol (guest)" in page.body and f'href="{FOLDER}"'.encode() in page.body


def test_scopes_are_per_site_and_whole_site_guests_are_unchanged(gate, gate_dir):
    path = gate_dir / "guest-passwords"
    digest = None
    phrase = scoped(gate_dir)
    digest = path.read_text().split()[2]
    path.write_text(f"carol {A}{FOLDER}*,{B} {digest}\n")
    touch(path)
    cookie = sign_in(gate, phrase)
    assert status(gate, cookie, "/", host=A) == 302
    assert status(gate, cookie, "/anything", host=B) == 200
    whole = sign_in(gate, add_guest(gate_dir, "bob", A), ip="198.51.100.8")
    assert status(gate, whole, "/anything", host=A) == 200


def test_narrowing_a_scope_in_the_guest_file_applies_to_live_sessions_and_revoking_ends_them(gate, gate_dir):
    phrase = scoped(gate_dir, paths=f"{FOLDER}*,{PAGE}")
    cookie = sign_in(gate, phrase)
    path = gate_dir / "guest-passwords"
    name, _, digest = path.read_text().split()[:3]
    path.write_text(f"{name} {A}{FOLDER}* {digest}\n")
    touch(path)
    assert status(gate, cookie, PAGE) == 302 and status(gate, cookie, FOLDER) == 200
    assert passwd(gate_dir, "--revoke", "carol") == 0
    touch(path)
    assert status(gate, cookie, FOLDER) == 302


@pytest.mark.parametrize("line_scope", [f"{A}/reports/../x/*", f"{A}reports/*", f"{A}/a/*,{A}/b*", f"{A}/a/*,nothost", f"{A}/a/%2e%2e/*"])
def test_a_malformed_scope_skips_the_whole_record_rather_than_widening_it(gate, gate_dir, line_scope):
    phrase = scoped(gate_dir)
    path = gate_dir / "guest-passwords"
    digest = path.read_text().split()[2]
    path.write_text(f"carol {line_scope} {digest}\n")
    touch(path)
    assert post_login(gate, phrase, host=A).status == 401


@pytest.mark.parametrize("bad", ["/a/../b/*", "/a*", "GET /a/*", "a/b", "/a/b,c"])
def test_passwd_refuses_a_path_that_is_not_a_plain_folder_or_link(gate_dir, capsys, bad):
    assert passwd(gate_dir, "--add", "carol", "--sites", A, "--paths", bad) == 2
    assert not (gate_dir / "guest-passwords").exists()


def test_paths_without_add_is_refused(gate_dir):
    assert passwd(gate_dir, "--paths", "/a/*") == 2


def test_gate_toml_is_reloaded_on_change_and_a_broken_one_keeps_the_running_config(gate_dir, capsys):
    path = gate_dir / "gate.toml"
    path.write_text(path.read_text().replace('cookie_domain = "example.com"\n', 'cookie_domain = "example.com"\nopen = ["/reports/*"]\n', 1))
    app = GateApp(load_config(path))
    assert verify_request(app, host=A, uri="/reports/x").status == 200
    good = path.read_text()
    path.write_text(good.replace('open = ["/reports/*"]', "open = [nonsense"))
    touch(path)
    assert verify_request(app, host=A, uri="/reports/x").status == 200
    assert "did not load, so the running config stays" in capsys.readouterr().err
    path.write_text(good.replace('open = ["/reports/*"]', "open = []"))
    touch(path)
    assert verify_request(app, host=A, uri="/reports/x").status == 302
    path.write_text(good.replace('password_file = "gate-password"', 'password_file = "elsewhere"'))
    touch(path)
    assert verify_request(app, host=A, uri="/reports/x").status == 302
    assert "changes password_file, which needs a restart; the running config stays" in capsys.readouterr().err
