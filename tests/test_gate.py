import base64
import json
import math
import os
import re
import stat
from email.message import Message
from pathlib import Path
from urllib.parse import urlencode

import pytest

from conftest import PEERS
from tailisman.cli import main
from tailisman.gate import password as password_module
from tailisman.gate.config import ConfigError, load_config, parse_config
from tailisman.gate.decision import Allow, GateRequest, SignIn, Unauthorised, decide, is_open, safe_next
from tailisman.gate.http import GateApp
from tailisman.gate.password import CONSONANTS, GROUPS, VOWELS, PasswordHash, generate_passphrase, hash_password, parse_hash
from tailisman.gate.session import Method, Session, first_valid, mint, session_key, verify

SECRET = bytes(range(32, 64))
PASSWORD = "correct-horse-battery"
TOOLS = "tools.example.com"
NOTES = "notes.example.com"
SOLO = "solo.example.net"
SERVE_HOST = "laptop.example-tailnet.ts.net"
TAILNET = f"https://{SERVE_HOST}:8443"

CONFIG = f"""
listen = "127.0.0.1:8471"
session_secret_file = "gate-secret"
password_file = "gate-password"
session_days = 30

[tailnet]
listen = "127.0.0.1:8470"
serve_host = "{SERVE_HOST}"
devices = ["laptop"]

[rate_limit]
per_ip = 3
global = 5
window_seconds = 900

[[sites]]
host = "{TOOLS}"
cookie_domain = "example.com"
open = ["/healthz", "/api/*", "POST /report"]

[[sites]]
host = "{NOTES}"
cookie_domain = "example.com"
tailnet = false

[[sites]]
host = "{SOLO}"
tailnet = false
"""


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def write_gate_dir(directory: Path, password: str | None = PASSWORD) -> Path:
    (directory / "gate-secret").write_bytes(SECRET)
    if password is not None:
        (directory / "gate-password").write_text(hash_password(password, log_n=10) + "\n")
    path = directory / "gate.toml"
    path.write_text(CONFIG)
    return path


@pytest.fixture
def gate(tmp_path):
    clock = Clock()
    app = GateApp(load_config(write_gate_dir(tmp_path)), clock=clock)
    app.clock_ref = clock
    return app


def headers(values: dict) -> Message:
    message = Message()
    for name, value in values.items():
        message[name] = value
    return message


def call(app, method, path, host=TOOLS, body=b"", **extra):
    sent = {"Host": host} | {k.replace("_", "-"): v for k, v in extra.items()}
    response, _ = app.respond(method, path, headers(sent), body, "203.0.113.9")
    return response


def header(response, name):
    return [value for key, value in response.headers if key.lower() == name.lower()]


def cookie_from(response, name):
    for value in header(response, "Set-Cookie"):
        if value.startswith(name + "="):
            return value.split(";")[0].split("=", 1)[1]
    return None


def login_form(app, host=TOOLS, next_path="/"):
    page = call(app, "GET", f"/.tailisman/login?next={next_path}", host=host)
    csrf = cookie_from(page, "tailisman_csrf")
    return csrf, page


def post_login(app, password, host=TOOLS, ip="198.51.100.1", csrf=None, next_path="/", origin=None):
    token, _ = login_form(app, host) if csrf is None else (csrf, None)
    extra = {"Cookie": f"tailisman_csrf={token}", "Content_Type": "application/x-www-form-urlencoded", "CF_Connecting_IP": ip}
    if origin:
        extra["Origin"] = origin
    body = urlencode({"csrf": token, "password": password, "next": next_path}).encode()
    return call(app, "POST", "/.tailisman/login", host=host, body=body, **extra)


def verify_request(app, host=TOOLS, uri="/", cookie=None, accept="text/html", method="GET"):
    extra = {"X_Forwarded_Method": method, "X_Forwarded_Uri": uri, "Accept": accept}
    if cookie:
        extra["Cookie"] = f"tailisman_gate={cookie}"
    return call(app, "GET", "/.tailisman/verify", host=host, **extra)


# Sessions


def owner(key):
    return lambda guest: key if guest is None else None


def session(now=1000, scope="example.com", method=Method.PASSWORD, device=None, days=30):
    return Session(method, device, scope, now, now + days * 86400)


def test_session_round_trips_and_covers_hosts_under_its_scope():
    key = session_key(SECRET, "scrypt$line")
    value = mint(session(device="laptop", method=Method.TAILNET), key)
    assert value.startswith("tsg1.")
    assert verify(value, owner(key), "tools.example.com", 2000) == session(device="laptop", method=Method.TAILNET)
    assert verify(value, owner(key), "example.com", 2000) is not None


@pytest.mark.parametrize("host", ["example.net", "badexample.com", "example.com.evil.net"])
def test_session_is_refused_for_a_host_outside_its_scope(host):
    key = session_key(SECRET, "line")
    assert verify(mint(session(), key), owner(key), host, 2000) is None


def test_session_is_refused_when_tampered_expired_or_signed_under_another_password():
    key = session_key(SECRET, "line")
    value = mint(session(now=1000, days=1), key)
    prefix, payload, mac = value.split(".")
    forged = mint(Session(Method.PASSWORD, None, "com", 1000, 10**9), key).split(".")[1]
    assert verify(f"{prefix}.{forged}.{mac}", owner(key), TOOLS, 2000) is None
    assert verify(f"{prefix}.{payload}.{mac[:-1]}A", owner(key), TOOLS, 2000) is None
    assert verify(f"{prefix}.{payload}=.{mac}", owner(key), TOOLS, 2000) is None
    assert verify(value, owner(key), TOOLS, 1000 + 86400) is None
    assert verify(value, owner(key), TOOLS, 999) is None
    assert verify(value, owner(session_key(SECRET, "another line")), TOOLS, 2000) is None
    assert verify(value, owner(session_key(bytes(32), "line")), TOOLS, 2000) is None


def test_session_payload_must_be_exactly_the_expected_shape():
    key = session_key(SECRET, "line")
    from tailisman.gate import session as module

    def signed(payload):
        text = json.dumps(payload, separators=(",", ":")).encode()
        signing_input = f"tsg1.{module.b64encode(text)}"
        return f"{signing_input}.{module.b64encode(module._mac(key, signing_input))}"

    good = {"m": "password", "dev": None, "scope": "example.com", "iat": 1000, "exp": 5000}
    assert verify(signed(good), owner(key), TOOLS, 2000) is not None
    with_id = verify(signed(good | {"m": "tailnet", "dev": "laptop", "id": "nEXAMPLE1CNTRL"}), owner(key), TOOLS, 2000)
    assert (with_id.device, with_id.device_id) == ("laptop", "nEXAMPLE1CNTRL")
    for bad in [
        good | {"extra": 1},
        {k: v for k, v in good.items() if k != "dev"},
        good | {"m": "admin"},
        good | {"m": "tailnet"},
        good | {"dev": "laptop"},
        good | {"exp": 5000.5},
        good | {"scope": ""},
        good | {"id": "nEXAMPLE1CNTRL"},
        good | {"m": "tailnet", "dev": "laptop", "id": ""},
        good | {"m": "tailnet", "dev": "laptop", "id": None},
    ]:
        assert verify(signed(bad), owner(key), TOOLS, 2000) is None, bad


def test_any_of_several_cookies_with_the_same_name_may_be_the_valid_one():
    key = session_key(SECRET, "line")
    assert first_valid(("junk", mint(session(), key)), owner(key), TOOLS, 2000) == session()
    assert first_valid(("junk", "tsg1.a.b"), owner(key), TOOLS, 2000) is None


# Passwords


def test_password_hash_round_trips_and_uses_the_documented_format():
    line = hash_password(PASSWORD, log_n=10)
    assert re.fullmatch(r"scrypt\$10\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+", line)
    parsed = parse_hash(line)
    assert parsed.matches(PASSWORD)
    assert not parsed.matches(PASSWORD + "x")
    assert parse_hash(hash_password(PASSWORD)).log_n == 15


@pytest.mark.parametrize("line", ["", "scrypt$10$8$1$c2FsdA==", "bcrypt$10$8$1$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoaGFzaA==", "scrypt$30$8$1$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoaGFzaA==", "scrypt$10$8$1$!!$aGFzaA=="])
def test_malformed_hash_lines_parse_to_none(line):
    assert parse_hash(line) is None


def test_passphrase_is_six_cvcv_groups_with_about_80_bits():
    phrases = {generate_passphrase() for _ in range(200)}
    assert len(phrases) == 200
    group = f"[{CONSONANTS}][{VOWELS}][{CONSONANTS}][{VOWELS}]"
    assert all(re.fullmatch("-".join([group] * GROUPS), p) for p in phrases)
    bits = GROUPS * math.log2((len(CONSONANTS) * len(VOWELS)) ** 2)
    assert 79 < bits < 82


# Open rules and next


def site(app, host=TOOLS):
    return app.config.sites[host]


@pytest.mark.parametrize(
    "method,path,expected",
    [
        ("GET", "/healthz", True),
        ("GET", "/healthz/", False),
        ("GET", "/healthzz", False),
        ("GET", "/api/items", True),
        ("DELETE", "/api/", True),
        ("GET", "/api", False),
        ("POST", "/report", True),
        ("GET", "/report", False),
        ("GET", "/api/../secret", False),
        ("GET", "/api/..", False),
        ("GET", "/api/%2e%2e/secret", False),
        ("GET", "/api/%2E%2E/secret", False),
        ("GET", "/api/..%2fsecret", False),
        ("GET", "/api/x%2Fy", False),
        ("GET", "/api/x%5cy", False),
        ("GET", "/api\\..\\secret", False),
        ("GET", "//x/api/secret", False),
        ("GET", "/api//x", False),
        ("GET", "/api/..;/secret", False),
        ("GET", "/api/x;y", False),
    ],
)
def test_open_rules_match_exact_prefix_and_method_and_refuse_traversal(gate, method, path, expected):
    assert is_open(site(gate), method, path) is expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("/notes/1?x=2", "/notes/1?x=2"),
        ("/", "/"),
        (None, "/"),
        ("", "/"),
        ("notes", "/"),
        ("//evil.example.net/", "/"),
        ("/\\evil.example.net", "/"),
        ("https://evil.example.net/", "/"),
        ("javascript:alert(1)", "/"),
        ("/\tevil", "/"),
        ("/.tailisman/login?next=/x", "/"),
        ("/\u4e2d", "/"),
    ],
)
def test_next_is_only_ever_a_same_host_path(text, expected):
    assert safe_next(text) == expected


@pytest.mark.parametrize(
    "text,error",
    [
        ('[[sites]]\nhost = "tools.example.com"\ncookie_domain = "ample.com"', "parent domain"),
        ('[[sites]]\nhost = "tools.example.com"\ncookie_domain = "com"', "parent domain"),
        ('[[sites]]\nhost = "tools.example.com"\nopen = ["/api*"]', "open rule"),
        ('[[sites]]\nhost = "tools.example.com"\nopen = ["/api/../x"]', ".. segment"),
        ('[[sites]]\nhost = "https://tools.example.com"', "DNS name"),
        ('[[sites]]\nhost = "tools.example.com"\ntailnet = "yes"', "tailnet must be true or false"),
        ('[[sites]]\nhost = "tools.example.com"\ntailisman_key = "tsk1.x"', "unknown key(s) at [[sites]]: tailisman_key"),
        ('issuer = "https://laptop.example-tailnet.ts.net:8443"\n[[sites]]\nhost = "tools.example.com"', "unknown key(s) at top level: issuer"),
        ('[tailnet]\nserve_host = "x.example-tailnet.ts.net"\n[[sites]]\nhost = "tools.example.com"', "[tailnet] devices is required"),
        ('[tailnet]\ndevices = ["laptop"]\n[[sites]]\nhost = "tools.example.com"', "[tailnet] serve_host must be"),
        ('[tailnet]\nlisten = "127.0.0.1:8471"\nserve_host = "x.example-tailnet.ts.net"\ndevices = ["laptop"]\n[[sites]]\nhost = "tools.example.com"', "must differ"),
        ('[[sites]]\nhost = "a.example.com"\n[[sites]]\nhost = "A.example.com."', "twice"),
    ],
)
def test_config_refuses_bad_sites(tmp_path, text, error):
    (tmp_path / "gate-secret").write_bytes(SECRET)
    head = 'session_secret_file = "gate-secret"\npassword_file = "gate-password"\n'
    path = tmp_path / "gate.toml"
    path.write_text(head + text)
    with pytest.raises(ConfigError, match=re.escape(error)):
        load_config(path)


def test_the_tailnet_table_makes_each_tailnet_site_an_audience_with_its_policy(tmp_path):
    (tmp_path / "gate-secret").write_bytes(SECRET)
    tailnet = {"serve_host": "Gate.Example-Tailnet.ts.net", "devices": ["laptop"], "users": ["owner@example.com"], "refuse_automation": True}
    sites = [{"host": TOOLS}, {"host": NOTES, "tailnet": False}, {"host": "files.example.com:8443"}]
    config = parse_config({"session_secret_file": "gate-secret", "password_file": "p", "tailnet": tailnet, "sites": sites}, base=tmp_path)
    assert config.tailnet.origin == "https://gate.example-tailnet.ts.net:8443"
    assert sorted(config.tailnet.checks.audiences) == ["https://files.example.com:8443", f"https://{TOOLS}"]
    audience = config.tailnet.checks.audiences[f"https://{TOOLS}"]
    assert (audience.devices, audience.users, audience.refuse_automation) == (frozenset({"laptop"}), frozenset({"owner@example.com"}), True)
    explicit = parse_config({"session_secret_file": "gate-secret", "password_file": "p", "tailnet": tailnet | {"origin": "https://gate.example-tailnet.ts.net:9443"}, "sites": sites}, base=tmp_path)
    assert explicit.tailnet.origin == "https://gate.example-tailnet.ts.net:9443"


# decide() through the verify route


def test_unknown_host_is_refused_even_with_a_valid_session(gate):
    cookie = cookie_from(post_login(gate, PASSWORD), "tailisman_gate")
    response = verify_request(gate, host="other.example.org", cookie=cookie)
    assert response.status == 401 and json.loads(response.body) == {"error": "unknown_host"}


def test_anonymous_navigation_is_sent_to_sign_in_with_the_original_uri(gate):
    response = verify_request(gate, uri="/notes/1?tab=a b")
    assert response.status == 302
    assert header(response, "Location") == ["/.tailisman/login?next=%2Fnotes%2F1%3Ftab%3Da%20b"]


def test_anonymous_api_call_gets_401(gate):
    response = verify_request(gate, uri="/data", accept="application/json")
    assert response.status == 401 and json.loads(response.body) == {"error": "sign_in_required"}
    assert verify_request(gate, uri="/data", method="POST").status == 401


def test_a_leading_double_slash_is_not_read_as_a_host(gate):
    request = GateRequest(host=TOOLS, method="GET", uri="//x/api/secret?q=1", cookies=(), accepts_html=False)
    assert decide(request, gate.config, lambda *_: None, 0) == Unauthorised("sign_in_required")


def test_open_rule_lets_an_anonymous_request_through_but_not_a_traversal(gate):
    assert verify_request(gate, uri="/api/items?x=1", accept="*/*").status == 200
    assert verify_request(gate, uri="/api/../secret", accept="*/*").status == 401


def test_decide_is_pure_over_its_inputs(gate):
    request = GateRequest(host=TOOLS, method="GET", uri="/", cookies=("x",), accepts_html=True)
    found = session()
    assert decide(request, gate.config, lambda cookies, host, now, path: found, 0) == Allow(found)
    assert decide(request, gate.config, lambda *_: None, 0) == SignIn("/.tailisman/login?next=%2F")
    assert decide(GateRequest(TOOLS, "", "", (), True), gate.config, lambda *_: None, 0) == Unauthorised("not_from_forward_auth")


# Password sign-in


def test_password_sign_in_sets_a_parent_domain_cookie_that_verify_accepts(gate):
    response = post_login(gate, PASSWORD, next_path="/notes/1")
    assert response.status == 303 and header(response, "Location") == ["/notes/1"]
    set_cookie = [c for c in header(response, "Set-Cookie") if c.startswith("tailisman_gate=")][0]
    assert "; Max-Age=2592000; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax" in set_cookie
    assert any(c.startswith("tailisman_csrf=; Max-Age=0") for c in header(response, "Set-Cookie"))
    cookie = cookie_from(response, "tailisman_gate")
    allowed = verify_request(gate, cookie=cookie)
    assert allowed.status == 200 and header(allowed, "X-Tailisman-Session") == ["password"]
    assert verify_request(gate, host=NOTES, cookie=cookie).status == 200
    assert verify_request(gate, host=SOLO, cookie=cookie).status == 302


def test_a_host_only_site_sets_a_cookie_without_domain(gate):
    response = post_login(gate, PASSWORD, host=SOLO)
    set_cookie = [c for c in header(response, "Set-Cookie") if c.startswith("tailisman_gate=")][0]
    assert "Domain" not in set_cookie
    assert verify_request(gate, host=SOLO, cookie=cookie_from(response, "tailisman_gate")).status == 200


def test_wrong_password_gets_401_and_one_generic_message(gate, tmp_path):
    response = post_login(gate, "wrong password")
    assert response.status == 401 and b"That password did not work." in response.body
    assert cookie_from(response, "tailisman_gate") is None
    (tmp_path / "gate-password").unlink()
    missing = post_login(gate, "wrong password", ip="198.51.100.2")
    assert missing.status == 401 and b"That password did not work." in missing.body


def test_login_page_says_when_the_password_path_is_off(tmp_path):
    app = GateApp(load_config(write_gate_dir(tmp_path, password=None)))
    page = call(app, "GET", "/.tailisman/login")
    assert page.status == 200 and b"Password sign-in is not set up" in page.body and b"type=password" not in page.body
    (tmp_path / "gate-password").write_text("not a hash\n")
    assert b"not set up" in call(app, "GET", "/.tailisman/login").body
    (tmp_path / "gate-password").write_text(hash_password(PASSWORD, log_n=10) + "\n")
    assert b"type=password" in call(app, "GET", "/.tailisman/login").body


def test_login_page_headers_and_tailnet_script(gate):
    page = call(gate, "GET", "/.tailisman/login?next=/x")
    csp = header(page, "Content-Security-Policy")[0]
    assert f"connect-src 'self' {TAILNET}" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert header(page, "Referrer-Policy") == ["same-origin"] and header(page, "Cache-Control") == ["no-store"]
    assert b'src="/.tailisman/login.js"' in page.body and b'data-next="/x"' in page.body
    assert b"<script>" not in page.body
    csrf_cookie = [c for c in header(page, "Set-Cookie") if c.startswith("tailisman_csrf=")][0]
    assert csrf_cookie.endswith("; Path=/.tailisman/; Secure; HttpOnly; SameSite=Strict")
    no_tailnet = call(gate, "GET", "/.tailisman/login", host=NOTES)
    assert b"login.js" not in no_tailnet.body and f"connect-src 'self';" in header(no_tailnet, "Content-Security-Policy")[0]


def test_login_page_with_a_valid_session_goes_straight_to_next(gate):
    cookie = cookie_from(post_login(gate, PASSWORD), "tailisman_gate")
    response = call(gate, "GET", "/.tailisman/login?next=/notes", Cookie=f"tailisman_gate={cookie}")
    assert response.status == 303 and header(response, "Location") == ["/notes"]


@pytest.mark.parametrize("case", ["no cookie", "mismatch", "no field", "cross origin"])
def test_csrf_refusals(gate, case):
    token, _ = login_form(gate)
    cookie = {"no cookie": "", "mismatch": "tailisman_csrf=" + "A" * 32}.get(case, f"tailisman_csrf={token}")
    fields = {"password": PASSWORD} | ({} if case == "no field" else {"csrf": token})
    extra = {"Cookie": cookie, "CF_Connecting_IP": "198.51.100.3"}
    if case == "cross origin":
        extra["Origin"] = "https://evil.example.net"
    response = call(gate, "POST", "/.tailisman/login", body=urlencode(fields).encode(), **extra)
    assert response.status == 403 and cookie_from(response, "tailisman_gate") is None


def test_same_origin_post_is_accepted(gate):
    assert post_login(gate, PASSWORD, origin=f"https://{TOOLS}").status == 303


def test_rate_limit_per_ip_refuses_without_running_scrypt(gate, monkeypatch):
    for _ in range(3):
        assert post_login(gate, "wrong", ip="198.51.100.7").status == 401
    calls = []
    original = PasswordHash.matches
    monkeypatch.setattr(PasswordHash, "matches", lambda self, pw: calls.append(pw) or original(self, pw))
    limited = post_login(gate, PASSWORD, ip="198.51.100.7")
    assert limited.status == 429 and int(header(limited, "Retry-After")[0]) > 0 and calls == []
    assert post_login(gate, PASSWORD, ip="198.51.100.8").status == 303
    gate.clock_ref.now += 901
    assert post_login(gate, PASSWORD, ip="198.51.100.7").status == 303


def test_global_rate_limit_counts_failures_from_every_ip_and_a_success_does_not_reset_it(gate):
    for i in range(4):
        assert post_login(gate, "wrong", ip=f"198.51.100.{20 + i}").status == 401
    assert post_login(gate, PASSWORD, ip="198.51.100.30").status == 303
    assert post_login(gate, "wrong", ip="198.51.100.31").status == 401
    assert post_login(gate, PASSWORD, ip="198.51.100.32").status == 429


def test_changing_the_password_file_signs_existing_sessions_out(gate, tmp_path):
    cookie = cookie_from(post_login(gate, PASSWORD), "tailisman_gate")
    assert verify_request(gate, cookie=cookie).status == 200
    path = tmp_path / "gate-password"
    path.write_text(hash_password("a new password!", log_n=10) + "\n")
    os.utime(path, ns=(os.stat(path).st_atime_ns, os.stat(path).st_mtime_ns + 1_000_000))
    assert verify_request(gate, cookie=cookie).status == 302
    assert post_login(gate, "a new password!", ip="198.51.100.40").status == 303


def test_expired_session_is_refused(gate):
    cookie = cookie_from(post_login(gate, PASSWORD), "tailisman_gate")
    gate.clock_ref.now += 30 * 86400
    assert verify_request(gate, cookie=cookie).status == 302


# Tailnet exchange, session page, sign out


SERVE = {"Host": f"{SERVE_HOST}:8443", "X-Forwarded-Host": f"{SERVE_HOST}:8443", "X-Forwarded-For": "192.0.2.1", "X-Forwarded-Proto": "https", "Tailscale-User-Login": "owner@example.com"}


def tailnet_answer(app, origin=f"https://{TOOLS}", peer="192.0.2.1", path="/v1/claim", extra=None):
    """Asks the gate's tailnet listener, through the same headers tailscale serve sets."""
    listener = app.tailnet_app(lambda ip: PEERS.get(ip))
    response, _ = listener.respond("GET", path, headers(SERVE | {"X-Forwarded-For": peer, "Origin": origin} | (extra or {})))
    return response


def code_for(app, origin=f"https://{TOOLS}"):
    return json.loads(tailnet_answer(app, origin).body)["token"]


def exchange(app, code, host=TOOLS, path="/.tailisman/exchange"):
    return call(app, "POST", path, host=host, body=json.dumps({"token": code}).encode(), Content_Type="application/json")


def test_the_tailnet_listener_answers_an_opaque_one_time_code_with_the_issuers_cors(gate):
    response = tailnet_answer(gate)
    code = json.loads(response.body)["token"]
    assert response.status == 200 and re.fullmatch(r"[A-Za-z0-9_-]{43}", code)
    assert header(response, "Access-Control-Allow-Origin") == [f"https://{TOOLS}"]
    assert code_for(gate) != code


@pytest.mark.parametrize(
    "origin,peer,extra,error",
    [
        (f"https://{NOTES}", "192.0.2.1", {}, "unknown_audience"),
        (f"https://{TOOLS}", "192.0.2.2", {}, "not_on_allowlist"),
        (f"https://{TOOLS}", "192.0.2.4", {}, "tagged_node"),
        (f"https://{TOOLS}", "192.0.2.1", {"Tailscale-Funnel-Request": "?1"}, "funnel_request"),
        (f"https://{TOOLS}", "192.0.2.1", {"Host": "evil.example.net"}, "wrong_host"),
    ],
)
def test_the_tailnet_listener_runs_the_issuers_device_checks(gate, origin, peer, extra, error):
    response = tailnet_answer(gate, origin, peer, extra=extra)
    assert json.loads(response.body) == {"error": error}


def test_exchange_turns_a_code_into_a_tailnet_session_once(gate):
    token = code_for(gate)
    body = json.dumps({"token": token}).encode()
    response = call(gate, "POST", "/.tailisman/exchange?next=/notes", body=body, Content_Type="application/json")
    assert response.status == 200 and json.loads(response.body) == {"device": "laptop", "next": "/notes"}
    cookie = cookie_from(response, "tailisman_gate")
    allowed = verify_request(gate, cookie=cookie)
    assert header(allowed, "X-Tailisman-Session") == ["tailnet"]
    assert json.loads(base64.urlsafe_b64decode(cookie.split(".")[1] + "==")) == {"m": "tailnet", "dev": "laptop", "scope": "example.com", "iat": 1_800_000_000, "exp": 1_800_000_000 + 30 * 86400, "id": "nEXAMPLE1CNTRL"}
    again = call(gate, "POST", "/.tailisman/exchange", body=body, Content_Type="application/json")
    assert again.status == 403 and json.loads(again.body) == {"error": "replayed"}


def test_the_navigation_path_posts_a_code_back_and_gets_a_redirect(gate):
    start = tailnet_answer(gate, path=f"/v1/start?return_to=https://{TOOLS}/.tailisman/exchange?next=/notes")
    code = re.search(rb'name=token value="([^"]+)"', start.body).group(1).decode()
    form = urlencode({"token": code}).encode()
    response = call(gate, "POST", "/.tailisman/exchange?next=//evil.example.net", body=form, Content_Type="application/x-www-form-urlencoded")
    assert response.status == 303 and header(response, "Location") == ["/"]


def test_a_code_is_refused_when_unknown_expired_or_for_another_site(gate, tmp_path):
    assert json.loads(exchange(gate, "A" * 43).body) == {"error": "malformed"}
    late = code_for(gate)
    gate.clock_ref.now += 60
    assert json.loads(exchange(gate, late).body) == {"error": "expired"}
    path = tmp_path / "two.toml"
    path.write_text(CONFIG.replace('tailnet = false\n\n[[sites]]\nhost = "solo', '\n[[sites]]\nhost = "solo'))
    app = GateApp(load_config(path), clock=gate.clock_ref)
    elsewhere = code_for(app, origin=f"https://{TOOLS}")
    assert json.loads(exchange(app, elsewhere, host=NOTES).body) == {"error": "wrong_audience"}
    assert json.loads(exchange(app, elsewhere, host=TOOLS).body) == {"error": "replayed"}
    assert exchange(gate, code_for(gate), host=SOLO).status == 404


def test_session_page_and_sign_out(gate):
    cookie = cookie_from(post_login(gate, PASSWORD), "tailisman_gate")
    anonymous = call(gate, "GET", "/.tailisman/")
    assert b"Not signed in" in anonymous.body
    page = call(gate, "GET", "/.tailisman/", Cookie=f"tailisman_gate={cookie}")
    assert b"Signed in with the password, until 14 Feb 2027, 08:00 UTC." in page.body
    csrf = cookie_from(page, "tailisman_csrf")
    refused = call(gate, "POST", "/.tailisman/logout", body=b"csrf=" + b"A" * 32, Cookie=f"tailisman_gate={cookie}; tailisman_csrf={csrf}")
    assert refused.status == 403
    out = call(gate, "POST", "/.tailisman/logout", body=f"csrf={csrf}".encode(), Cookie=f"tailisman_gate={cookie}; tailisman_csrf={csrf}")
    assert out.status == 303 and header(out, "Location") == ["/.tailisman/login?signed_out=1"]
    after = call(gate, "GET", "/.tailisman/login?signed_out=1")
    assert b"You are signed out." in after.body and b'data-silent="0"' in after.body
    assert b'data-silent="1"' in call(gate, "GET", "/.tailisman/login").body
    clears = sorted(c for c in header(out, "Set-Cookie") if c.startswith("tailisman_gate=;"))
    assert clears == [
        "tailisman_gate=; Max-Age=0; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax",
        "tailisman_gate=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
    ]


def test_static_files_and_health(gate):
    assert call(gate, "GET", "/.tailisman/healthz", host="anything.example.org").body == b"ok\n"
    snippet = call(gate, "GET", "/.tailisman/tailisman.js")
    assert snippet.status == 200 and b"export async function claim" in snippet.body
    assert b'from "/.tailisman/tailisman.js"' in call(gate, "GET", "/.tailisman/login.js").body
    assert call(gate, "GET", "/.tailisman/nope").status == 404
    assert call(gate, "GET", "/.tailisman/login", host="other.example.org").status == 404


# passwd


def test_passwd_prompts_and_writes_a_private_hash(tmp_path, monkeypatch, capsys):
    config = write_gate_dir(tmp_path, password=None)
    answers = iter([PASSWORD, PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert main(["passwd", "--config", str(config)]) == 0
    path = tmp_path / "gate-password"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert parse_hash(path.read_text()).matches(PASSWORD)
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err and path.read_text().strip() not in out.out + out.err
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_passwd_refuses_mismatch_and_short_passwords(tmp_path, monkeypatch):
    config = write_gate_dir(tmp_path, password=None)
    for answers in ([PASSWORD, PASSWORD + "x"], ["short", "short"]):
        replies = iter(answers)
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(replies))
        assert main(["passwd", "--config", str(config)]) == 1
    assert not (tmp_path / "gate-password").exists()


def test_passwd_generate_writes_both_files_private_and_never_prints_them(tmp_path, capsys):
    config = write_gate_dir(tmp_path, password=None)
    out = tmp_path / "passphrase"
    assert main(["passwd", "--config", str(config), "--generate", "--out", str(out)]) == 0
    phrase = out.read_text().strip()
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600 and stat.S_IMODE(os.stat(tmp_path / "gate-password").st_mode) == 0o600
    assert parse_hash((tmp_path / "gate-password").read_text()).matches(phrase)
    printed = capsys.readouterr()
    assert phrase not in printed.out + printed.err and "$" not in printed.out
    hash_before = (tmp_path / "gate-password").read_text()
    assert main(["passwd", "--config", str(config), "--generate", "--out", str(out)]) == 1
    assert out.read_text().strip() == phrase and (tmp_path / "gate-password").read_text() == hash_before
    assert main(["passwd", "--config", str(config), "--generate", "--out", str(out), "--force"]) == 0
    assert out.read_text().strip() != phrase


def test_passwd_generate_needs_out(tmp_path, capsys):
    config = write_gate_dir(tmp_path, password=None)
    assert main(["passwd", "--config", str(config), "--generate"]) == 2
    assert "--out" in capsys.readouterr().err


# Cookies minted before guests existed


GOLDEN_LINE = "scrypt$10$8$1$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoaGFzaA=="
GOLDEN_PASSWORD_COOKIE = "tsg1.eyJtIjoicGFzc3dvcmQiLCJkZXYiOm51bGwsInNjb3BlIjoiZXhhbXBsZS5jb20iLCJpYXQiOjE4MDAwMDAwMDAsImV4cCI6MTgwMjU5MjAwMH0.viL96Tr54ToIcgBswYE6TAGaM8HhjW1kre54dpIqkno"
GOLDEN_TAILNET_COOKIE = "tsg1.eyJtIjoidGFpbG5ldCIsImRldiI6ImxhcHRvcCIsInNjb3BlIjoidG9vbHMuZXhhbXBsZS5jb20iLCJpYXQiOjE4MDAwMDAwMDAsImV4cCI6MTgwMjU5MjAwMH0.1KNr_6EUOWZaUWIszRqGSR0AvOr4XeT_6wcUDE-hnbc"


def test_owner_cookies_minted_by_the_released_gate_still_verify(gate, tmp_path):
    (tmp_path / "gate-password").write_text(GOLDEN_LINE + "\n")
    allowed = verify_request(gate, host=NOTES, cookie=GOLDEN_PASSWORD_COOKIE)
    assert allowed.status == 200 and header(allowed, "X-Tailisman-Session") == ["password"]
    tailnet = verify_request(gate, cookie=GOLDEN_TAILNET_COOKIE)
    assert tailnet.status == 200 and header(tailnet, "X-Tailisman-Session") == ["tailnet"]
    assert verify_request(gate, host=NOTES, cookie=GOLDEN_TAILNET_COOKIE).status == 302


def test_a_password_piped_from_its_file_signs_in_despite_the_trailing_newline(gate):
    assert post_login(gate, PASSWORD + "\n").status == 303
    assert post_login(gate, PASSWORD + "\r\n", ip="198.51.100.3").status == 303
    assert post_login(gate, PASSWORD + "\n\n", ip="198.51.100.4").status == 401
