import html
import json
import re
from urllib.parse import quote

import pytest

from tailisman import Verifier
from tailisman._token import derive_consumer_key, format_key

from tailisman.issuer.cli import app_for
from tailisman.issuer.config import ConfigError, load_config

from conftest import SERVE_HOST, SERVE_HOST_HEADER, Issuer, UnixHTTPConnection, write_issuer_dir

HECKLE = "https://heckle.example.com"
NOTES = "https://notes.example.com"
DEMO = "http://localhost:8080"


def verifier_for(issuer, origin):
    return Verifier(key=format_key(derive_consumer_key(issuer.config.master, origin)), audience=origin)


def claim(issuer, origin=HECKLE, query="a=0", **kwargs):
    response, body = issuer.request("GET", f"/v1/claim?{query}", origin=origin, **kwargs)
    return response, json.loads(body)


def test_allowlisted_device_gets_a_token_the_verifier_accepts(issuer):
    response, body = claim(issuer)
    assert response.status == 200
    assert response.getheader("Access-Control-Allow-Origin") == HECKLE
    assert response.getheader("Vary") == "Origin"
    assert response.getheader("Access-Control-Allow-Private-Network") == "true"
    assert response.getheader("Cache-Control") == "no-store"
    verified = verifier_for(issuer, HECKLE).verify(body["token"])
    assert (verified.node_id, verified.node_name, verified.login, verified.audience) == ("nEXAMPLE1CNTRL", "laptop", "owner@example.com", HECKLE)
    assert verified.expires_at - verified.issued_at == 60


def test_token_for_one_audience_fails_under_another_audience_key(issuer):
    _, body = claim(issuer, origin=HECKLE)
    with pytest.raises(Exception) as caught:
        verifier_for(issuer, DEMO).verify(body["token"])
    assert caught.value.code == "bad_signature"


@pytest.mark.parametrize("peer,how", [
    ("192.0.2.1", "short name"),
    ("192.0.2.2", "stable ID"),
    ("192.0.2.5", "MagicDNS name with trailing dot"),
    ("192.0.2.6", "MagicDNS name without trailing dot"),
])
def test_allowlist_entries_match(issuer, peer, how):
    response, _ = claim(issuer, peer=peer)
    assert response.status == 200, how


@pytest.mark.parametrize("peer,code", [
    ("192.0.2.3", "not_on_allowlist"),
    ("192.0.2.4", "tagged_node"),
    ("192.0.2.99", "unknown_peer"),
])
def test_refused_peers(issuer, peer, code):
    response, body = claim(issuer, peer=peer)
    assert (response.status, body) == (403, {"error": code})
    assert response.getheader("Access-Control-Allow-Origin") == HECKLE


def test_unknown_origin_gets_403_and_no_cors(issuer):
    response, body = claim(issuer, origin="https://evil.example.com")
    assert (response.status, body) == (403, {"error": "unknown_audience"})
    assert response.getheader("Access-Control-Allow-Origin") is None


def test_missing_origin_is_unknown_audience(issuer):
    response, body = claim(issuer, origin=None)
    assert body == {"error": "unknown_audience"}


@pytest.mark.parametrize("headers", [
    {"X-Forwarded-For": None},
    {"X-Forwarded-Proto": None},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-For": "1.2.3.4, 192.0.2.1"},
    {"X-Forwarded-For": "not-an-ip"},
])
def test_requests_not_from_serve_get_421(issuer, headers):
    response, body = claim(issuer, headers=headers)
    assert (response.status, body) == (421, {"error": "not_behind_serve"})


def test_repeated_forwarded_for_headers_get_421(issuer):
    conn = issuer.connect()
    conn.putrequest("GET", "/v1/claim", skip_host=True)
    for name, value in [("Host", SERVE_HOST_HEADER), ("Origin", HECKLE), ("X-Forwarded-Proto", "https"), ("X-Forwarded-For", "192.0.2.1"), ("X-Forwarded-For", "192.0.2.2")]:
        conn.putheader(name, value)
    conn.endheaders()
    response = conn.getresponse()
    assert (response.status, json.loads(response.read())) == (421, {"error": "not_behind_serve"})


REBOUND = "attacker.example:8443"


@pytest.mark.parametrize("path", ["/v1/claim", f"/v1/start?return_to={quote(HECKLE + '/auth')}", "/"])
@pytest.mark.parametrize("headers", [
    {"Host": REBOUND, "X-Forwarded-Host": None},
    {"Host": REBOUND},
    {"X-Forwarded-Host": REBOUND},
    {"Host": "127.0.0.1:8470", "X-Forwarded-Host": None},
    {"Host": f"{SERVE_HOST}.attacker.example"},
    {"Host": f"x@{SERVE_HOST}"},
])
def test_a_request_for_any_other_host_is_refused(issuer, path, headers):
    response, body = issuer.request("GET", path, origin=HECKLE, headers=headers)
    assert response.status == 421 and b"wrong_host" in body and b"tsm1." not in body


@pytest.mark.parametrize("host", [SERVE_HOST, SERVE_HOST.upper() + ":443", SERVE_HOST + ".:8443"])
def test_the_serve_host_matches_without_case_or_port(issuer, host):
    response, _ = claim(issuer, headers={"Host": host, "X-Forwarded-Host": host})
    assert response.status == 200


def test_x_forwarded_host_is_optional(issuer):
    assert claim(issuer, headers={"X-Forwarded-Host": None})[0].status == 200


def test_missing_or_repeated_host_is_refused(issuer):
    for hosts in ([], [SERVE_HOST_HEADER, SERVE_HOST_HEADER]):
        conn = issuer.connect()
        conn.putrequest("GET", "/v1/claim", skip_host=True)
        for name, value in [("Origin", HECKLE), ("X-Forwarded-Proto", "https"), ("X-Forwarded-For", "192.0.2.1")] + [("Host", h) for h in hosts]:
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        assert (response.status, json.loads(response.read())) == (421, {"error": "wrong_host"})


def test_wrong_host_comes_before_every_other_refusal(issuer):
    assert claim(issuer, origin="https://evil.example.com", headers={"Host": REBOUND, "X-Forwarded-For": None})[1] == {"error": "wrong_host"}


def test_healthz_answers_any_host(issuer):
    assert issuer.request("GET", "/healthz", headers={"Host": REBOUND})[0].status == 200


def test_serve_host_comes_from_tailscale_status_or_the_config(short_tmp, monkeypatch):
    monkeypatch.setenv("FAKE_TAILSCALE_STATE", str(short_tmp / "state.json"))
    assert app_for(load_config(write_issuer_dir(short_tmp, status={"Self": {"DNSName": "Issuer.Example-Tailnet.ts.net."}}))).serve_host == SERVE_HOST
    configured = write_issuer_dir(short_tmp, status={}, extra='serve_host = "other.example-tailnet.ts.net."\n')
    assert app_for(load_config(configured)).serve_host == "other.example-tailnet.ts.net"
    with pytest.raises(ConfigError, match="set serve_host"):
        app_for(load_config(write_issuer_dir(short_tmp, status={})))


def test_funnel_traffic_is_refused(issuer):
    response, body = claim(issuer, headers={"Tailscale-Funnel-Request": "?1"})
    assert body == {"error": "funnel_request"}


def test_refusal_order_puts_serve_checks_before_audience(issuer):
    assert claim(issuer, origin="https://evil.example.com", headers={"Tailscale-Funnel-Request": "?1"})[1] == {"error": "funnel_request"}
    assert claim(issuer, origin="https://evil.example.com", headers={"X-Forwarded-Proto": None})[1] == {"error": "not_behind_serve"}
    assert claim(issuer, origin="https://evil.example.com", peer="192.0.2.99")[1] == {"error": "unknown_audience"}


def test_login_header_must_match_whois(issuer):
    response, body = claim(issuer, login="intruder@example.com")
    assert body == {"error": "identity_mismatch"}


def test_user_restriction(issuer):
    assert claim(issuer, origin=NOTES, peer="192.0.2.5")[1] == {"error": "user_not_allowed"}
    assert claim(issuer, origin=HECKLE, peer="192.0.2.5")[0].status == 200


def test_refuse_automation_by_flag_and_by_user_agent(issuer):
    assert claim(issuer, origin=NOTES, query="a=1")[1] == {"error": "automation"}
    assert claim(issuer, origin=NOTES, headers={"User-Agent": "Mozilla/5.0 HeadlessChrome/155.0"})[1] == {"error": "automation"}
    assert claim(issuer, origin=NOTES, query="a=0")[0].status == 200
    assert claim(issuer, origin=HECKLE, query="a=1")[0].status == 200


def test_preflight(issuer):
    response, _ = issuer.request("OPTIONS", "/v1/claim", origin=HECKLE, headers={"Access-Control-Request-Method": "GET", "Access-Control-Request-Private-Network": "true"})
    assert response.status == 204
    assert response.getheader("Access-Control-Allow-Origin") == HECKLE
    assert response.getheader("Access-Control-Allow-Private-Network") == "true"
    response, _ = issuer.request("OPTIONS", "/v1/claim", origin="https://evil.example.com")
    assert response.status == 403 and response.getheader("Access-Control-Allow-Origin") is None


def test_start_renders_a_self_submitting_form_to_return_to(issuer):
    return_to = f"{DEMO}/auth/tailisman"
    response, body = issuer.request("GET", f"/v1/start?return_to={quote(return_to)}&a=0")
    page = body.decode()
    assert response.status == 200
    assert f'<form method=post action="{return_to}">' in page
    token = html.unescape(re.search(r'name=token value="([^"]+)"', page).group(1))
    assert verifier_for(issuer, DEMO).verify(token).node_name == "laptop"
    assert response.getheader("Referrer-Policy") == "no-referrer"
    csp = response.getheader("Content-Security-Policy")
    script = re.search(r"<script>(.*?)</script>", page).group(1)
    import base64, hashlib
    assert f"'sha256-{base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()}'" in csp
    assert f"form-action {DEMO}" in csp
    assert "<button type=submit>" in page


@pytest.mark.parametrize("return_to", [
    "https://evil.example.com/auth",
    "javascript:alert(1)",
    "/auth/tailisman",
    "",
    "https://heckle.example.com@evil.example/",
    "http://heckle.example.com/auth/tailisman",
    "https://heckle.example.com\\@evil.example",
    "https://heckle.example.com:8443/auth/tailisman",
    "//heckle.example.com/auth/tailisman",
])
def test_start_refuses_return_to_outside_the_audiences(issuer, return_to):
    response, body = issuer.request("GET", f"/v1/start?return_to={quote(return_to)}")
    assert response.status == 403
    assert b"unknown_audience" in body and b"<form" not in body


def test_start_refusal_links_back_to_the_audience(issuer):
    response, body = issuer.request("GET", f"/v1/start?return_to={quote(HECKLE + '/x')}", peer="192.0.2.3")
    assert response.status == 403
    assert b"not_on_allowlist" in body and f'href="{HECKLE}"'.encode() in body


def test_status_page_for_a_device_no_site_accepts_shows_only_its_identity(issuer):
    response, body = issuer.request("GET", "/", peer="192.0.2.3")
    page = body.decode()
    assert response.status == 200
    assert "tablet" in page and "nEXAMPLE3CNTRL" in page
    assert html.escape('devices = ["nEXAMPLE3CNTRL"]  # tablet') in page
    assert "example.com" not in page.replace("owner@example.com", "") and "localhost" not in page


def test_status_page_for_an_allowed_device_lists_accepting_sites(issuer):
    page = issuer.request("GET", "/", peer="192.0.2.1")[1].decode()
    assert f"{HECKLE}: accepts" in page
    assert "devices = [" not in page


def test_status_page_escapes_html(issuer):
    page = issuer.request("GET", "/", peer="192.0.2.7")[1].decode()
    assert "evil&lt;script&gt;x" in page
    assert "<script>" not in page


def test_status_page_shows_tagged_devices_their_identity_only(issuer):
    page = issuer.request("GET", "/", peer="192.0.2.4")[1].decode()
    assert "tag:server" in page and "always refused" in page
    assert "heckle" not in page and "devices = [" not in page


def test_status_page_lists_sites_for_a_device_some_site_accepts(issuer):
    page = issuer.request("GET", "/", peer="192.0.2.5")[1].decode()
    assert f"{HECKLE}: accepts" in page and f"{NOTES}: refuses: user_not_allowed" in page


def test_healthz_needs_no_identity(issuer):
    response, body = issuer.request("GET", "/healthz", serve=False)
    assert (response.status, body) == (200, b"ok\n")


def test_unknown_route_and_method(issuer):
    assert issuer.request("GET", "/nope")[0].status == 404
    assert issuer.request("POST", "/v1/claim", origin=HECKLE)[0].status == 405


def test_unix_socket_listener(short_tmp, monkeypatch):
    import os, stat

    monkeypatch.setenv("FAKE_TAILSCALE_STATE", str(short_tmp / "state.json"))
    sock = short_tmp / "issuer.sock"
    sock.write_text("")
    with pytest.raises(SystemExit):
        Issuer(write_issuer_dir(short_tmp, listen=f"unix:{sock}"))
    sock.unlink()
    running = Issuer(write_issuer_dir(short_tmp, listen=f"unix:{sock}"))
    try:
        assert stat.S_IMODE(os.stat(sock).st_mode) == 0o660
        conn = UnixHTTPConnection(str(sock))
        conn.request("GET", "/v1/claim", headers={"Host": SERVE_HOST_HEADER, "Origin": HECKLE, "X-Forwarded-For": "192.0.2.1", "X-Forwarded-Proto": "https"})
        response = conn.getresponse()
        assert response.status == 200 and json.loads(response.read())["token"].startswith("tsm1.")
    finally:
        running.close()


def test_unix_socket_is_never_looser_than_0660(short_tmp, monkeypatch):
    import os, stat
    from tailisman.issuer import http as issuer_http

    monkeypatch.setenv("FAKE_TAILSCALE_STATE", str(short_tmp / "state.json"))
    sock = short_tmp / "issuer.sock"
    modes = []
    bind = issuer_http._ThreadingUnixHTTPServer.server_bind

    def observed_bind(self):
        bind(self)
        modes.append(stat.S_IMODE(os.stat(sock).st_mode))

    monkeypatch.setattr(issuer_http._ThreadingUnixHTTPServer, "server_bind", observed_bind)
    previous = os.umask(0)
    try:
        running = Issuer(write_issuer_dir(short_tmp, listen=f"unix:{sock}"))
    finally:
        os.umask(previous)
    running.close()
    assert modes and modes[0] & 0o007 == 0
