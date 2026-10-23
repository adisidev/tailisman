import http.client
import io
import re

import pytest
from test_gate import SECRET, headers

from tailisman.gate.config import ConfigError, parse_config
from tailisman.gate.decision import GateRequest
from tailisman.gate.proxy import BadRequest, body_length, check_header_values, client_headers, is_websocket, upstream_headers


def config_with(tmp_path, upstream):
    (tmp_path / "gate-secret").write_bytes(SECRET)
    raw = {"session_secret_file": "gate-secret", "password_file": "p", "sites": [{"host": "app.example.com", "upstream": upstream}]}
    return parse_config(raw, base=tmp_path)


@pytest.mark.parametrize("text,shown", [("http://127.0.0.1:9000", "http://127.0.0.1:9000"), ("http://localhost:8080/", "http://localhost:8080"), ("http://[::1]:9000", "http://[::1]:9000")])
def test_upstream_is_an_http_origin(tmp_path, text, shown):
    assert str(config_with(tmp_path, text).sites["app.example.com"].upstream) == shown


@pytest.mark.parametrize(
    "text,error",
    [
        ("https://127.0.0.1:9000", "speaks plain HTTP"),
        ("http://127.0.0.1:9000/app", "a path, query or fragment is not allowed"),
        ("http://127.0.0.1:9000?x=1", "a path, query or fragment is not allowed"),
        ("http://user:pw@127.0.0.1:9000", "a user name or password is not allowed"),
        ("http://127.0.0.1", "must be http://HOST:PORT"),
        ("127.0.0.1:9000", "must be http://HOST:PORT"),
        ("http://127.0.0.1:99999", "must be http://HOST:PORT"),
        (9000, "must be http://HOST:PORT"),
    ],
)
def test_upstream_refuses_anything_but_http_host_port(tmp_path, text, error):
    with pytest.raises(ConfigError, match=re.escape(error)):
        config_with(tmp_path, text)


def test_a_proxied_request_is_judged_by_its_own_request_line_not_forwarded_headers():
    request = GateRequest.from_request("get", "/secret", headers({"Host": "App.example.com", "X-Forwarded-Uri": "/public/x", "X-Forwarded-Method": "GET"}))
    assert (request.host, request.method, request.uri) == ("app.example.com", "GET", "/secret")


def test_upstream_headers_drop_hop_by_hop_gate_cookies_and_client_identity():
    sent = headers({
        "Host": "app.example.com",
        "Connection": "keep-alive, X-Secret-Hop",
        "X-Secret-Hop": "1",
        "Keep-Alive": "timeout=5",
        "Proxy-Authorization": "Basic x",
        "TE": "trailers",
        "Trailer": "X-Sum",
        "Upgrade": "h2c",
        "Expect": "100-continue",
        "Cookie": "tailisman_gate=tsg1.a.b; theme=dark; tailisman_csrf=c",
        "X-Tailisman-Session": "password",
        "x-tailisman-user": "owner",
        "X-Forwarded-For": "203.0.113.5",
        "X-Forwarded-Host": "evil.example.net",
        "Accept": "text/html",
    })
    forwarded = upstream_headers(sent, (("X-Tailisman-Session", "guest"), ("X-Tailisman-User", "alice")), "127.0.0.1", 10, websocket=False)
    assert forwarded == [
        ("Host", "app.example.com"),
        ("Cookie", "theme=dark"),
        ("Accept", "text/html"),
        ("X-Forwarded-For", "203.0.113.5, 127.0.0.1"),
        ("X-Forwarded-Proto", "https"),
        ("X-Forwarded-Host", "app.example.com"),
        ("X-Tailisman-Session", "guest"),
        ("X-Tailisman-User", "alice"),
        ("Content-Length", "10"),
    ]


def test_a_request_with_only_gate_cookies_reaches_the_app_with_no_cookie_header():
    forwarded = upstream_headers(headers({"Host": "a.example.com", "Cookie": "tailisman_gate=x"}), (), "127.0.0.1", None, websocket=False)
    assert [name for name, _ in forwarded] == ["Host", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"]


def test_a_websocket_upgrade_keeps_its_upgrade_and_a_chunked_body_is_rechunked():
    upgrade = headers({"Host": "a.example.com", "Connection": "keep-alive, Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": "k"})
    assert is_websocket(upgrade)
    forwarded = upstream_headers(upgrade, (), "127.0.0.1", None, websocket=True)
    assert forwarded[-2:] == [("Connection", "Upgrade"), ("Upgrade", "websocket")] and ("Sec-WebSocket-Key", "k") in forwarded
    assert not is_websocket(headers({"Upgrade": "websocket"}))
    chunked = headers({"Transfer-Encoding": "chunked", "Content-Length": "5"})
    assert body_length(chunked) == "chunked"
    assert upstream_headers(chunked, (), "p", "chunked", websocket=False)[-1] == ("Transfer-Encoding", "chunked")


def test_client_headers_apply_the_private_cache_rule_and_keep_set_cookie_lines():
    assert client_headers([("Content-Type", "text/plain")]) == [("Content-Type", "text/plain"), ("Cache-Control", "private")]
    assert client_headers([("Cache-Control", "Public, max-age=60")]) == [("Cache-Control", "private, max-age=60")]
    assert client_headers([("Cache-Control", "no-store")]) == [("Cache-Control", "no-store")]
    kept = client_headers([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("Connection", "close, X-Hop"), ("X-Hop", "1"), ("Transfer-Encoding", "chunked"), ("Keep-Alive", "5"), ("Cache-Control", "no-cache")])
    assert kept == [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("Cache-Control", "no-cache")]


def test_upstream_headers_drop_every_name_with_an_underscore():
    sent = headers({"Host": "a.example.com", "X_Tailisman_Session": "password", "x_tailisman_user": "owner", "X_Forwarded_For": "203.0.113.9", "Accept_Language": "en", "Accept": "text/html"})
    forwarded = upstream_headers(sent, (("X-Tailisman-Session", "password"),), "127.0.0.1", None, websocket=False)
    assert [name for name, _ in forwarded] == ["Host", "Accept", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Tailisman-Session"]


@pytest.mark.parametrize("raw", [b"Foo: bar\r\n X-Tailisman-Session: password\r\n", b"Foo: bar\r\n\tmore\r\n"])
def test_a_folded_header_value_is_refused(raw):
    parsed = http.client.parse_headers(io.BytesIO(b"Host: a.example.com\r\n" + raw + b"\r\n"))
    with pytest.raises(BadRequest):
        check_header_values(parsed)


def test_plain_header_values_pass():
    check_header_values(headers({"Host": "a.example.com", "Accept": "text/html", "Cookie": "a=1; b=2"}))
