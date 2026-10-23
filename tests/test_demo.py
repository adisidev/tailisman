import html
import http.client
import importlib.util
import json
import re
import threading
from urllib.parse import quote, urlencode

import pytest

from tailisman._token import derive_consumer_key, format_key

from conftest import ROOT

ORIGIN = "http://localhost:8080"


@pytest.fixture(scope="module")
def demo(issuer):
    spec = importlib.util.spec_from_file_location("demo_consumer", ROOT / "demo" / "consumer.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    key = format_key(derive_consumer_key(issuer.config.master, ORIGIN))
    server = module.make_server("127.0.0.1", 0, ORIGIN, "https://laptop.example-tailnet.ts.net:8443", key)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def call(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(*server.server_address[:2], timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    return response, response.read()


def state(server, cookie):
    return json.loads(call(server, "GET", "/state", headers={"Cookie": cookie})[1])


def session_cookie(response):
    header = response.getheader("Set-Cookie")
    assert "HttpOnly" in header and "Secure" in header and "SameSite=Lax" in header
    return header.split(";")[0]


def test_navigation_path_form_post_signs_in_and_redirects(issuer, demo):
    _, page = issuer.request("GET", f"/v1/start?return_to={quote(ORIGIN + '/auth/tailisman')}")
    token = html.unescape(re.search(r'name=token value="([^"]+)"', page.decode()).group(1))
    form = urlencode({"token": token})
    response, _ = call(demo, "POST", "/auth/tailisman", form, {"Content-Type": "application/x-www-form-urlencoded"})
    assert (response.status, response.getheader("Location")) == (303, "/")
    cookie = session_cookie(response)
    assert state(demo, cookie) == {"signed_in": True, "node_name": "laptop", "node_id": "nEXAMPLE1CNTRL", "login": "owner@example.com"}
    page = call(demo, "GET", "/", headers={"Cookie": cookie})[1].decode()
    assert "Signed in as <b>laptop</b>" in page and 'data-outcome="signed-in"' in page
    replay, body = call(demo, "POST", "/auth/tailisman", form, {"Content-Type": "application/x-www-form-urlencoded"})
    assert (replay.status, body) == (403, b"refused: replayed\n")


def test_silent_path_json_exchange_answers_204(issuer, demo):
    _, body = issuer.request("GET", "/v1/claim", origin=ORIGIN)
    response, _ = call(demo, "POST", "/auth/tailisman", json.dumps({"token": json.loads(body)["token"]}), {"Content-Type": "application/json"})
    assert response.status == 204
    assert state(demo, session_cookie(response))["node_name"] == "laptop"


def test_token_for_another_audience_is_refused(issuer, demo):
    _, body = issuer.request("GET", "/v1/claim", origin="https://heckle.example.com")
    response, text = call(demo, "POST", "/auth/tailisman", json.dumps({"token": json.loads(body)["token"]}), {"Content-Type": "application/json"})
    assert (response.status, text) == (403, b"refused: bad_signature\n")


def test_page_without_session_serves_the_snippet(demo):
    page = call(demo, "GET", "/")[1].decode()
    assert "Not signed in." in page and 'import { mount } from "/tailisman.js"' in page
    response, script = call(demo, "GET", "/tailisman.js")
    assert response.getheader("Content-Type").startswith("text/javascript") and b"export function mount" in script
    assert state(demo, "") == {"signed_in": False}
