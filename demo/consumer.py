"""A consumer that turns a tailisman token into its own session cookie. Standard library only.

    TAILISMAN_KEY=tsk1.... uv run python demo/consumer.py --origin https://demo.example.com --issuer https://laptop.example-tailnet.ts.net:8443

GET /                 the page, with the snippet; says who is signed in
GET /tailisman.js     client/tailisman.js
POST /auth/tailisman  the exchange: JSON from the silent path (204), a form from the navigation path (303 to /)
GET /state            JSON for tests and scripts
"""

from __future__ import annotations

import argparse
import html
import http.server
import json
import os
import secrets
import threading
from pathlib import Path

from tailisman import Claim, TailismanError, Verifier, extract_token

SNIPPET = Path(__file__).resolve().parent.parent / "client" / "tailisman.js"
COOKIE = "demo_session"
MAX_BODY = 16 * 1024

PAGE = """<!doctype html><meta charset=utf-8><title>tailisman demo</title>
<body data-outcome="{outcome}">
<h1>tailisman demo</h1>
<p id=who>{who}</p>
<button id=tailnet-signin hidden>Sign in from this device</button>
<p id=result></p>
<script type=module>
import {{ mount }} from "/tailisman.js";
const issuer = {issuer};
const targetAddressSpace = {space};
const silent = new URLSearchParams(location.search).get("silent") !== "0";
mount({{
  issuer,
  exchange: "/auth/tailisman",
  button: "#tailnet-signin",
  silent,
  targetAddressSpace,
  isSignedIn: () => document.body.dataset.outcome === "signed-in",
  onResult(result, status) {{
    if (result.ok && status >= 200 && status < 300) return location.reload();
    document.body.dataset.outcome = result.ok ? "exchange-failed" : result.reason;
    document.getElementById("result").textContent = result.ok ? `exchange answered ${{status}}` : `${{result.reason}} ${{result.error ?? result.permission ?? ""}}`;
  }},
}});
if (!silent) document.body.dataset.outcome = "waiting-for-click";
</script>
"""


class Demo:
    def __init__(self, verifier: Verifier, issuer: str, address_space: str) -> None:
        self.verifier = verifier
        self.issuer = issuer
        self.address_space = address_space
        self.sessions: dict[str, Claim] = {}
        self.lock = threading.Lock()

    def session(self, cookie_header: str | None) -> Claim | None:
        for part in (cookie_header or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                with self.lock:
                    return self.sessions.get(value)
        return None

    def sign_in(self, claim: Claim) -> str:
        sid = secrets.token_urlsafe(24)
        with self.lock:
            self.sessions[sid] = claim
        return sid


def handler_for(demo: Demo) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            claim = demo.session(self.headers.get("Cookie"))
            if self.path == "/tailisman.js":
                return self._send(200, "text/javascript; charset=utf-8", SNIPPET.read_bytes())
            if self.path == "/state":
                state = {"signed_in": claim is not None}
                if claim:
                    state.update(node_name=claim.node_name, node_id=claim.node_id, login=claim.login)
                return self._send(200, "application/json", json.dumps(state).encode())
            if self.path.split("?")[0] == "/":
                who = f"Signed in as <b>{html.escape(claim.node_name)}</b> ({html.escape(claim.login)})" if claim else "Not signed in."
                issuer = json.dumps(demo.issuer).replace("<", "\\u003c")
                space = json.dumps(demo.address_space)
                page = PAGE.format(outcome="signed-in" if claim else "pending", who=who, issuer=issuer, space=space)
                return self._send(200, "text/html; charset=utf-8", page.encode())
            self._send(404, "text/plain", b"not found\n")

        def do_POST(self) -> None:
            if self.path != "/auth/tailisman":
                return self._send(404, "text/plain", b"not found\n")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413, "text/plain", b"too large\n")
            content_type = self.headers.get("Content-Type")
            try:
                claim = demo.verifier.verify(extract_token(content_type, self.rfile.read(length)))
            except TailismanError as exc:
                return self._send(403, "text/plain", f"refused: {exc.code}\n".encode())
            cookie = f"{COOKIE}={demo.sign_in(claim)}; HttpOnly; Secure; SameSite=Lax; Path=/"
            if (content_type or "").startswith("application/json"):
                self.send_response(204)
            else:
                self.send_response(303)
                self.send_header("Location", "/")
            self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def make_server(host: str, port: int, origin: str, issuer: str, key: str, address_space: str = "local") -> http.server.ThreadingHTTPServer:
    demo = Demo(Verifier(key=key, audience=origin), issuer, address_space)
    return http.server.ThreadingHTTPServer((host, port), handler_for(demo))


def main() -> None:
    parser = argparse.ArgumentParser(description="tailisman demo consumer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--origin", required=True, help="the public origin visitors load this page from, e.g. https://demo.example.com")
    parser.add_argument("--issuer", required=True, help="the issuer's tailnet URL, e.g. https://laptop.example-tailnet.ts.net:8443")
    parser.add_argument("--address-space", choices=["local", "loopback"], default="local", help="loopback only when the issuer URL is a 127.0.0.1 stand-in")
    args = parser.parse_args()
    key = os.environ.get("TAILISMAN_KEY")
    if not key:
        parser.error("set TAILISMAN_KEY to the output of `tailisman key --aud <origin>`")
    server = make_server(args.host, args.port, args.origin, args.issuer, key, args.address_space)
    print(f"demo consumer on http://{args.host}:{args.port} for {args.origin}, issuer {args.issuer}")
    server.serve_forever()


if __name__ == "__main__":
    main()
