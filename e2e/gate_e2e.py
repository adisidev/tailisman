"""End to end for the gate: a real Caddy with forward_auth, the gate, a trivial upstream, and the issuer behind the serve stand-in.

    uv run python e2e/gate_e2e.py [--caddy /opt/homebrew/bin/caddy] [--keep]

Prints one line per check and exits 1 on any failure. Everything runs on loopback in a temporary directory; nothing
touches a tailnet, a tunnel or the Caddy admin API. Caddy listens on plain HTTP here, as it does behind a Cloudflare
Tunnel, so this client sends the session cookie itself: the gate's cookies are always Secure, and a cookie jar would not
send them over http. e2e/gate_browser_check.py runs the same stack with Caddy's own TLS for a real browser.
"""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from tailisman.gate.decision import bearer_digest  # noqa: E402
from tailisman.gate.password import parse_hash  # noqa: E402
from tailisman.gate.session import Method, Session, mint, session_key  # noqa: E402

TOOLS = "tools.example.com"
NOTES = "notes.example.com"
SOLO = "solo.example.net"
PEER = "192.0.2.1"
BEARER = "e2e-machine-caller-token"
WHOIS = {
    PEER: {
        "Node": {"ID": 1, "StableID": "nEXAMPLE1CNTRL", "Name": "laptop.example-tailnet.ts.net.", "ComputedName": "laptop", "Tags": None, "Addresses": [f"{PEER}/32"]},
        "UserProfile": {"ID": 2, "LoginName": "owner@example.com", "DisplayName": "Owner", "ProfilePicURL": ""},
        "CapMap": None,
    }
}


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_port(port: int, process: subprocess.Popen | None, name: str, timeout: float = 15) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            raise SystemExit(f"{name} exited with {process.returncode}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"{name} did not listen on {port}")


class Upstream(http.server.BaseHTTPRequestHandler):
    def _answer(self) -> None:
        body = json.dumps({"upstream": True, "path": self.path, "session": self.headers.get("X-Tailisman-Session"), "user": self.headers.get("X-Tailisman-User"), "authorization": self.headers.get("Authorization")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.path.startswith("/cacheable"):
            self.send_header("Cache-Control", "public, max-age=600")
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _answer

    def log_message(self, format: str, *args) -> None:
        pass


class Stack:
    """Starts every process on fresh loopback ports. With tls=True Caddy serves https on its port with its internal CA."""

    def __init__(self, caddy: str, tls: bool = False, keep: bool = False) -> None:
        self.caddy_bin = caddy
        self.tls = tls
        self.keep = keep
        self.dir = Path(tempfile.mkdtemp(prefix="tailisman-gate-e2e-"))
        self.ports = {name: free_port() for name in ("issuer", "serve", "gate", "upstream", "caddy")}
        self.processes: list[subprocess.Popen] = []
        self.env = os.environ | {"FAKE_TAILSCALE_STATE": str(self.dir / "state.json"), "XDG_DATA_HOME": str(self.dir / "xdg-data"), "XDG_CONFIG_HOME": str(self.dir / "xdg-config"), "PYTHONPATH": str(ROOT / "src")}
        suffix = f":{self.ports['caddy']}" if tls else ""
        self.tools, self.notes, self.solo = TOOLS + suffix, NOTES + suffix, SOLO + suffix
        self.issuer_url = f"http://127.0.0.1:{self.ports['serve']}"

    def tailisman(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "tailisman.cli", *args], env=self.env, capture_output=True, text=True, check=check)

    def start(self) -> Stack:
        d, p = self.dir, self.ports
        (d / "state.json").write_text(json.dumps({"whois": WHOIS, "status": {"Self": {"DNSName": "127.0.0.1."}}}))
        self.tailisman("keygen", str(d / "issuer-secret"))
        self.tailisman("keygen", str(d / "gate-secret"))
        (d / "issuer.toml").write_text(
            f'secret_file = "issuer-secret"\nlisten = "127.0.0.1:{p["issuer"]}"\ntailscale_bin = "{ROOT / "e2e" / "fake_tailscale.py"}"\n'
            f'serve_host = "127.0.0.1"\ndevices = ["nEXAMPLE1CNTRL"]\n\n[[audiences]]\norigin = "https://{self.tools}"\n'
        )
        key = self.tailisman("key", "--config", str(d / "issuer.toml"), "--aud", f"https://{self.tools}").stdout.strip()
        (d / "gate.toml").write_text(
            f'listen = "127.0.0.1:{p["gate"]}"\nsession_secret_file = "gate-secret"\npassword_file = "gate-password"\nsession_days = 30\n'
            f'issuer = "{self.issuer_url}"\nissuer_address_space = "loopback"\n\n'
            "[rate_limit]\nper_ip = 3\nglobal = 6\nwindow_seconds = 900\n\n"
            f'[[sites]]\nhost = "{self.tools}"\ncookie_domain = "example.com"\ntailisman_key = "{key}"\nopen = ["/healthz", "/api/*", "POST /report"]\nbearers = ["{bearer_digest(BEARER)}"]\n\n'
            f'[[sites]]\nhost = "{self.notes}"\ncookie_domain = "example.com"\n\n'
            f'[[sites]]\nhost = "{self.solo}"\n'
        )
        self.set_password(force=False)
        scheme = "https" if self.tls else "http"
        global_options = "\tadmin off\n\tlocal_certs\n\tskip_install_trust\n" + ("\tauto_https disable_redirects\n" if self.tls else "\tauto_https off\n")
        (d / "Caddyfile").write_text(
            f"{{\n{global_options}}}\n\n"
            f"(tailisman_gate) {{\n\theader ?Cache-Control \"private\"\n\theader >Cache-Control \"public\" \"private\"\n\troute {{\n\t\treverse_proxy /.tailisman/* 127.0.0.1:{p['gate']}\n\t\tforward_auth 127.0.0.1:{p['gate']} {{\n\t\t\turi /.tailisman/verify\n\t\t\tcopy_headers X-Tailisman-Session X-Tailisman-User\n\t\t}}\n\t}}\n}}\n\n"
            + "".join(f"{scheme}://{host}:{p['caddy']} {{\n\timport tailisman_gate\n\treverse_proxy 127.0.0.1:{p['upstream']}\n}}\n\n" for host in (TOOLS, NOTES, SOLO))
        )
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", p["upstream"]), Upstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.spawn("issuer", [sys.executable, "-m", "tailisman.cli", "run", "--config", str(d / "issuer.toml")], p["issuer"])
        self.spawn("serve stand-in", [sys.executable, str(ROOT / "e2e" / "fake_serve.py"), "--listen", f"127.0.0.1:{p['serve']}", "--backend", f"127.0.0.1:{p['issuer']}", "--peer", PEER], p["serve"])
        self.spawn("gate", [sys.executable, "-m", "tailisman.cli", "gate", "run", "--config", str(d / "gate.toml")], p["gate"])
        self.spawn("caddy", [self.caddy_bin, "run", "--config", str(d / "Caddyfile"), "--adapter", "caddyfile"], p["caddy"])
        return self

    def spawn(self, name: str, argv: list[str], port: int) -> None:
        log = open(self.dir / f"{name.replace(' ', '-')}.log", "w")
        process = subprocess.Popen(argv, env=self.env, stdout=log, stderr=subprocess.STDOUT, cwd=self.dir)
        self.processes.append(process)
        wait_for_port(port, process, name)

    def set_password(self, force: bool = True) -> str:
        out = self.dir / "passphrase"
        self.tailisman("passwd", "--config", str(self.dir / "gate.toml"), "--generate", "--out", str(out), *(["--force"] if force else []))
        return out.read_text().strip()

    def stop(self) -> None:
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        if not self.keep:
            shutil.rmtree(self.dir)


class Reply:
    def __init__(self, response: http.client.HTTPResponse) -> None:
        self.status = response.status
        self.headers = response.getheaders()
        self.body = response.read()

    def header(self, name: str) -> str | None:
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    def cookies(self) -> dict[str, str]:
        return {v.split("=", 1)[0]: v for k, v in self.headers if k.lower() == "set-cookie"}

    def cookie(self, name: str) -> str | None:
        line = self.cookies().get(name)
        return line.split(";")[0].split("=", 1)[1] if line else None

    def json(self) -> dict:
        return json.loads(self.body)


def request(port: int, method: str, path: str, host: str, headers: dict | None = None, body: bytes | None = None) -> Reply:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        conn.request(method, path, body=body, headers={"Host": host} | (headers or {}))
        return Reply(conn.getresponse())
    finally:
        conn.close()


def attributes(reply: Reply, name: str) -> str:
    return (reply.cookies().get(name) or "").partition(";")[2].strip()


class Checks:
    def __init__(self) -> None:
        self.failed = 0

    def check(self, name: str, ok: bool, detail: object = "") -> bool:
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail != "" else ""))
        self.failed += not ok
        return ok


def run(stack: Stack) -> int:
    port, d = stack.ports["caddy"], stack.dir
    c = Checks()
    html = {"Accept": "text/html,application/xhtml+xml"}

    def get(path, host=TOOLS, cookie=None, extra=None):
        headers = html | ({"Cookie": f"tailisman_gate={cookie}"} if cookie else {}) | (extra or {})
        return request(port, "GET", path, host, headers)

    def reached_upstream(reply):
        return reply.status == 200 and reply.body.startswith(b'{"upstream"')

    r = get("/notes?tab=1")
    c.check("anonymous navigation gets 302 to the login page with the original path", r.status == 302 and r.header("Location") == "/.tailisman/login?next=%2Fnotes%3Ftab%3D1", (r.status, r.header("Location")))
    r = request(port, "GET", "/data", TOOLS, {"Accept": "application/json"})
    c.check("anonymous API call gets 401 JSON", r.status == 401 and r.json() == {"error": "sign_in_required"}, (r.status, r.body))
    r = request(port, "POST", "/data", TOOLS, html, b"")
    c.check("anonymous POST navigation gets 401, not a redirect", r.status == 401, r.status)
    r = get("/healthz")
    c.check("an open path reaches the upstream with no session", reached_upstream(r) and r.json()["path"] == "/healthz", r.body)
    r = request(port, "POST", "/report", TOOLS, {}, b"x")
    c.check("an open method rule (POST /report) reaches the upstream", reached_upstream(r), r.status)
    r = get("/api/../secret")
    c.check("an open prefix with a .. segment does not open /secret", r.status == 302, r.status)
    r = get("/api/%2e%2e/secret")
    c.check("an open prefix with an encoded .. does not open /secret", r.status == 302, r.status)

    r = request(port, "GET", "/feed.xml", TOOLS, {"Authorization": f"Bearer {BEARER}", "Accept": "application/json"})
    c.check("a listed bearer on a non-open path reaches the app through forward_auth, Authorization intact, as session bearer", reached_upstream(r) and (r.json()["session"], r.json()["authorization"]) == ("bearer", f"Bearer {BEARER}"), r.body)
    r = request(port, "GET", "/feed.xml", TOOLS, {"Authorization": f"Bearer {BEARER}-wrong", "Accept": "application/json"})
    c.check("an unlisted bearer falls through to 401", r.status == 401, r.status)

    token = json.loads(request(stack.ports["serve"], "GET", "/v1/claim", "127.0.0.1", {"Origin": f"https://{TOOLS}"}).body).get("token", "")
    c.check("the stand-in issuer mints a token for the site", token.startswith("tsm1."), token[:12])
    r = request(port, "POST", "/.tailisman/exchange?next=/notes", TOOLS, {"Content-Type": "application/json"}, json.dumps({"token": token}).encode())
    tailnet_cookie = r.cookie("tailisman_gate")
    c.check("exchange answers the device and sets a session cookie", r.status == 200 and r.json() == {"device": "laptop", "next": "/notes"} and tailnet_cookie is not None, (r.status, r.body))
    c.check("the tailnet cookie is Secure, HttpOnly, Lax, Domain=example.com", "; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax" in r.cookies().get("tailisman_gate", ""), attributes(r, "tailisman_gate"))
    r = get("/notes", cookie=tailnet_cookie)
    c.check("the upstream answers with the tailnet cookie", reached_upstream(r), r.status)
    r = request(port, "POST", "/.tailisman/exchange", TOOLS, {"Content-Type": "application/json"}, json.dumps({"token": token}).encode())
    c.check("the same token is refused a second time", r.status == 403 and r.json() == {"error": "replayed"}, r.body)
    r = get("/", host=SOLO, cookie=tailnet_cookie)
    c.check("the example.com cookie does not open a site outside its scope", r.status == 302, r.status)

    r = get("/.tailisman/login?next=/notes")
    csrf = r.cookie("tailisman_csrf")
    field = re.search(rb'name=csrf value="([^"]+)"', r.body)
    c.check("the login page sets a CSRF cookie and the matching hidden field", r.status == 200 and csrf and field and field.group(1).decode() == csrf, r.status)
    c.check("the login page has a strict CSP and no inline script", "script-src 'self'" in (r.header("Content-Security-Policy") or "") and b"<script>" not in r.body, r.header("Content-Security-Policy"))
    passphrase = (d / "passphrase").read_text().strip()

    def login(password, ip, token_value=None):
        page = get("/.tailisman/login", extra={"CF-Connecting-IP": ip})
        value = token_value or page.cookie("tailisman_csrf")
        body = urlencode({"csrf": value, "password": password, "next": "/notes"}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": f"tailisman_csrf={value}", "Origin": f"https://{TOOLS}", "CF-Connecting-IP": ip}
        return request(port, "POST", "/.tailisman/login", TOOLS, headers, body)

    r = login(passphrase, "198.51.100.1")
    password_cookie = r.cookie("tailisman_gate")
    c.check("the password path answers 303 to next with a session cookie", r.status == 303 and r.header("Location") == "/notes" and password_cookie is not None, (r.status, r.header("Location")))
    r = get("/notes", cookie=password_cookie)
    c.check("the upstream answers with the password cookie", reached_upstream(r), r.status)
    c.check("a gated answer with no Cache-Control is marked private", r.header("Cache-Control") == "private", r.header("Cache-Control"))
    r = get("/cacheable.js", cookie=password_cookie)
    c.check("a gated answer the app marked public is marked private", r.header("Cache-Control") == "private, max-age=600", r.header("Cache-Control"))
    r = get("/", host=SOLO)
    solo_csrf = r.status == 302 and get("/.tailisman/login", host=SOLO).cookie("tailisman_csrf")
    body = urlencode({"csrf": solo_csrf, "password": passphrase, "next": "/"}).encode()
    r = request(port, "POST", "/.tailisman/login", SOLO, {"Content-Type": "application/x-www-form-urlencoded", "Cookie": f"tailisman_csrf={solo_csrf}", "CF-Connecting-IP": "198.51.100.2"}, body)
    solo_cookie = r.cookie("tailisman_gate")
    c.check("the host-only site sets a cookie with no Domain", r.status == 303 and "Domain" not in r.cookies().get("tailisman_gate", "Domain"), attributes(r, "tailisman_gate"))
    c.check("the host-only cookie opens its own site", reached_upstream(get("/", host=SOLO, cookie=solo_cookie)))
    body = urlencode({"csrf": csrf, "password": passphrase, "next": "/"}).encode()
    r = request(port, "POST", "/.tailisman/login", TOOLS, {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "tailisman_csrf=" + "A" * 32}, body)
    c.check("a login POST whose CSRF cookie and field differ is refused", r.status == 403 and r.cookie("tailisman_gate") is None, r.status)
    r = login("not the password", "198.51.100.3")
    c.check("a wrong password gets 401 and one generic message", r.status == 401 and b"That password did not work." in r.body, r.status)

    secret = (d / "gate-secret").read_bytes()
    line = parse_hash((d / "gate-password").read_text()).line
    now = int(time.time())
    expired = mint(Session(Method.PASSWORD, None, "example.com", now - 7200, now - 3600), session_key(secret, line))
    c.check("an expired cookie is refused", get("/notes", cookie=expired).status == 302)

    page = get("/.tailisman/", cookie=password_cookie)
    c.check("the session page says how the browser signed in", b"Signed in with the password" in page.body, page.status)
    tailnet_page = get("/.tailisman/", cookie=tailnet_cookie)
    c.check("the session page names the tailnet device", b"Signed in from laptop on the tailnet" in tailnet_page.body, tailnet_page.status)
    logout_csrf = page.cookie("tailisman_csrf")
    r = request(port, "POST", "/.tailisman/logout", TOOLS, {"Content-Type": "application/x-www-form-urlencoded", "Cookie": f"tailisman_gate={password_cookie}; tailisman_csrf={logout_csrf}"}, f"csrf={logout_csrf}".encode())
    clears = [v for k, v in r.headers if k.lower() == "set-cookie" and v.startswith("tailisman_gate=;")]
    c.check("sign out answers 303 to the login page and clears the cookie", r.status == 303 and r.header("Location") == "/.tailisman/login?signed_out=1" and any("Max-Age=0" in v and "Domain=example.com" in v for v in clears), clears)

    added = stack.tailisman("passwd", "--config", str(d / "gate.toml"), "--add", "visitor", "--sites", NOTES)
    guest_phrase = (d / "guests" / "visitor").read_text().strip()
    c.check("`passwd --add` writes the guest passphrase to a file and prints only paths", added.returncode == 0 and guest_phrase not in added.stdout + added.stderr and "guests/visitor" in added.stdout, added.stdout.strip().replace("\n", " | "))
    page = get("/.tailisman/login", host=NOTES)
    notes_csrf = page.cookie("tailisman_csrf")
    form = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": f"tailisman_csrf={notes_csrf}", "CF-Connecting-IP": "198.51.100.5"}
    r = request(port, "POST", "/.tailisman/login", NOTES, form, urlencode({"csrf": notes_csrf, "password": guest_phrase, "next": "/"}).encode())
    guest_cookie = r.cookie("tailisman_gate")
    c.check("the guest signs in to their site with a Domain=example.com cookie", r.status == 303 and "Domain=example.com" in attributes(r, "tailisman_gate"), (r.status, attributes(r, "tailisman_gate")))
    r = get("/", host=NOTES, cookie=guest_cookie)
    c.check("the app behind sees X-Tailisman-Session guest and X-Tailisman-User visitor through copy_headers", reached_upstream(r) and (r.json()["session"], r.json()["user"]) == ("guest", "visitor"), r.body)
    r = get("/", host=TOOLS, cookie=guest_cookie)
    c.check("the guest's example.com cookie is refused on tools.example.com, which shares the domain", r.status == 302, r.status)
    owner_cookie = login(passphrase, "198.51.100.6").cookie("tailisman_gate")
    r = get("/", host=NOTES, cookie=owner_cookie, extra={"X-Tailisman-User": "visitor", "X-Tailisman-Session": "guest"})
    c.check("an owner request's own X-Tailisman-User is removed and its X-Tailisman-Session replaced", reached_upstream(r) and (r.json()["session"], r.json()["user"]) == ("password", None), r.body)
    r = request(port, "POST", "/.tailisman/login", TOOLS, form, urlencode({"csrf": notes_csrf, "password": guest_phrase, "next": "/"}).encode())
    c.check("the guest password typed into tools.example.com's form is refused", r.status == 401 and r.cookie("tailisman_gate") is None, r.status)

    new_passphrase = stack.set_password()
    c.check("after `tailisman passwd`, the guest session still works", reached_upstream(get("/", host=NOTES, cookie=guest_cookie)))
    revoked = stack.tailisman("passwd", "--config", str(d / "gate.toml"), "--revoke", "visitor")
    c.check("after `passwd --revoke`, the guest session is refused without a restart", revoked.returncode == 0 and get("/", host=NOTES, cookie=guest_cookie).status == 302 and not (d / "guests" / "visitor").exists(), revoked.stdout.strip())
    c.check("after `tailisman passwd`, an existing session cookie is refused", get("/notes", cookie=tailnet_cookie).status == 302)
    r = login(new_passphrase, "198.51.100.4")
    c.check("the new password signs in without a restart", r.status == 303 and reached_upstream(get("/notes", cookie=r.cookie("tailisman_gate"))), r.status)

    status = stack.tailisman("gate", "status", "--config", str(d / "gate.toml"), "--base-url-for", f"{TOOLS}=http://127.0.0.1:{port}", "--base-url-for", f"{NOTES}=http://127.0.0.1:{port}", "--base-url-for", f"{SOLO}=http://127.0.0.1:{port}", check=False)
    c.check("`tailisman gate status --base-url-for` passes", status.returncode == 0 and status.stdout.count(": ok") == 3, status.stdout.strip().replace("\n", " | "))

    for _ in range(3):
        login("wrong", "198.51.100.10")
    r = login(new_passphrase, "198.51.100.10")
    c.check("the right password from an IP at its limit (3 failures) gets 429 with Retry-After", r.status == 429 and (r.header("Retry-After") or "").isdigit(), (r.status, r.header("Retry-After")))
    r = login(new_passphrase, "198.51.100.11")
    c.check("another IP still signs in while one IP is limited", r.status == 303, r.status)
    for _ in range(2):
        login("wrong", "198.51.100.12")
    r = login(new_passphrase, "198.51.100.13")
    c.check("the right password from a fresh IP gets 429 once the global limit (6 failures) is hit", r.status == 429, r.status)
    gate_log = (d / "gate.log").read_text()
    c.check("the gate log names refusals and sign-ins without secrets", "wrong password" in gate_log and "as guest visitor" in gate_log and all(p not in gate_log for p in (passphrase, new_passphrase, guest_phrase)), gate_log.count("\n"))
    print(f"{'all checks passed' if not c.failed else f'{c.failed} check(s) failed'}; logs in {d}" if stack.keep else ("all checks passed" if not c.failed else f"{c.failed} check(s) failed"))
    return 1 if c.failed else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", default=shutil.which("caddy") or "/opt/homebrew/bin/caddy")
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory and its logs")
    args = parser.parse_args()
    stack = Stack(args.caddy, keep=args.keep)
    try:
        version = subprocess.run([args.caddy, "version"], capture_output=True, text=True, check=True).stdout.split()[0]
        print(f"caddy {version}, gate on 127.0.0.1:{stack.ports['gate']}, caddy on 127.0.0.1:{stack.ports['caddy']}")
        stack.start()
        return run(stack)
    finally:
        stack.stop()


if __name__ == "__main__":
    sys.exit(main())
