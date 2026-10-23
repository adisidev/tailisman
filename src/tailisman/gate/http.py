"""The gate's HTTP surface: the /.tailisman/ pages and forward_auth's verify target on every gated host, and proxy mode for sites with an upstream."""

from __future__ import annotations

import dataclasses
import hmac
import html
import http.server
import json
import re
import secrets
import socket
import sys
import threading
import time
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from .. import MAX_BODY, TailismanError, extract_token
from .._token import normalise_origin
from ..issuer.config import ConfigError
from ..issuer.decision import Grant, Whois
from ..issuer.http import IssuerApp, Response
from .codes import CodeBook, Device
from .config import GateConfig, Site, host_without_port
from .decision import LOGIN_PATH, Allow, Decision, GateRequest, SignIn, Unauthorised, decide, request_host, safe_next
from .credentials import Credentials
from .ratelimit import RateLimiter
from .proxy import identity_headers, relay
from .session import COOKIE, CSRF_COOKIE, Method, Session, cookie_values, mint

STATIC = Path(__file__).with_name("static")
_CSRF = re.compile(r"[A-Za-z0-9_-]{32}")
Headers = tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True)
class Incoming:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: Message
    body: bytes
    peer: str

    def single(self, name: str) -> str | None:
        values = self.query.get(name, [])
        return values[0] if len(values) == 1 else None

    def client_ip(self) -> str:
        """CF-Connecting-IP, then the first X-Forwarded-For entry, then the socket peer. A request that skips Cloudflare can set either header itself."""
        if cf := (self.headers.get("CF-Connecting-IP") or "").strip():
            return cf
        if forwarded := (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip():
            return forwarded
        return self.peer


def _snippet_path() -> Path:
    packaged = STATIC / "tailisman.js"
    return packaged if packaged.is_file() else Path(__file__).resolve().parents[3] / "client" / "tailisman.js"


class GateApp:
    def __init__(self, config: GateConfig, clock: Callable[[], float] = time.time) -> None:
        self.config = config
        self.clock = clock
        self.credentials = Credentials(config.session_secret, config.password_file, config.guest_file)
        self.limiter = RateLimiter(config.rate_limit)
        self.codes = CodeBook(config.tailnet.checks.ttl_seconds if config.tailnet else 60)
        self._password_lock = threading.Lock()
        self._down_lock = threading.Lock()
        self._down: set[str] = set()
        try:
            self.static = {
                "/.tailisman/tailisman.js": ("text/javascript; charset=utf-8", _snippet_path().read_bytes()),
                "/.tailisman/login.js": ("text/javascript; charset=utf-8", (STATIC / "login.js").read_bytes()),
                "/.tailisman/gate.css": ("text/css; charset=utf-8", (STATIC / "gate.css").read_bytes()),
            }
        except OSError as exc:
            raise ConfigError(f"a gate static file is missing from the install: {exc}") from exc

    def respond(self, method: str, target: str, headers: Message, body: bytes = b"", peer: str = "") -> tuple[Response, str | None]:
        """The response, and a line for the log when something worth logging happened."""
        url = urlsplit(target)
        request = Incoming(method, url.path, parse_qs(url.query), headers, body, peer)
        if url.path in self.static:
            content_type, data = self.static[url.path]
            return Response(200, (("Content-Type", content_type), ("Cache-Control", "no-cache"), ("X-Content-Type-Options", "nosniff")), data), None
        if url.path == "/.tailisman/healthz":
            return _text(200, "ok\n"), None
        if url.path == "/.tailisman/verify":
            return self._verify(headers), None
        routes: dict[str, dict[str, Callable[[Incoming, Site], tuple[Response, str | None]]]] = {
            "/.tailisman/": {"GET": self._session_page},
            LOGIN_PATH: {"GET": self._login_page, "POST": self._login},
            "/.tailisman/exchange": {"POST": self._exchange},
            "/.tailisman/logout": {"POST": self._logout},
        }
        methods = routes.get(url.path)
        if methods is None:
            return _text(404, "not found\n"), None
        if method not in methods:
            return _text(405, "method not allowed\n"), None
        site = self.config.sites.get(request_host(headers) or "")
        if site is None:
            return _text(404, "this gate does not cover this host\n"), None
        return methods[method](request, site)

    def now(self) -> int:
        return int(self.clock())

    def tailnet_app(self, whois: Whois) -> IssuerApp:
        """The tailnet listener: the issuer's checks and CORS, answering a one-time code for this process instead of a signed token."""
        assert self.config.tailnet is not None
        checks = self.config.tailnet.checks
        return IssuerApp(checks, whois, checks.serve_host, self.clock, issue=self._issue_code)

    def _issue_code(self, grant: Grant, now: int) -> str:
        return self.codes.issue(grant.audience.origin, Device(grant.peer.node_id, grant.peer.node_name, grant.peer.login), now)

    def check(self, request: GateRequest) -> Decision:
        return decide(request, self.config, self.credentials.session_for, self.now())

    def proxy_site(self, target: str, headers: Message) -> Site | None:
        """The proxy site a request goes on to, or None when the gate answers it: its pages under /.tailisman/, forward_auth sites, unknown hosts."""
        if target.startswith("/.tailisman/"):
            return None
        site = self.config.sites.get(request_host(headers) or "")
        return site if site is not None and site.upstream is not None else None

    def note_upstream(self, site: Site, error: str | None) -> str | None:
        """A log line when a site's app stops or starts answering, so a dead app is logged once rather than per request."""
        with self._down_lock:
            if error is not None and site.host not in self._down:
                self._down.add(site.host)
                return f"{site.host}: upstream {site.upstream} is not answering ({error}); answering 502"
            if error is None and site.host in self._down:
                self._down.discard(site.host)
                return f"{site.host}: upstream {site.upstream} answers again"
        return None

    def _verify(self, headers: Message) -> Response:
        decision = self.check(GateRequest.from_forward_auth(headers))
        if isinstance(decision, Allow):
            return Response(200, (("Cache-Control", "no-store"),) + identity_headers(decision), b"")
        return refusal(decision)

    def _current_session(self, request: Incoming, site: Site) -> Session | None:
        return self.credentials.session_for(cookie_values(request.headers.get("Cookie"), COOKIE), site.host, self.now())

    def _login_page(self, request: Incoming, site: Site) -> tuple[Response, str | None]:
        next_path = safe_next(request.single("next"))
        if self._current_session(request, site):
            return _redirect(next_path), None
        return self._render_login(request, site, next_path, 200, None, signed_out=request.single("signed_out") == "1"), None

    def _render_login(self, request: Incoming, site: Site, next_path: str, status: int, message: str | None, extra: Headers = (), signed_out: bool = False) -> Response:
        """After sign-out the tailnet path waits for a click; signing straight back in would make Sign out do nothing on a tailnet device."""
        csrf = _csrf_from(request) or secrets.token_urlsafe(24)
        password = self.credentials.owner.current() is not None or self.credentials.guest_count(site.host) > 0
        tailnet = self.config.tailnet if self._tailnet_on(site) else None
        parts = [f'<p class=site>{html.escape(host_without_port(site.host))}</p><h1>Sign in</h1>']
        if message:
            parts.append(f"<p class=message role=alert>{html.escape(message)}</p>")
        if signed_out:
            parts.append("<p class=note>You are signed out.</p>")
        if tailnet:
            parts.append(
                f'<section class=tailnet data-issuer="{html.escape(tailnet.origin)}" data-next="{html.escape(next_path)}" data-space="{tailnet.address_space}" data-silent="{0 if signed_out else 1}">'
                '<p id=tailnet-status role=status aria-live=polite></p>'
                '<button type=button id=tailnet-signin class=secondary hidden>Sign in from this device</button></section>'
            )
        if password:
            parts.append(
                '<form method=post action="/.tailisman/login">'
                f'<input type=hidden name=csrf value="{csrf}"><input type=hidden name=next value="{html.escape(next_path)}">'
                '<label for=password>Password</label>'
                '<input id=password name=password type=password autocomplete=current-password required autofocus>'
                "<button type=submit>Sign in</button></form>"
            )
        else:
            parts.append("<p class=note>Password sign-in is not set up on this gate.</p>")
        script = '<script type=module src="/.tailisman/login.js"></script>' if tailnet else ""
        return _page(status, "Sign in", "".join(parts) + script, self._csp(site), (_csrf_cookie(csrf),) + extra)

    def _login(self, request: Incoming, site: Site) -> tuple[Response, str | None]:
        form = _form(request.body)
        next_path = safe_next(_one(form, "next"))
        ip = request.client_ip()
        with self._password_lock:
            now = self.clock()
            wait = self.limiter.retry_after(ip, now)
            if wait is not None:
                minutes = max(1, round(wait / 60))
                message = f"Too many wrong passwords. Try again in {minutes} minute{'s' if minutes != 1 else ''}."
                return self._render_login(request, site, next_path, 429, message, (("Retry-After", str(wait)),)), f"login refused for {site.host}: rate limited, {ip}"
            if not self._csrf_ok(request, site, form):
                return self._render_login(request, site, next_path, 403, "This form had expired. Try again."), f"login refused for {site.host}: csrf, {ip}"
            opened = self.credentials.opens(_one(form, "password"), site.host)
            if opened is None:
                self.limiter.record_failure(ip, now)
                return self._render_login(request, site, next_path, 401, "That password did not work."), f"login refused for {site.host}: wrong password, {ip}"
        session = self._new_session(site, opened.method, None, opened.guest)
        cookies = (self._session_cookie(site, session, opened.key), _clear(CSRF_COOKIE, "/.tailisman/", None, "Strict"))
        who = f"as guest {opened.guest}" if opened.guest else "with the password"
        return _redirect(next_path, cookies), f"signed in to {site.host} {who}, {ip}"

    def _exchange(self, request: Incoming, site: Site) -> tuple[Response, str | None]:
        next_path = safe_next(request.single("next"))
        wants_json = (request.headers.get("Content-Type") or "").split(";")[0].strip().lower() == "application/json"
        if not self._tailnet_on(site):
            return _json(404, {"error": "tailnet_off"}), None
        try:
            device = self.codes.redeem(extract_token(request.headers.get("Content-Type"), request.body), site.origin, self.now())
        except TailismanError as exc:
            log = f"exchange refused for {site.host}: {exc.code}"
            if wants_json:
                return _json(403, {"error": exc.code.value}), log
            body = f"<h1>Not signed in</h1><p>The tailnet sign-in was refused: <code>{html.escape(exc.code.value)}</code>.</p><p><a href=\"{LOGIN_PATH}?next={quote(next_path, safe='')}\">Back to sign in</a></p>"
            return _page(403, "Not signed in", body, self._csp(site)), log
        session = dataclasses.replace(self._new_session(site, Method.TAILNET, device.node_name), device_id=device.node_id)
        cookie = (self._session_cookie(site, session, self.credentials.owner_key()),)
        log = f"signed in to {site.host} from {device.node_name}"
        if wants_json:
            return _json(200, {"device": device.node_name, "next": next_path}, cookie), log
        return _redirect(next_path, cookie), log

    def _session_page(self, request: Incoming, site: Site) -> tuple[Response, str | None]:
        session = self._current_session(request, site)
        name = html.escape(host_without_port(site.host))
        if session is None:
            body = f'<p class=site>{name}</p><h1>Not signed in</h1><p><a href="{LOGIN_PATH}">Sign in</a></p>'
            return _page(200, "Not signed in", body, self._csp(site)), None
        csrf = _csrf_from(request) or secrets.token_urlsafe(24)
        how = {
            Method.PASSWORD: "with the password",
            Method.TAILNET: f"from {html.escape(session.device or '')} on the tailnet",
            Method.GUEST: f"as {html.escape(session.guest or '')} (guest)",
        }[session.method]
        until = time.strftime("%d %b %Y, %H:%M UTC", time.gmtime(session.expires_at))
        scope = "" if session.scope == host_without_port(site.host) else f" The sign-in covers every site under {html.escape(session.scope)}."
        body = (
            f'<p class=site>{name}</p><h1>Signed in</h1><p>Signed in {how}, until {until}.{scope}</p>'
            f'<form method=post action="/.tailisman/logout"><input type=hidden name=csrf value="{csrf}">'
            '<button type=submit class=secondary>Sign out</button></form><p><a href="/">Back to the site</a></p>'
        )
        return _page(200, "Signed in", body, self._csp(site), (_csrf_cookie(csrf),)), None

    def _logout(self, request: Incoming, site: Site) -> tuple[Response, str | None]:
        if not self._csrf_ok(request, site, _form(request.body)):
            body = '<h1>Still signed in</h1><p>This form had expired. <a href="/.tailisman/">Try again</a>.</p>'
            return _page(403, "Still signed in", body, self._csp(site)), None
        cookies = tuple(_clear(COOKIE, "/", domain, "Lax") for domain in {site.cookie_domain, None})
        return _redirect(f"{LOGIN_PATH}?signed_out=1", cookies), f"signed out of {site.host}"

    def _tailnet_on(self, site: Site) -> bool:
        return self.config.tailnet is not None and site.tailnet

    def _csp(self, site: Site) -> str:
        connect = "'self'" + (f" {self.config.tailnet.origin}" if self._tailnet_on(site) else "")
        return f"default-src 'none'; script-src 'self'; style-src 'self'; connect-src {connect}; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

    def _csrf_ok(self, request: Incoming, site: Site, form: dict[str, list[str]]) -> bool:
        cookie, field = _csrf_from(request), _one(form, "csrf")
        if cookie is None or field is None or not hmac.compare_digest(cookie, field):
            return False
        origin = request.headers.get("Origin")
        if origin is None:
            return True
        try:
            return normalise_origin(origin) == site.origin
        except ValueError:
            return False

    def _new_session(self, site: Site, method: Method, device: str | None, guest: str | None = None) -> Session:
        now = self.now()
        return Session(method, device, site.scope, now, now + self.config.session_days * 86400, guest)

    def _session_cookie(self, site: Site, session: Session, key: bytes) -> tuple[str, str]:
        value = mint(session, key)
        domain = f"; Domain={site.cookie_domain}" if site.cookie_domain else ""
        return ("Set-Cookie", f"{COOKIE}={value}; Max-Age={self.config.session_days * 86400}; Path=/{domain}; Secure; HttpOnly; SameSite=Lax")


def refusal(decision: SignIn | Unauthorised) -> Response:
    """The same answer for forward_auth and proxy mode: a page navigation goes to sign in, anything else gets 401."""
    if isinstance(decision, SignIn):
        return Response(302, (("Location", decision.login_url), ("Cache-Control", "no-store")), b"")
    return _json(401, {"error": decision.reason})


def _csrf_from(request: Incoming) -> str | None:
    values = [v for v in cookie_values(request.headers.get("Cookie"), CSRF_COOKIE) if _CSRF.fullmatch(v)]
    return values[0] if values else None


def _csrf_cookie(value: str) -> tuple[str, str]:
    return ("Set-Cookie", f"{CSRF_COOKIE}={value}; Path=/.tailisman/; Secure; HttpOnly; SameSite=Strict")


def _clear(name: str, path: str, domain: str | None, same_site: str) -> tuple[str, str]:
    scope = f"; Domain={domain}" if domain else ""
    return ("Set-Cookie", f"{name}=; Max-Age=0; Path={path}{scope}; Secure; HttpOnly; SameSite={same_site}")


def _form(body: bytes) -> dict[str, list[str]]:
    if len(body) > MAX_BODY:
        return {}
    try:
        return parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except (UnicodeDecodeError, ValueError):
        return {}


def _one(form: dict[str, list[str]], name: str) -> str | None:
    values = form.get(name, [])
    return values[0] if len(values) == 1 else None


def _base_headers(content_type: str) -> Headers:
    return (("Content-Type", content_type), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"))


def _text(status: int, body: str) -> Response:
    return Response(status, _base_headers("text/plain; charset=utf-8"), body.encode())


def _json(status: int, body: dict, extra: Headers = ()) -> Response:
    return Response(status, _base_headers("application/json") + extra, json.dumps(body).encode())


def _redirect(location: str, extra: Headers = ()) -> Response:
    return Response(303, (("Location", location), ("Cache-Control", "no-store")) + extra, b"")


def _page(status: int, title: str, main: str, csp: str, extra: Headers = ()) -> Response:
    document = (
        "<!doctype html><html lang=en><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1"><meta name=color-scheme content="light dark">'
        f'<title>{html.escape(title)}</title><link rel=stylesheet href="/.tailisman/gate.css"><main>{main}</main>'
    )
    # Not no-referrer: under no-referrer Chrome 156 sends Origin: null on the page's own form posts, which the Origin check refuses.
    headers = _base_headers("text/html; charset=utf-8") + (("Content-Security-Policy", csp), ("Referrer-Policy", "same-origin"))
    return Response(status, headers + extra, document.encode())


def _log(line: str | None) -> None:
    if line:
        print(f"tailisman gate: {line}", file=sys.stderr)


def handler_for(app: GateApp) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "tailisman-gate"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _dispatch(self) -> None:
            site = app.proxy_site(self.path, self.headers)
            if site is None:
                self._answer_here()
            else:
                self._proxy(site)

        def _answer_here(self) -> None:
            if "Transfer-Encoding" in self.headers:
                self.send_error(411)
                return
            length = self.headers.get("Content-Length") or "0"
            if not length.isdigit() or int(length) > MAX_BODY:
                self.send_error(413)
                return
            body = self.rfile.read(int(length))
            response, log = app.respond(self.command, self.path, self.headers, body, self.client_address[0])
            self._send(response)
            _log(log)

        def _proxy(self, site: Site) -> None:
            decision = app.check(GateRequest.from_request(self.command, self.path, self.headers))
            if isinstance(decision, Allow):
                _log(app.note_upstream(site, relay(self, site.upstream, identity_headers(decision))))
                return
            self._skip_small_body()
            self._send(refusal(decision))

        def _skip_small_body(self) -> None:
            """A refused request's body is read and dropped up to the gate's own form limit, so the connection stays usable; a bigger one closes it unread."""
            length = self.headers.get("Content-Length") or "0"
            if "Transfer-Encoding" in self.headers or not length.isdigit() or int(length) > MAX_BODY:
                self.close_connection = True
            else:
                self.rfile.read(int(length))

        def _send(self, response: Response) -> None:
            self.send_response(response.status)
            for name, value in response.headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response.body)))
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.body)

        def __getattr__(self, name: str):
            """Every method reaches _dispatch, so a proxied app can use WebDAV's or any other; the gate's own routes still list theirs."""
            if name.startswith("do_"):
                return self._dispatch
            raise AttributeError(name)

        def log_message(self, format: str, *args) -> None:
            pass

    return Handler


class _ThreadingHTTPServerV6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def make_server(app: GateApp) -> http.server.ThreadingHTTPServer:
    listen = app.config.listen
    server_class = _ThreadingHTTPServerV6 if ":" in listen.host else http.server.ThreadingHTTPServer
    return server_class((listen.host, listen.port), handler_for(app))
