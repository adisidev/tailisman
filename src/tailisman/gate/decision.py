"""Whether a request may reach the site, asked by Caddy's forward_auth or by the gate's own proxy. One pure function, decide(), owns the answer.

Measured on Caddy 2.11.7: forward_auth sends the original Host, X-Forwarded-Method and the raw X-Forwarded-Uri (path and
query exactly as the client sent them, `/api/../secret` included), appends the original query to the verify URI, and
returns a non-2xx answer from the gate to the client as is, Location and Set-Cookie included.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from email.message import Message
from urllib.parse import quote, urlsplit

from .config import GateConfig, Site, is_plain_path, site_key
from .session import COOKIE, Session, cookie_values

LOGIN_PATH = "/.tailisman/login"
NAVIGATION_METHODS = ("GET", "HEAD")

SessionCheck = Callable[[tuple[str, ...], str, int], Session | None]
"""(cookie values, site key, now) -> the session they hold on that site."""


@dataclasses.dataclass(frozen=True)
class GateRequest:
    host: str | None
    method: str
    uri: str
    cookies: tuple[str, ...]
    accepts_html: bool

    @classmethod
    def from_forward_auth(cls, headers: Message) -> GateRequest:
        """Caddy's question about another request: the method and URI come from the X-Forwarded-* headers Caddy sets."""
        return cls._of(headers, (headers.get("X-Forwarded-Method") or "").upper(), headers.get("X-Forwarded-Uri") or "")

    @classmethod
    def from_request(cls, method: str, target: str, headers: Message) -> GateRequest:
        """A request the gate proxies itself. Its own request line counts; X-Forwarded-* from the client never does."""
        return cls._of(headers, method.upper(), target)

    @classmethod
    def _of(cls, headers: Message, method: str, uri: str) -> GateRequest:
        return cls(request_host(headers), method, uri, cookie_values(headers.get("Cookie"), COOKIE), "text/html" in (headers.get("Accept") or ""))

    @property
    def path(self) -> str:
        return self.uri.split("?", 1)[0]


@dataclasses.dataclass(frozen=True)
class Allow:
    session: Session | None


@dataclasses.dataclass(frozen=True)
class SignIn:
    login_url: str


@dataclasses.dataclass(frozen=True)
class Unauthorised:
    reason: str


Decision = Allow | SignIn | Unauthorised


def request_host(headers: Message) -> str | None:
    """The site key of the one Host header, or None when there is not exactly one."""
    hosts = headers.get_all("Host") or []
    return site_key(hosts[0]) if len(hosts) == 1 else None


def decide(request: GateRequest, config: GateConfig, check_session: SessionCheck, now: int) -> Decision:
    site = config.sites.get(request.host) if request.host is not None else None
    if site is None:
        return Unauthorised("unknown_host")
    if not request.method or not request.uri.startswith("/"):
        return Unauthorised("not_from_forward_auth")
    if is_open(site, request.method, request.path):
        return Allow(None)
    if session := check_session(request.cookies, site.host, now):
        return Allow(session)
    if request.method in NAVIGATION_METHODS and request.accepts_html:
        return SignIn(f"{LOGIN_PATH}?next={quote(request.uri, safe='')}")
    return Unauthorised("sign_in_required")


def is_open(site: Site, method: str, path: str) -> bool:
    return is_plain_path(path) and any(rule.matches(method, path) for rule in site.open)


def safe_next(text: str | None) -> str:
    """A same-host path to return to after sign-in; anything else becomes /, including the login page, which would loop."""
    if not text or not text.isascii() or not text.startswith("/") or text.startswith("//") or "\\" in text or any(ord(c) < 0x21 for c in text):
        return "/"
    parts = urlsplit(text)
    return text if not parts.scheme and not parts.netloc and parts.path != LOGIN_PATH else "/"
