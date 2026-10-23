"""Whether a request Caddy's forward_auth asks about may reach the site. One pure function, decide(), owns the answer.

Measured on Caddy 2.11.7: forward_auth sends the original Host, X-Forwarded-Method and the raw X-Forwarded-Uri (path and
query exactly as the client sent them, `/api/../secret` included), appends the original query to the verify URI, and
returns a non-2xx answer from the gate to the client as is, Location and Set-Cookie included.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from email.message import Message
from urllib.parse import quote, urlsplit

from .config import GateConfig, Site, host_without_port, is_plain_path, site_key
from .session import COOKIE, Session, cookie_values

LOGIN_PATH = "/.tailisman/login"
NAVIGATION_METHODS = ("GET", "HEAD")

SessionCheck = Callable[[tuple[str, ...], str, int], Session | None]


@dataclasses.dataclass(frozen=True)
class GateRequest:
    host: str | None
    method: str
    uri: str
    cookies: tuple[str, ...]
    accepts_html: bool

    @classmethod
    def from_forward_auth(cls, headers: Message) -> GateRequest:
        hosts = headers.get_all("Host") or []
        return cls(
            host=site_key(hosts[0]) if len(hosts) == 1 else None,
            method=(headers.get("X-Forwarded-Method") or "").upper(),
            uri=headers.get("X-Forwarded-Uri") or "",
            cookies=cookie_values(headers.get("Cookie"), COOKIE),
            accepts_html="text/html" in (headers.get("Accept") or ""),
        )

    @property
    def path(self) -> str:
        return urlsplit(self.uri).path


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


def decide(request: GateRequest, config: GateConfig, check_session: SessionCheck, now: int) -> Decision:
    site = config.sites.get(request.host) if request.host is not None else None
    if site is None:
        return Unauthorised("unknown_host")
    if not request.method or not request.uri.startswith("/"):
        return Unauthorised("not_from_forward_auth")
    if is_open(site, request.method, request.path):
        return Allow(None)
    if session := check_session(request.cookies, host_without_port(site.host), now):
        return Allow(session)
    if request.method in NAVIGATION_METHODS and request.accepts_html:
        return SignIn(f"{LOGIN_PATH}?next={quote(request.uri, safe='')}")
    return Unauthorised("sign_in_required")


def is_open(site: Site, method: str, path: str) -> bool:
    return is_plain_path(path) and any(rule.matches(method, path) for rule in site.open)


def safe_next(text: str | None) -> str:
    """A same-host path to return to after sign-in; anything else becomes /."""
    if not text or not text.startswith("/") or text.startswith("//") or "\\" in text or any(ord(c) < 0x21 for c in text):
        return "/"
    parts = urlsplit(text)
    return text if not parts.scheme and not parts.netloc else "/"
