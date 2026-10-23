"""Who is asking, and whether they get a token. One ordered function, decide(), owns every refusal.

Measured on Tailscale 1.102.4: serve replaces any client-sent X-Forwarded-For with exactly one value (the peer's
tailnet IP) and Tailscale-User-Login with the real login; tagged nodes get no Tailscale-User-* headers; Funnel
traffic carries Tailscale-Funnel-Request; Host and X-Forwarded-Host carry the name the browser asked for. Node
identity comes only from `tailscale whois`.
"""

from __future__ import annotations

import dataclasses
import enum
import ipaddress
from collections.abc import Callable
from email.message import Message

from .._token import Claim, derive_consumer_key, encode, new_nonce
from .config import Audience, IssuerConfig, host_name

Whois = Callable[[str], dict | None]


class RefusalCode(enum.StrEnum):
    WRONG_HOST = "wrong_host"
    NOT_BEHIND_SERVE = "not_behind_serve"
    FUNNEL_REQUEST = "funnel_request"
    UNKNOWN_AUDIENCE = "unknown_audience"
    UNKNOWN_PEER = "unknown_peer"
    TAGGED_NODE = "tagged_node"
    IDENTITY_MISMATCH = "identity_mismatch"
    NOT_ON_ALLOWLIST = "not_on_allowlist"
    USER_NOT_ALLOWED = "user_not_allowed"
    AUTOMATION = "automation"


HTTP_STATUS = {code: 421 if code in (RefusalCode.WRONG_HOST, RefusalCode.NOT_BEHIND_SERVE) else 403 for code in RefusalCode}


@dataclasses.dataclass(frozen=True)
class Refusal:
    code: RefusalCode
    node: str | None = None


@dataclasses.dataclass(frozen=True)
class ServeFacts:
    hosts: tuple[str, ...]
    forwarded_hosts: tuple[str, ...]
    proto: str | None
    forwarded_for: tuple[str, ...]
    funnel: bool
    login: str | None
    user_agent: str

    @classmethod
    def from_headers(cls, headers: Message) -> ServeFacts:
        values = tuple(v.strip() for header in headers.get_all("X-Forwarded-For") or [] for v in header.split(","))
        return cls(
            hosts=tuple(headers.get_all("Host") or []),
            forwarded_hosts=tuple(headers.get_all("X-Forwarded-Host") or []),
            proto=headers.get("X-Forwarded-Proto"),
            forwarded_for=values,
            funnel="Tailscale-Funnel-Request" in headers,
            login=headers.get("Tailscale-User-Login"),
            user_agent=headers.get("User-Agent", ""),
        )

    def asked_for(self, serve_host: str) -> bool:
        """A rebinding page can point its own name at 127.0.0.1 and forge every other header, but its Host stays its own name."""
        if len(self.hosts) != 1 or len(self.forwarded_hosts) > 1:
            return False
        return all(host_name(h) == serve_host for h in self.hosts + self.forwarded_hosts)

    def peer_ip(self) -> str | None:
        if self.proto != "https" or len(self.forwarded_for) != 1:
            return None
        try:
            return str(ipaddress.ip_address(self.forwarded_for[0]))
        except ValueError:
            return None


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    node_id: str
    node_name: str
    dns_name: str
    login: str
    tags: tuple[str, ...]

    @classmethod
    def from_whois(cls, raw: dict) -> PeerIdentity | None:
        """None when the whois JSON lacks a field we rely on, which decide() treats like an unknown peer."""
        node, profile = raw.get("Node"), raw.get("UserProfile")
        if not isinstance(node, dict) or not isinstance(profile, dict):
            return None
        fields = (node.get("StableID"), node.get("ComputedName"), node.get("Name"), profile.get("LoginName"))
        tags = node.get("Tags") or []
        if not all(isinstance(f, str) and f for f in fields) or not isinstance(tags, list):
            return None
        stable_id, computed, name, login = fields
        return cls(stable_id, computed, name.rstrip("."), login, tuple(str(t) for t in tags))

    def matches(self, entry: str) -> bool:
        name = entry.rstrip(".").lower()
        return entry == self.node_id or name == self.node_name.lower() or name == self.dns_name.lower()


@dataclasses.dataclass(frozen=True)
class Grant:
    audience: Audience
    peer: PeerIdentity


def serve_refusal(facts: ServeFacts, serve_host: str) -> Refusal | None:
    if not facts.asked_for(serve_host):
        return Refusal(RefusalCode.WRONG_HOST)
    if facts.peer_ip() is None:
        return Refusal(RefusalCode.NOT_BEHIND_SERVE)
    if facts.funnel:
        return Refusal(RefusalCode.FUNNEL_REQUEST)
    return None


def lookup_peer(facts: ServeFacts, whois: Whois) -> PeerIdentity | None:
    raw = whois(facts.peer_ip())
    return PeerIdentity.from_whois(raw) if raw is not None else None


def decide(facts: ServeFacts, origin: str | None, automation_reported: bool, config: IssuerConfig, whois: Whois, serve_host: str) -> Grant | Refusal:
    if refusal := serve_refusal(facts, serve_host):
        return refusal
    audience = config.audiences.get(origin) if origin is not None else None
    if audience is None:
        return Refusal(RefusalCode.UNKNOWN_AUDIENCE)
    peer = lookup_peer(facts, whois)
    if peer is None:
        return Refusal(RefusalCode.UNKNOWN_PEER)
    if peer.tags:
        return Refusal(RefusalCode.TAGGED_NODE, peer.node_name)
    if facts.login is not None and facts.login != peer.login:
        return Refusal(RefusalCode.IDENTITY_MISMATCH, peer.node_name)
    if not any(peer.matches(entry) for entry in audience.devices):
        return Refusal(RefusalCode.NOT_ON_ALLOWLIST, peer.node_name)
    if audience.users is not None and peer.login not in audience.users:
        return Refusal(RefusalCode.USER_NOT_ALLOWED, peer.node_name)
    if audience.refuse_automation and (automation_reported or "HeadlessChrome" in facts.user_agent):
        return Refusal(RefusalCode.AUTOMATION, peer.node_name)
    return Grant(audience, peer)


def mint(grant: Grant, config: IssuerConfig, now: int) -> str:
    claim = Claim(
        node_id=grant.peer.node_id,
        node_name=grant.peer.node_name,
        login=grant.peer.login,
        audience=grant.audience.origin,
        issued_at=now,
        expires_at=now + config.ttl_seconds,
        nonce=new_nonce(),
    )
    return encode(claim, derive_consumer_key(config.master, grant.audience.origin))
