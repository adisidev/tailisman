from __future__ import annotations

import json
import os
import subprocess
import sys

from .config import ConfigError, host_name
from .decision import Whois


def _cli_env() -> dict[str, str]:
    """Under launchd the macOS app binary, started straight from Python, tries to launch its GUI and prints that it failed instead of answering (measured with Tailscale 1.102.4). It answers as the CLI once SHLVL or TERM is set, as any shell sets them."""
    return {"SHLVL": "1", **os.environ}


def cli_whois(tailscale_bin: str, timeout: float = 5.0) -> Whois:
    """`tailscale whois --json IP` through the CLI, the one path that works with both the macOS app and Linux tailscaled."""

    def whois(ip: str) -> dict | None:
        try:
            done = subprocess.run([tailscale_bin, "whois", "--json", ip], capture_output=True, timeout=timeout, check=False, env=_cli_env())
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"tailisman: whois {ip} failed: {exc}", file=sys.stderr)
            return None
        if done.returncode != 0:
            return None
        try:
            raw = json.loads(done.stdout)
        except ValueError:
            return None
        return raw if isinstance(raw, dict) else None

    return whois


def cli_self_dns_name(tailscale_bin: str, timeout: float = 5.0) -> str:
    """This node's MagicDNS name from `tailscale status --json`, the name serve answers on and the only Host the issuer accepts."""
    try:
        done = subprocess.run([tailscale_bin, "status", "--json"], capture_output=True, timeout=timeout, check=False, env=_cli_env())
        name = json.loads(done.stdout)["Self"]["DNSName"]
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
        raise ConfigError(f"could not read this node's MagicDNS name from `tailscale status --json` ({exc!r}); set serve_host") from exc
    host = host_name(name) if isinstance(name, str) else None
    if host is None:
        raise ConfigError(f"`tailscale status --json` gave no usable Self.DNSName ({name!r}); set serve_host")
    return host
