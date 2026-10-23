from __future__ import annotations

import json
import subprocess
import sys

from .decision import Whois


def cli_whois(tailscale_bin: str, timeout: float = 5.0) -> Whois:
    """`tailscale whois --json IP` through the CLI, the one path that works with both the macOS app and Linux tailscaled."""

    def whois(ip: str) -> dict | None:
        try:
            done = subprocess.run([tailscale_bin, "whois", "--json", ip], capture_output=True, timeout=timeout, check=False)
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
