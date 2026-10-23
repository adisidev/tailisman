import stat

from tailisman.issuer.tailscale import cli_whois

GUI_LIKE = """#!/usr/bin/env python3
import os
if "SHLVL" in os.environ or "TERM" in os.environ:
    print('{"Node": {"StableID": "nEXAMPLE1CNTRL"}}')
else:
    print("The Tailscale GUI failed to start")
"""


def test_whois_answers_when_started_without_a_shell_environment(tmp_path, monkeypatch):
    binary = tmp_path / "Tailscale"
    binary.write_text(GUI_LIKE)
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    monkeypatch.delenv("SHLVL", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    assert cli_whois(str(binary))("100.64.0.1") == {"Node": {"StableID": "nEXAMPLE1CNTRL"}}
