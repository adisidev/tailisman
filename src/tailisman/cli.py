"""The `tailisman` command: the issuer's keygen, key, run and check, and the gate's gate run, gate status, passwd, share, unshare and guests."""

from __future__ import annotations

import argparse
import sys

from . import guide
from .gate import cli as gate_cli
from .issuer import cli as issuer_cli
from .issuer.config import ConfigError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tailisman",
        usage="tailisman guide [TOPIC]   (start here: how to lock pages, share them and fix problems)\n       tailisman COMMAND ...",
        description="Tell a public web app that its visitor is on one of your tailnet devices.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    handlers = guide.add_commands(commands) | issuer_cli.add_commands(commands) | gate_cli.add_commands(commands)
    args = parser.parse_args(argv)
    try:
        return handlers[args.command](args)
    except ConfigError as exc:
        print(f"tailisman: config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
