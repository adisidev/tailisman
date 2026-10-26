"""`tailisman guide`: the agent guide (skills/tailisman/SKILL.md and its references), shipped inside the package so an
installed CLI documents itself with no clone and no skill install."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

PACKAGED = Path(__file__).with_name("guide_files")
CHECKOUT = Path(__file__).resolve().parents[2] / "skills" / "tailisman"
SHARE_HEADING = "## Share a page with someone"
PROBLEMS_HEADING = "## What can go wrong"

TOPICS: dict[str, tuple[str, str, str | None]] = {
    "share": ("give someone a password for a page or folder, take it back, list who has what", "SKILL.md", SHARE_HEADING),
    "lock": ("set the gate up in front of pages, from discovery to the final checks", "SKILL.md", None),
    "problems": ("what can go wrong once it runs", "SKILL.md", PROBLEMS_HEADING),
    "front-doors": ("finding and configuring Cloudflare Tunnel, Caddy, nginx and tailscale serve", "references/front-doors.md", None),
    "cloudflare": ("tunnel API, cache purge, timeouts", "references/cloudflare.md", None),
}


def add_commands(commands: argparse._SubParsersAction) -> dict[str, Callable[[argparse.Namespace], int]]:
    guide = commands.add_parser("guide", help="start here: print the agent guide for a topic (run it with no topic for the list)")
    guide.add_argument("topic", nargs="?", choices=sorted(TOPICS))
    return {"guide": _guide}


def _guide(args: argparse.Namespace) -> int:
    if args.topic is None:
        print("tailisman guide TOPIC prints the part of the agent guide you need:\n")
        for name, (summary, _, _) in TOPICS.items():
            print(f"  {name:<12} {summary}")
        print("\nTo give someone access to a page, start with `tailisman guide share`.")
        return 0
    _, name, heading = TOPICS[args.topic]
    root = PACKAGED if (PACKAGED / "SKILL.md").is_file() else CHECKOUT
    try:
        text = (root / name).read_text()
    except OSError as exc:
        print(f"tailisman: the guide is missing from this install ({exc}); read https://github.com/adisidev/tailisman/blob/main/skills/tailisman/{name}", file=sys.stderr)
        return 1
    sys.stdout.write(section(text, heading) if heading else text)
    return 0


def section(text: str, heading: str) -> str:
    """From the heading to the next heading of the same level."""
    start = text.index(heading + "\n")
    level = heading.split(" ", 1)[0] + " "
    end = text.find("\n" + level, start + len(heading))
    return text[start : end + 1 if end >= 0 else len(text)]
