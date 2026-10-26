"""share, unshare and guests: the guest commands written for an agent to run. They never prompt, take --json and --dry-run,
and exit with a code per kind of failure (EXIT). share also checks its own work against the live gate."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import enum
import html.parser
import http.client
import json
import os
import secrets
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlsplit

LOOPBACK = ("localhost", "127.0.0.1", "::1")

from ..issuer.config import ConfigError
from .config import GateConfig, OpenRule, load_config, parse_guest_path, site_key
from .credentials import GUESTS_DIR, Grants, Guest, guest_digest, guest_records, parse_guest_line, write_guest_records
from .decision import LOGIN_PATH
from .password import generate_passphrase, write_private
from .session import COOKIE, CSRF_COOKIE, GUEST_NAME

DEFAULT_CONFIG = "~/.config/tailisman/gate.toml"
USER_AGENT = "tailisman-share-check/1"


class Exit(enum.IntEnum):
    OK = 0
    USAGE = 2
    CONFIG = 3
    NOT_FOUND = 4
    CHECK_FAILED = 5
    UNREACHABLE = 6
    STILL_PUBLIC = 7


class Failure(Exception):
    def __init__(self, code: Exit, error: str, message: str, next_steps: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.code, self.error, self.message, self.next_steps = code, error, message, next_steps


@dataclasses.dataclass(frozen=True)
class Target:
    """One shared URL: a whole site (rule None, from a URL whose path is /), a folder (path ends in /) or an exact link."""

    host: str
    rule: OpenRule | None
    origin: str = ""

    @classmethod
    def parse(cls, url: str) -> Target:
        parts = urlsplit(url.strip())
        if parts.scheme not in ("http", "https") or not parts.netloc or "@" in parts.netloc:
            raise Failure(Exit.USAGE, "bad_url", f"{url!r} is not a full http(s) URL such as https://notes.example.com/reports/", ("pass the full URL, scheme included",))
        host = site_key(parts.netloc)
        if host is None:
            raise Failure(Exit.USAGE, "bad_url", f"{url!r} has no usable host name")
        path = quote(parts.path or "/", safe="/%!$&'()*+=:@")
        origin = f"{parts.scheme}://{parts.netloc}"
        if path == "/":
            return cls(host, None, origin)
        try:
            return cls(host, parse_guest_path(path + "*" if path.endswith("/") else path), origin)
        except ConfigError as exc:
            raise Failure(Exit.USAGE, "bad_url", str(exc), ("share a plain path: no .., no //, no encoded / or . and no comma",)) from exc

    @property
    def path(self) -> str:
        return self.rule.path if self.rule else "/"

    def describe(self) -> dict:
        return scope_entry(self.host, self.rule, self.origin)


def scope_entry(host: str, rule: OpenRule | None, origin: str = "") -> dict:
    kind = "site" if rule is None else "folder" if rule.prefix else "link"
    path = rule.path if rule else "/"
    return {"url": f"{origin or 'https://' + host}{path}", "host": host, "path": path, "kind": kind}


def scopes(grants: Grants) -> list[dict]:
    return [scope_entry(host, rule) for host, rules in grants.items() for rule in (rules or (None,))]


def add_commands(commands: argparse._SubParsersAction) -> dict[str, Callable[[argparse.Namespace], int]]:
    share = commands.add_parser("share", help="let one named guest into one URL (a folder if it ends in /, else that exact link), creating the guest if needed, then check it live")
    share.add_argument("url", help="the full URL to share, such as https://notes.example.com/reports/ or https://notes.example.com/reports/may.html")
    share.add_argument("--to", required=True, metavar="NAME", help="the guest: 1 to 32 of a-z, 0-9, _ and -")
    share.add_argument("--close-open-rule", action="store_true", help="remove open rules in gate.toml that sit inside the shared scope, so the page needs the password (gate.toml is backed up first)")
    share.add_argument("--new-password", action="store_true", help="give an existing guest a new passphrase, which signs them out everywhere")
    share.add_argument("--print-once", action="store_true", help="put the passphrase in the output and delete its file; only when a person asked to see it")
    share.add_argument("--no-check", action="store_true", help="skip the live check against the gate")
    share.add_argument("--base-url", metavar="URL", help="send the live check to URL (such as http://127.0.0.1:8471) instead of the shared URL's own origin, with HOST as the Host header")
    unshare = commands.add_parser("unshare", help="take one URL back from a guest, or with no URL remove the guest; their sessions there end on the next request")
    unshare.add_argument("url", nargs="?", help="the URL as it was shared; omit it to remove the guest altogether")
    unshare.add_argument("--from", dest="name", required=True, metavar="NAME")
    guests = commands.add_parser("guests", help="list guests, what each may open, and where an undelivered passphrase file sits")
    guests.add_argument("name", nargs="?", help="only this guest")
    for parser in (share, unshare, guests):
        parser.add_argument("--config", default=os.environ.get("TAILISMAN_GATE_CONFIG", DEFAULT_CONFIG), help=f"the gate's gate.toml (default $TAILISMAN_GATE_CONFIG, else {DEFAULT_CONFIG})")
        parser.add_argument("--json", action="store_true", help="print one JSON object; ok, exit, warnings and next_steps are always there")
        parser.add_argument("--dry-run", action="store_true", help="say what would change and change nothing")
    return {"share": lambda a: _run(a, _share), "unshare": lambda a: _run(a, _unshare), "guests": lambda a: _run(a, _guests)}


def _run(args: argparse.Namespace, command: Callable[[argparse.Namespace, dict], Exit]) -> int:
    report: dict = {"command": args.command, "ok": False, "dry_run": args.dry_run, "warnings": [], "next_steps": []}
    try:
        code = command(args, report)
    except Failure as failure:
        code = failure.code
        report |= {"error": failure.error, "message": failure.message}
        report["next_steps"] += list(failure.next_steps)
    except OSError as exc:
        code = Exit.CONFIG
        report |= {"error": "file", "message": f"could not read or write a gate file: {exc}"}
        report["next_steps"].append("check the path and its permissions; the gate's files belong to the user the gate runs as")
    report["ok"] = code is Exit.OK
    report["exit"] = int(code)
    _emit(report, args.json)
    return int(code)


def _load(args: argparse.Namespace) -> GateConfig:
    path = Path(os.path.expanduser(args.config))
    try:
        return load_config(path)
    except ConfigError as exc:
        raise Failure(Exit.CONFIG, "config", str(exc), (f"pass --config with the gate's gate.toml, or set TAILISMAN_GATE_CONFIG",)) from exc


def _guest_dir(config: GateConfig) -> Path:
    assert config.source is not None
    return config.source.parent / GUESTS_DIR


def _check_name(name: str) -> None:
    if not GUEST_NAME.fullmatch(name):
        raise Failure(Exit.USAGE, "bad_name", f"guest name {name!r} must be 1 to 32 of a-z, 0-9, _ and -, starting with a letter or digit")


def _current_guest(config: GateConfig, name: str) -> Guest | None:
    line = guest_records(config.guest_file).get(name)
    return parse_guest_line(line) if line else None


# share


def _share(args: argparse.Namespace, report: dict) -> Exit:
    _check_name(args.to)
    target = Target.parse(args.url)
    config = _load(args)
    report |= {"guest": args.to, "host": target.host, "scope": target.describe(), "config": str(config.source)}
    site = config.sites.get(target.host)
    if site is None:
        raise Failure(Exit.CONFIG, "not_gated", f"{target.host} is not a [[sites]] host of {config.source}; its sites are {', '.join(config.sites)}", ("add a [[sites]] entry for the host first (docs/GATE.md, Config)",))
    current = _current_guest(config, args.to)
    grants = _with_target(current.grants if current else {}, target)
    passphrase_file = _guest_dir(config) / args.to
    new_password = current is None or args.new_password
    report["created"] = current is None
    report["changed"] = current is None or args.new_password or grants != current.grants
    report["scopes"] = scopes(grants)
    if current is not None and not report["changed"]:
        report["warnings"].append(f"{args.to} could already open {target.describe()['url']}; nothing changed")

    inside, wider = _open_rules(site.open, target)
    report["open_rules"] = {"inside": [str(r) for r in inside], "wider": [str(r) for r in wider], "closed": [], "backup": None}
    still_public = [str(r) for r in wider] + ([] if args.close_open_rule else [str(r) for r in inside])
    if target.rule is None:
        still_public = []
        if site.open:
            report["warnings"].append(f"open rules on {site.host} stay open to everyone: {', '.join(map(str, site.open))}")

    if args.dry_run:
        report["password_file"] = str(passphrase_file)
        report["checks"] = []
        report["next_steps"].append("run the same command without --dry-run")
        return _still_public(report, still_public, args) if still_public else Exit.OK

    passphrase = generate_passphrase() if new_password else _read_passphrase(passphrase_file)
    if args.print_once and passphrase is None:
        raise Failure(Exit.NOT_FOUND, "no_passphrase_file", f"{passphrase_file} is gone, so there is no passphrase to print", (f"rerun with --new-password --print-once, which signs {args.to} out",))
    if args.close_open_rule and inside and target.rule is not None:
        report["open_rules"]["backup"] = str(close_open_rules(config, site.host, inside))
        report["open_rules"]["closed"] = [str(r) for r in inside]
    if new_password:
        directory = passphrase_file.parent
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        write_private(passphrase_file, passphrase + "\n", overwrite=True)
    digest = guest_digest(passphrase) if new_password else current.digest
    records = guest_records(config.guest_file)
    records[args.to] = Guest(args.to, grants, digest).line()
    write_guest_records(config.guest_file, records)

    report["checks"] = [] if args.no_check else check_share(args.base_url, target, Guest(args.to, grants, digest), passphrase, report)
    if passphrase is None:
        report["warnings"].append(f"{passphrase_file} is gone, so the check signed in as nobody; {args.to} keeps the passphrase they were given")
    if args.print_once and passphrase is not None:
        report["password"] = passphrase
        passphrase_file.unlink(missing_ok=True)
        report["password_file"] = None
    else:
        report["password_file"] = str(passphrase_file) if passphrase_file.exists() else None
    if report["password_file"]:
        report["next_steps"].append(f"send the passphrase in {passphrase_file} to {args.to} over a private channel, then delete the file")
    report["next_steps"].append(f"give {args.to} the link {target.describe()['url']}")
    if still_public:
        return _still_public(report, still_public, args)
    failed = [check for check in report["checks"] if not check["ok"]]
    if any(check.get("unreachable") for check in failed):
        report["next_steps"].append("is the gate running? `tailisman gate status --config ...` checks every site")
        return Exit.UNREACHABLE
    if failed:
        report["next_steps"].append("read the gate's log: a gate.toml that did not load, or that needs a restart, is logged there")
        return Exit.CHECK_FAILED
    return Exit.OK


def _still_public(report: dict, rules: list[str], args: argparse.Namespace) -> Exit:
    inside = report["open_rules"]["inside"]
    report["warnings"].append(f"anyone can still open {report['scope']['url']} through the open rule(s) {', '.join(rules)}")
    if inside and not args.close_open_rule:
        report["next_steps"].append("rerun with --close-open-rule to remove the open rules inside the shared scope")
    if report["open_rules"]["wider"]:
        report["next_steps"].append(f"narrow or remove {', '.join(report['open_rules']['wider'])} in gate.toml by hand; share never removes an open rule wider than what it shares")
    return Exit.STILL_PUBLIC


def _with_target(grants: Grants, target: Target) -> Grants:
    """Adding never narrows: a whole-site grant stays whole, and a scope already held is not repeated."""
    out = dict(grants)
    rules = out.get(target.host)
    if target.rule is None:
        out[target.host] = ()
    elif rules is None:
        out[target.host] = (target.rule,)
    elif rules and target.rule not in rules:
        out[target.host] = rules + (target.rule,)
    return out


def _open_rules(rules: tuple[OpenRule, ...], target: Target) -> tuple[list[OpenRule], list[OpenRule]]:
    """The open rules that expose part of the target: those inside it, which share may close, and those wider than it, which it never does.
    Compared without case, since an app on a case-insensitive filesystem serves /Reports/ for /reports/."""
    inside, wider = [], []
    for rule in rules:
        path, shared = rule.path.lower(), target.rule.path.lower() if target.rule else "/"
        if target.rule is None:
            inside.append(rule)
        elif path.startswith(shared) and (target.rule.prefix or (path == shared and not rule.prefix)):
            inside.append(rule)
        elif rule.prefix and shared.startswith(path):
            wider.append(rule)
    return inside, wider


def _read_passphrase(path: Path) -> str | None:
    try:
        return path.read_text().strip() or None
    except OSError:
        return None


def close_open_rules(config: GateConfig, host: str, remove: list[OpenRule]) -> Path:
    """Rewrites one site's `open = [...]` in gate.toml without those rules, keeping every other line. The rewrite is loaded
    and compared before it replaces the file, so an edit this cannot make cleanly is refused rather than guessed."""
    assert config.source is not None
    source = config.source.resolve()
    lines = source.read_text().splitlines(keepends=True)
    start, end = _open_array(lines, host)
    if start is None:
        raise Failure(Exit.CONFIG, "open_rule_edit", f"could not find {host}'s open = [...] in {source}", (f"remove {', '.join(map(str, remove))} from it by hand",))
    kept = [rule for rule in config.sites[host].open if rule not in remove]
    indent = lines[start][: len(lines[start]) - len(lines[start].lstrip())]
    comment = _trailing_comment(lines[end]) if kept else ""
    replacement = f"{indent}open = [{', '.join(json.dumps(str(rule)) for rule in kept)}]{comment}\n"
    text = "".join(lines[:start] + [replacement] + lines[end + 1 :])
    temp = source.with_name(f".{source.name}.{secrets.token_hex(4)}.tmp")
    try:
        write_private(temp, text, overwrite=False)
        os.chmod(temp, source.stat().st_mode & 0o777)
        fresh = load_config(temp)
        expected = dataclasses.replace(config.sites[host], open=tuple(kept))
        if fresh.sites != config.sites | {host: expected} or dataclasses.replace(fresh, sites={}, source=None) != dataclasses.replace(config, sites={}, source=None):
            raise ConfigError("the rewritten file did not parse to the same config minus those rules")
        backup = source.with_name(f"{source.name}.bak-share-{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}")
        shutil.copy2(source, backup)
        os.replace(temp, source)
    except ConfigError as exc:
        raise Failure(Exit.CONFIG, "open_rule_edit", f"could not remove the open rules from {source} cleanly: {exc}", (f"remove {', '.join(map(str, remove))} by hand",)) from exc
    finally:
        temp.unlink(missing_ok=True)
    return backup


def _open_array(lines: list[str], host: str) -> tuple[int | None, int]:
    block = False
    for number, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            block = stripped == "[[sites]]" and _block_host(lines, number + 1) == host
            continue
        if block and stripped.startswith("open") and stripped[4:].lstrip().startswith("="):
            for end in range(number, len(lines)):
                if "]" in lines[end].split("#", 1)[0]:
                    return number, end
    return None, 0


def _block_host(lines: list[str], start: int) -> str | None:
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("["):
            return None
        key, sep, value = stripped.partition("=")
        if sep and key.strip() == "host":
            return site_key(value.split("#", 1)[0].strip().strip('"'))
    return None


def _trailing_comment(line: str) -> str:
    code, sep, comment = line.rstrip("\n").partition("#")
    return f"   #{comment}" if sep and "]" in code else ""


# The live check


@dataclasses.dataclass
class _Answer:
    status: int
    location: str
    cookies: dict[str, str]
    content_type: str
    body: bytes


def check_share(base_url: str | None, target: Target, guest: Guest, passphrase: str | None, report: dict) -> list[dict]:
    """What a stranger and the guest each get, through the same front door a browser uses."""
    base = urlsplit(base_url or target.origin)
    checks: list[dict] = []
    landing = target.path
    if base.scheme != "https" and base.hostname not in LOOPBACK and passphrase is not None:
        report["warnings"].append(f"{base.geturl()} is plain http and not this machine, so the check did not send the passphrase there; use an https URL or --base-url http://127.0.0.1:PORT")
        passphrase = None

    def get(path: str, cookie: str | None = None) -> _Answer:
        return _request(base, target.host, "GET", path, cookie)

    def record(name: str, path: str, ok: bool, answer: _Answer | None, expected: str) -> None:
        checks.append({"name": name, "path": path, "ok": ok, "status": answer.status if answer else None, "expected": expected} | ({"unreachable": True} if answer is None else {}))

    try:
        anonymous = get(landing)
        signs_in = _is_sign_in(anonymous)
        record("anonymous_gets_sign_in", landing, signs_in, anonymous, "302 to the sign-in page")
        if passphrase is None:
            return checks
        form = get(f"{LOGIN_PATH}?next={quote(landing, safe='')}")
        csrf = form.cookies.get(CSRF_COOKIE, "")
        body = urlencode({"csrf": csrf, "password": passphrase, "next": landing}).encode()
        login = _request(base, target.host, "POST", LOGIN_PATH, f"{CSRF_COOKIE}={csrf}", body)
        session = login.cookies.get(COOKIE)
        record("guest_signs_in", LOGIN_PATH, login.status == 303 and bool(session) and login.location == landing, login, f"303 to {landing} with a session cookie")
        if not session:
            return checks
        inside = get(landing, f"{COOKIE}={session}")
        record("guest_opens_scope", landing, inside.status == 200, inside, "200")
        outside = _outside_path(guest, target.host)
        if outside is not None:
            refused = get(outside, f"{COOKIE}={session}")
            record("guest_refused_outside", outside, _is_sign_in(refused), refused, "302 to the sign-in page")
        if inside.status == 200 and inside.content_type.startswith("text/html"):
            _note_outside_references(inside.body, target, guest, report)
    except (OSError, http.client.HTTPException) as exc:
        report["warnings"].append(f"could not reach {base.geturl()}: {exc}")
        record("gate_reachable", landing, False, None, "an answer")
    return checks


def _outside_path(guest: Guest, host: str) -> str | None:
    for path in ("/", "/.tailisman-share-check-outside"):
        if not guest.allows(host, path):
            return path
    return None


def _is_sign_in(answer: _Answer) -> bool:
    return answer.status == 302 and answer.location.startswith(LOGIN_PATH)


def _request(base, host: str, method: str, path: str, cookie: str | None, body: bytes | None = None) -> _Answer:
    connection = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    conn = connection(base.netloc, timeout=15)
    headers = {"Host": host, "Accept": "text/html", "User-Agent": USER_AGENT}
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        cookies = {}
        for value in response.msg.get_all("Set-Cookie") or []:
            name, _, rest = value.split(";", 1)[0].partition("=")
            cookies[name.strip()] = rest.strip()
        return _Answer(response.status, response.getheader("Location") or "", cookies, response.getheader("Content-Type") or "", response.read(4 * 1024 * 1024))
    finally:
        conn.close()


class _References(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("src"):
            self.assets.append(values["src"])
        if values.get("href"):
            (self.links if tag == "a" else self.assets if tag == "link" else []).append(values["href"])


def _note_outside_references(body: bytes, target: Target, guest: Guest, report: dict) -> None:
    """Same-origin src and href the shared page uses that the guest cannot open; they would get the sign-in page for each."""
    parser = _References()
    parser.feed(body.decode("utf-8", "replace"))
    page = f"https://{target.host}{target.path}"

    def outside(references: list[str]) -> list[str]:
        found = []
        for reference in references:
            url = urlsplit(urljoin(page, reference.strip()))
            if url.scheme in ("http", "https") and site_key(url.netloc) == target.host and not url.path.startswith("/.tailisman/"):
                if not guest.allows(target.host, url.path or "/") and url.path not in found:
                    found.append(url.path or "/")
        return found

    assets, links = outside(parser.assets), outside(parser.links)
    report["outside_scope"] = {"assets": assets, "links": links}
    if assets:
        report["warnings"].append(f"the page loads {', '.join(assets)}, which {guest.name} cannot open")
        report["next_steps"].append(f"share those too (one `tailisman share` each), or share the folder that holds the page and them")
    if links:
        report["warnings"].append(f"the page links to {', '.join(links)}, which {guest.name} would see as a sign-in page")


# unshare and guests


def _unshare(args: argparse.Namespace, report: dict) -> Exit:
    _check_name(args.name)
    config = _load(args)
    current = _current_guest(config, args.name)
    report |= {"guest": args.name, "config": str(config.source)}
    if current is None:
        known = ", ".join(sorted(name for name in guest_records(config.guest_file) if not name.startswith(" "))) or "none"
        raise Failure(Exit.NOT_FOUND, "no_such_guest", f"no guest named {args.name!r} (guests: {known})", ("`tailisman guests` lists them",))
    grants = dict(current.grants)
    if args.url is not None:
        target = Target.parse(args.url)
        report["scope"] = target.describe()
        rules = grants.get(target.host)
        if rules is None or (target.rule is None) != (rules == ()) or (target.rule is not None and target.rule not in rules):
            held = ", ".join(entry["url"] for entry in scopes(current.grants))
            raise Failure(Exit.NOT_FOUND, "not_shared", f"{args.name} was not given {target.describe()['url']}; they hold {held}", (f"unshare one of those, or omit the URL to remove {args.name}",))
        remaining = tuple(rule for rule in rules if rule != target.rule)
        if remaining:
            grants[target.host] = remaining
        else:
            del grants[target.host]
    else:
        grants = {}
    report["removed_guest"] = not grants
    report["scopes"] = scopes(grants)
    passphrase_file = _guest_dir(config) / args.name
    report["deleted_files"] = [str(passphrase_file)] if not grants and passphrase_file.exists() else []
    if args.dry_run:
        report["next_steps"].append("run the same command without --dry-run")
        return Exit.OK
    records = guest_records(config.guest_file)
    if grants:
        records[args.name] = Guest(args.name, grants, current.digest).line()
    else:
        del records[args.name]
        passphrase_file.unlink(missing_ok=True)
    write_guest_records(config.guest_file, records)
    return Exit.OK


def _guests(args: argparse.Namespace, report: dict) -> Exit:
    config = _load(args)
    report["config"] = str(config.source)
    listed = []
    for name, line in guest_records(config.guest_file).items():
        guest = parse_guest_line(line)
        if guest is None or (args.name and name != args.name):
            continue
        passphrase_file = _guest_dir(config) / name
        listed.append({"name": name, "scopes": scopes(guest.grants), "password_file": str(passphrase_file) if passphrase_file.exists() else None})
    if args.name and not listed:
        raise Failure(Exit.NOT_FOUND, "no_such_guest", f"no guest named {args.name!r}", ("`tailisman guests` lists them",))
    report["guests"] = listed
    return Exit.OK


def _emit(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return
    out = sys.stdout if report["ok"] else sys.stderr
    if "message" in report:
        print(f"tailisman: {report['message']}", file=out)
    if report["command"] == "guests" and "guests" in report:
        for guest in report["guests"]:
            waiting = f" (passphrase not handed over yet: {guest['password_file']})" if guest["password_file"] else ""
            print(f"{guest['name']}: {', '.join(entry['url'] for entry in guest['scopes'])}{waiting}", file=out)
        if not report["guests"]:
            print("no guests", file=out)
    elif "scopes" in report:
        verb = "would" if report["dry_run"] else "can"
        who = report.get("guest", "")
        if report.get("removed_guest"):
            print(f"{who} {'would be' if report['dry_run'] else 'is'} removed; their sessions end on the next request", file=out)
        else:
            print(f"{who} {verb} open: {', '.join(entry['url'] for entry in report['scopes'])}", file=out)
    for closed in report.get("open_rules", {}).get("closed", []):
        print(f"closed open rule {closed} (backup {report['open_rules']['backup']})", file=out)
    for check in report.get("checks", []):
        print(f"check {check['name']} {check['path']}: {'ok' if check['ok'] else 'FAILED'} ({check['status']}, expected {check['expected']})", file=out)
    if report.get("password"):
        print(f"passphrase (shown once, file deleted): {report['password']}", file=out)
    elif report.get("password_file"):
        print(f"passphrase file: {report['password_file']}", file=out)
    for warning in report["warnings"]:
        print(f"warning: {warning}", file=out)
    for step in report["next_steps"]:
        print(f"next: {step}", file=out)
