"""The gate in a real browser: Playwright Chromium against the e2e stack with Caddy serving its own TLS on loopback.

One gate process holds both listeners: the public one behind Caddy, and the tailnet one behind the serve stand-in,
which hands out the one-time codes the public one redeems.

    uv run --with playwright python e2e/gate_browser_check.py [--screenshots DIR] [--headed]

Chromium resolves *.example.com and *.example.net to 127.0.0.1 and accepts Caddy's internal certificate. The page then
sits in Chrome's loopback address space, like the serve stand-in, so the gate config sets the test knob
[tailnet] address_space = "loopback"; on a real tailnet it stays "local". Prints one line per check, exits 1 on any failure.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_e2e import CODE_SECONDS, NOTES, SOLO, TOOLS, Checks, Stack  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", default=shutil.which("caddy") or "/opt/homebrew/bin/caddy")
    parser.add_argument("--screenshots", type=Path)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    stack = Stack(args.caddy, tls=True, keep=args.keep).start()
    c = Checks()
    port = stack.ports["caddy"]
    tools, notes, solo = f"https://{TOOLS}:{port}", f"https://{NOTES}:{port}", f"https://{SOLO}:{port}"
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)

    def shot(page, name):
        if args.screenshots:
            page.screenshot(path=str(args.screenshots / f"{name}.png"))

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not args.headed, args=["--host-resolver-rules=MAP *.example.com 127.0.0.1, MAP *.example.net 127.0.0.1"])
            print(f"chromium {browser.version}, caddy on 127.0.0.1:{port} with its internal CA")

            def context():
                return browser.new_context(ignore_https_errors=True, viewport={"width": 420, "height": 640})

            silent = context().new_page()
            console = []
            silent.on("console", lambda message: console.append(message.text))
            silent.goto(f"{tools}/notes?tab=1")
            silent.wait_for_selector("text=Recognised laptop, signing you in", timeout=15000)
            c.check("the silent tailnet path shows \"Recognised laptop, signing you in\"", True)
            shot(silent, "1-recognised")
            silent.wait_for_url(f"{tools}/notes?tab=1", timeout=15000)
            c.check("then lands on the page it was asked for, served by the upstream", '"upstream": true' in silent.content(), silent.url)
            cookie = next((x for x in silent.context.cookies() if x["name"] == "tailisman_gate"), None)
            c.check("the browser stored a Secure, HttpOnly, Lax cookie for .example.com", bool(cookie) and cookie["secure"] and cookie["httpOnly"] and cookie["sameSite"] == "Lax" and cookie["domain"] == ".example.com", cookie and {k: cookie[k] for k in ("domain", "secure", "httpOnly", "sameSite")})
            silent.goto(f"{tools}/.tailisman/")
            c.check("the session page names the device", "Signed in from laptop on the tailnet" in silent.content())
            shot(silent, "2-session")
            silent.click("text=Sign out")
            silent.wait_for_url(f"{tools}/.tailisman/login?signed_out=1", timeout=15000)
            silent.wait_for_selector("#tailnet-signin:not([hidden])", timeout=15000)
            c.check("sign out clears the cookie and does not sign straight back in", not any(x["name"] == "tailisman_gate" for x in silent.context.cookies()) and silent.is_visible("text=You are signed out."))
            shot(silent, "3-signed-out")
            c.check("no CSP violations were reported", not any("Content Security Policy" in line for line in console), console[-3:])

            fallback = context().new_page()
            fallback.route(f"{stack.issuer_url}/v1/claim*", lambda route: route.abort())
            fallback.goto(f"{tools}/notes")
            fallback.wait_for_selector("#tailnet-signin:not([hidden])", timeout=15000)
            c.check("an unreachable tailnet listener shows the \"Sign in from this device\" button", fallback.is_visible("text=Sign in from this device"))
            shot(fallback, "4-button")
            fallback.click("#tailnet-signin")
            fallback.wait_for_url(f"{tools}/notes", timeout=15000)
            c.check("the button signs in through the tailnet listener's navigation path", '"upstream": true' in fallback.content(), fallback.url)

            restarting = context().new_page()
            dropped = []
            restarting.route(f"{stack.issuer_url}/v1/claim*", lambda route: (dropped.append(1), route.abort()) if not dropped else route.continue_())
            restarting.goto(f"{tools}/notes?restart=1")
            restarting.wait_for_url(f"{tools}/notes?restart=1", timeout=15000)
            c.check("a tailnet listener that is down for the first try (a gate restarting) is tried once more and signs in", '"upstream": true' in restarting.content() and dropped == [1], restarting.url)

            lost = context().new_page()
            refused = []
            lost.route(f"{tools}/.tailisman/exchange*", lambda route: (refused.append(1), route.fulfill(status=403, content_type="application/json", body='{"error": "malformed"}')) if not refused else route.continue_())
            lost.goto(f"{tools}/notes?lost=1")
            lost.wait_for_url(f"{tools}/notes?lost=1", timeout=15000)
            c.check("a code lost to a gate restart (refused at the exchange) is fetched again once and signs in", '"upstream": true' in lost.content() and refused == [1], lost.url)

            gone = context().new_page()
            gone.route(f"{stack.issuer_url}/v1/claim*", lambda route: route.abort())
            gone.goto(f"{tools}/notes?gone=1")
            gone.wait_for_selector("#tailnet-signin:not([hidden])", timeout=15000)
            c.check("when the listener stays down the page says why and keeps the password and the button", gone.is_visible("text=No tailnet device answered.") and gone.is_visible("#password"))

            claim_js = "issuer => fetch(issuer + '/v1/claim', {targetAddressSpace: 'loopback'}).then(r => r.json()).then(b => b.token)"
            redeem_js = "code => fetch('/.tailisman/exchange', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token: code})}).then(async r => [r.status, await r.json()])"
            codes = context()
            at_tools, at_notes = codes.new_page(), codes.new_page()
            at_tools.goto(f"{tools}/.tailisman/login?signed_out=1")
            at_notes.goto(f"{notes}/.tailisman/login?signed_out=1")
            code = at_tools.evaluate(claim_js, stack.issuer_url)
            first, second = at_tools.evaluate(redeem_js, code), at_tools.evaluate(redeem_js, code)
            c.check("a code the page fetched itself signs in once and is refused as replayed the second time", first[0] == 200 and second == [403, {"error": "replayed"}], (first, second))
            code = at_tools.evaluate(claim_js, stack.issuer_url)
            elsewhere = at_notes.evaluate(redeem_js, code)
            c.check("a code fetched on tools.example.com is refused at notes.example.com", elsewhere == [403, {"error": "wrong_audience"}], elsewhere)
            code = at_tools.evaluate(claim_js, stack.issuer_url)
            time.sleep(CODE_SECONDS + 1)
            late = at_tools.evaluate(redeem_js, code)
            c.check(f"a code redeemed after its {CODE_SECONDS} s lifetime is refused as expired", late == [403, {"error": "expired"}], late)

            form = context().new_page()
            form.goto(f"{solo}/private?x=1")
            c.check("the host-only site has no tailnet section", form.locator("section.tailnet").count() == 0 and form.url.startswith(f"{solo}/.tailisman/login"), form.url)
            form.fill("#password", "not the password")
            form.click("button[type=submit]")
            c.check("a wrong password through the real form shows the generic message", form.is_visible("text=That password did not work."))
            shot(form, "5-wrong-password")
            form.fill("#password", (stack.dir / "passphrase").read_text().strip())
            form.click("button[type=submit]")
            form.wait_for_url(f"{solo}/private?x=1", timeout=15000)
            c.check("the right password through the real form lands on the page asked for", '"upstream": true' in form.content(), form.url)
            browser.close()
    finally:
        stack.stop()
    print("all checks passed" if not c.failed else f"{c.failed} check(s) failed")
    return 1 if c.failed else 0


if __name__ == "__main__":
    sys.exit(main())
