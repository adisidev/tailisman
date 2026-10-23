"""Load the demo consumer in a real browser and check the outcome. Prints one JSON line of evidence; exits 1 on mismatch.

    uv run --with playwright python e2e/browser_check.py --demo https://demo.example.com --browser chromium --grant-lna --expect signed-in
    uv run --with playwright python e2e/browser_check.py --demo https://demo.example.com --browser webkit --transport navigate --expect signed-in

--grant-lna grants Chromium's local-network-access permission to the demo origin, and for Firefox sets
network.lna.blocking=false (Firefox has no Playwright permission for it, so this turns the check off rather than granting it).
--spoof-automation hides the automation signals the snippet reports (navigator.webdriver, Playwright's and ChromeDriver's
globals, AutomationControlled, HeadlessChrome in the user agent), to show that refuse_automation is best effort.
--simulate-off-tailnet makes every *.ts.net name fail to resolve in Chrome, which is what a visitor off the tailnet sees.
See e2e/LIVE.md for the full live sequence.
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

PENDING = ("pending", "waiting-for-click")
CHROMIUM = ("chrome", "chromium")
HIDE_AUTOMATION = """
Object.defineProperty(Navigator.prototype, "webdriver", { get: () => false, configurable: true });
for (const name of Object.getOwnPropertyNames(window)) {
  if (/^(__pw|__playwright|cdc_)/.test(name)) delete window[name];
}
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", required=True)
    parser.add_argument("--browser", choices=["chrome", "chromium", "webkit", "firefox"], default="chromium")
    parser.add_argument("--grant-lna", action="store_true")
    parser.add_argument("--expect", choices=["signed-in", "unreachable", "refused"], required=True)
    parser.add_argument("--transport", choices=["silent", "navigate"], default="silent")
    parser.add_argument("--screenshot")
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--timeout", type=float, default=30, help="seconds to wait for an outcome")
    parser.add_argument("--spoof-automation", action="store_true", help="hide navigator.webdriver, automation globals and HeadlessChrome")
    parser.add_argument("--simulate-off-tailnet", action="store_true", help="Chrome only: make *.ts.net names unresolvable")
    args = parser.parse_args()
    if args.simulate_off_tailnet and args.browser not in CHROMIUM:
        parser.error("--simulate-off-tailnet needs --browser chrome or chromium")
    demo = args.demo.rstrip("/")
    origin = "{0.scheme}://{0.netloc}".format(urlsplit(demo))

    with sync_playwright() as p:
        engine = {"chrome": p.chromium, "chromium": p.chromium, "webkit": p.webkit, "firefox": p.firefox}[args.browser]
        launch = {"headless": not args.headed, "args": []}
        if args.browser == "chrome":
            launch["channel"] = "chrome"
        if args.browser == "firefox" and args.grant_lna:
            launch["firefox_user_prefs"] = {"network.lna.blocking": False}
        if args.simulate_off_tailnet:
            launch["args"].append("--host-resolver-rules=MAP *.ts.net ~NOTFOUND")
        if args.spoof_automation and args.browser in CHROMIUM:
            launch["args"].append("--disable-blink-features=AutomationControlled")
        browser = engine.launch(**launch)
        context_options = {}
        if args.spoof_automation and args.browser in CHROMIUM:
            major = browser.version.split(".")[0]
            context_options["user_agent"] = f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
        context = browser.new_context(**context_options)
        if args.spoof_automation:
            context.add_init_script(HIDE_AUTOMATION)
        if args.grant_lna and args.browser in ("chrome", "chromium"):
            context.grant_permissions(["local-network-access"], origin=origin)
        page = context.new_page()
        console = []
        page.on("console", lambda message: console.append(message.text))
        timeout_ms = args.timeout * 1000

        page.goto(demo + ("/?silent=0" if args.transport == "navigate" else "/"))
        if args.transport == "navigate":
            page.locator("#tailnet-signin").click(timeout=timeout_ms)
            page.wait_for_load_state("load", timeout=timeout_ms)
            page.wait_for_url(lambda url: url.startswith(demo) or "/v1/start" in url, timeout=timeout_ms)
        if page.url.startswith(demo):
            page.wait_for_function(f"!{json.dumps(list(PENDING))}.includes(document.body.dataset.outcome)", timeout=timeout_ms)
            outcome = page.evaluate("document.body.dataset.outcome")
            state = page.evaluate("fetch('/state', {credentials: 'same-origin'}).then(r => r.json())")
        else:
            outcome = "refused" if "tailisman refused" in page.content() else "unreachable"
            state = None
        has_cookie = any(c["name"] == "demo_session" for c in context.cookies(demo))
        if args.screenshot:
            page.screenshot(path=args.screenshot, full_page=True)
        evidence = {
            "browser": args.browser,
            "version": browser.version,
            "transport": args.transport,
            "grant_lna": args.grant_lna,
            "spoof_automation": args.spoof_automation,
            "simulate_off_tailnet": args.simulate_off_tailnet,
            "expect": args.expect,
            "outcome": outcome,
            "cookie": has_cookie,
            "state": state,
            "url": page.url,
            "result_text": page.locator("#result").text_content() if page.url.startswith(demo) else None,
            "console": console[-5:],
        }
        browser.close()

    evidence["ok"] = outcome == args.expect and has_cookie == (args.expect == "signed-in")
    print(json.dumps(evidence))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
