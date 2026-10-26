# tailisman

To set it up with a coding agent (Claude Code, Codex, Cursor, Copilot, Gemini CLI, or another), open the agent in your own project or home directory and type this.

```
Lock my personal pages with [tailisman](https://github.com/adisidev/tailisman)
```

An agent reading this follows [skills/tailisman/SKILL.md](skills/tailisman/SKILL.md) (raw: https://raw.githubusercontent.com/adisidev/tailisman/main/skills/tailisman/SKILL.md) from step 1. It is also an installable skill, `npx skills add adisidev/tailisman`. Once the gate runs, the installed CLI carries the same guide: `tailisman guide` lists its topics, and `tailisman guide share` is how an agent gives someone a password for one page or folder.

tailisman lets a public web app learn that the visitor's browser runs on one of your own tailnet devices.

There are two ways to use it.

- The gate is the default. One `tailisman gate run` process sits in front of any number of sites, with no change to the apps, and signs a visitor in from an allowlisted device, a backup password or a guest password. It has its own tailnet listener, so it needs no separate issuer and signs nothing. Start with [docs/GATE.md](docs/GATE.md).
- Token mode is the option for embedding device sign-in in your own app's sessions. The standalone issuer hands the browser a signed claim that lives 60 seconds, and the app verifies it on its server with the Python or Node verifier and turns it into its own session cookie. Most of this README covers token mode; the gate has its own section near the end.

It is for a single owner with a site on the public internet (for example `heckle.example.com` behind Cloudflare) who wants their laptop and phone signed in without a password, and nobody else. It checks the device as well as the user, because the owner's own scripts and agents run as the owner's user.

There are four parts in this repository, all MIT licensed.

- The issuer (token mode) is a small Python HTTP server on a tailnet host, reachable only through `tailscale serve`.
- The browser snippet is `client/tailisman.js`, one ES module with no dependencies.
- The verifiers are a Python package (`tailisman`, standard library only) and a Node package (`js/`, `node:crypto` only).
- The gate (`tailisman gate`) signs visitors in to whole sites, through its own tailnet listener, a backup password or a guest password, with no change to the apps. It proxies sites itself behind a Cloudflare Tunnel, or answers Caddy's `forward_auth`. See [docs/GATE.md](docs/GATE.md).

## How it works

```
 visitor's browser                     public app server                 issuer (tailnet host)
 on laptop.example-tailnet.ts.net      heckle.example.com                behind tailscale serve
 ---------------------------------     ------------------                ---------------------
 page loads the snippet
 fetch https://laptop...:8443/v1/claim  ----------------------------->   serve adds X-Forwarded-For (peer IP)
   (Origin: https://heckle.example.com)                                   and Tailscale-User-Login
                                                                          issuer runs `tailscale whois <IP>`
                                                                          checks allowlist, signs with K_aud
 <------------------------------------------------------------------   {"token": "tsm1...."}
 POST {"token"} to /auth/tailisman  -->  Verifier.verify(token)
                                         checks MAC, aud, exp, nonce
 <-----------------------------------   Set-Cookie: its own session
```

In Playwright's WebKit build (WebKit 27.2, headless) the silent fetch worked without a prompt, and real Safari on macOS did the same when observed once by hand in a private window. Safari on iOS has not been tested. Chrome and Firefox gate it behind a one-time Local Network Access permission per site. When the fetch fails, the snippet shows a button. Clicking it navigates to the issuer, which answers with a form that posts the token back to the same `/auth/tailisman` endpoint. A top-level navigation is never gated, so the button works in every browser.

A visitor who is not on the tailnet cannot resolve the issuer's `*.ts.net` name, so their fetch fails at DNS and they never see a permission prompt. They see the button only, and clicking it leads to a DNS error page.

The token is `tsm1.<base64url payload>.<base64url HMAC-SHA256>`. The payload holds the node stable ID, the short node name, the user login, the audience origin, issue and expiry times, and a random nonce. Each audience has its own key, `K_aud = HMAC-SHA256(master, "tailisman/v1/aud:" + origin)`, so a consumer only ever holds a key that can sign tokens for itself.

## Quickstart

### 1. Run the issuer on a tailnet host

The issuer needs Python 3.11 or later and is not on PyPI.

```sh
uv tool install git+https://github.com/adisidev/tailisman
mkdir -p ~/.config/tailisman
tailisman keygen ~/.config/tailisman/secret
cp issuer.example.toml ~/.config/tailisman/issuer.toml   # from a checkout of this repository; set secret_file = "secret", then edit devices and audiences
```

`/etc/tailisman` works too, but writing there needs root. Then start the issuer. `tailisman run` stays in the foreground, so run it under a service manager (systemd, launchd) or in a terminal of its own, and add the serve handler from another one.

```sh
tailisman run --config ~/.config/tailisman/issuer.toml
```

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:8470
tailisman check --config ~/.config/tailisman/issuer.toml
```

Never put the issuer behind `tailscale funnel`. The issuer refuses any request that carries serve's `Tailscale-Funnel-Request` header, and `tailisman check` exits non-zero when Funnel is on for the host that proxies to the issuer.

Open `https://<issuer-host>.example-tailnet.ts.net:8443/` from any of your devices. The status page shows that device's name, stable ID, login and whether it is tagged. A device that at least one configured site accepts also sees which sites would accept it. Any other device sees only its own identity and the TOML line to add, nothing about the configured sites, and a tagged device is told that tagged devices are always refused.

### 2. Give each consumer its key

```sh
tailisman key --config ~/.config/tailisman/issuer.toml --aud https://heckle.example.com
# tsk1.<43 base64url characters>
```

Put it in the consumer's environment as `TAILISMAN_KEY`. The consumer never sees the master secret.

### 3. Add the snippet to the public page

Serve `client/tailisman.js` from your own origin.

```html
<button id="tailnet-signin" hidden>Sign in from this device</button>
<script type="module">
  import { mount } from "/static/tailisman.js";
  mount({
    issuer: "https://laptop.example-tailnet.ts.net:8443",
    exchange: "/auth/tailisman",
    button: "#tailnet-signin",
    isSignedIn: () => document.body.dataset.signedIn === "true",
  });
</script>
```

### 4. Verify on the server

The Python verifier is the same package as the issuer, standard library only, Python 3.11 or later. Add it to a consumer project from git:

```sh
uv add "tailisman @ git+https://github.com/adisidev/tailisman"
# or, in an environment you manage yourself
uv pip install "git+https://github.com/adisidev/tailisman"
```

```python
import os
from tailisman import TailismanError, Verifier, extract_token

verifier = Verifier(key=os.environ["TAILISMAN_KEY"], audience="https://heckle.example.com")

def exchange(content_type: str, body: bytes):
    claim = verifier.verify(extract_token(content_type, body))   # raises TailismanError with .code
    return claim.node_id, claim.node_name, claim.login
```

The Node package is plain ES modules with JSDoc types and a hand-written `index.d.ts`, no build step and no dependencies. It is not on npm, and npm cannot install a subdirectory of a git repository, so install it from a checkout:

```sh
git clone https://github.com/adisidev/tailisman
npm install --install-links ./tailisman/js     # copies the package into node_modules
# or build a tarball and install that
(cd tailisman/js && npm pack)                   # writes tailisman-0.1.0.tgz
npm install ./tailisman/js/tailisman-0.1.0.tgz
```

Plain `npm install ./tailisman/js` also works, but it links to the checkout instead of copying it. Both routes were tested on Node 22 and 26. It needs Node 22 or later, because it reads JSON numbers' source text to refuse a float `iat`, which older Node cannot do; on Node 20 the `Verifier` constructor throws instead of refusing every token.

```ts
import { TailismanError, Verifier, extractToken } from "tailisman";

const verifier = new Verifier({ key: process.env.TAILISMAN_KEY!, audience: "https://heckle.example.com" });
const claim = verifier.verify(extractToken(req.headers["content-type"], body));   // throws TailismanError with .code
```

Answer the JSON body (silent path) with a 2xx and the form body (navigation path) with a 303 to a page, and set your own cookie in both. Keep that 303 within your own origin. The issuer's `/v1/start` page has a `form-action` CSP that allows only your origin, and CSP applies `form-action` to redirects after the form post as well, so an exchange that redirects to another origin is blocked. `demo/consumer.py` is a complete consumer in about a hundred lines.

## The verifier

`Verifier(key, audience, replay=None, devices=None, leeway=5, clock=time.time)` checks, in this order, the format and MAC (`malformed`, `bad_signature`), the audience (`wrong_audience`), the time window with `leeway` seconds of skew (`expired`, `not_yet_valid`), single use of the nonce (`replayed`), and, when you pass `devices`, that the node's stable ID or short name is in your own list (`device_not_allowed`). Every failure raises `TailismanError` with one of those codes. A negative or non-integer `leeway` is refused when the verifier is built. The Node verifier has the same options in camelCase and the same codes.

The default replay store is a dictionary in memory, which is correct for one process. A server with several worker processes needs one store they all share. Pass any object with one method:

```python
class ReplayStore(Protocol):
    def claim(self, nonce: str, until: int, now: int) -> bool:
        """True the first time this nonce is seen, False on every later call before `until`."""
```

The method must be atomic across workers. With Redis that is `SET nonce 1 NX EXAT until`. With SQLite it is `INSERT OR IGNORE` on a primary key and a check that one row changed. The store only needs to remember a nonce for about 65 seconds.

`extract_token(content_type, body)` (`extractToken` in Node) reads the token from either body the snippet sends, JSON `{"token": "..."}` or a form field named `token`. A body over 16 KiB (`MAX_BODY`), a token over 4096 characters (`MAX_TOKEN`), or a body that does not parse, deeply nested JSON included, is `malformed`. Cap the request body at `MAX_BODY` before you read it.

## The snippet

`client/tailisman.js` exports three functions.

- `claim({issuer, timeoutMs, targetAddressSpace, signal})` makes the silent fetch and resolves with `{ok: true, token}`, `{ok: false, reason: "unreachable"}` or `{ok: false, reason: "refused", error}`. It never rejects.
- `navigate({issuer, exchange})` sends the browser to the issuer's `/v1/start`, which posts the token back to `exchange`.
- `mount(options)` is the default integration. It does nothing when `isSignedIn()` returns true. Otherwise it makes the silent fetch, posts the token to `exchange` as JSON and reloads. When the issuer is unreachable it shows the button, whose click calls `navigate`. When the issuer refuses the device it only reports, through `onResult(result, exchangeStatus)` if you pass one.

`mount` options beyond the ones above:

- `silent: false` skips the fetch and only shows the button.
- `askPermission` (default true) decides what happens while Chrome's `local-network-access` permission is still `prompt`. When true the fetch runs and Chrome asks. When false the snippet shows the button instead. A `denied` permission always shows the button. Browsers that do not support the permission query fetch as usual.
- `targetAddressSpace` (default `"local"`) is passed to `fetch`. Chrome places tailnet addresses in the `local` space and fails a fetch whose declared space does not match, so use `"loopback"` only for an issuer stand-in on 127.0.0.1.
- `timeoutMs` (default 20000) is long because Chrome holds the fetch open while the user reads the prompt.

The snippet sends `a=1` when it sees cheap signs of automation: `navigator.webdriver`, Playwright's injected globals, ChromeDriver's `cdc_` globals, or `HeadlessChrome` in the user agent.

## Issuer config reference

| Key | Default | Meaning |
| --- | --- | --- |
| `secret_file` | required | 32 bytes from `tailisman keygen`. Relative paths resolve against the config file. |
| `listen` | `"127.0.0.1:8470"` | A loopback address and port, or `"unix:/absolute/path"`. Anything else is a config error. |
| `ttl_seconds` | `60` | Token lifetime, 10 to 300. |
| `tailscale_bin` | `"auto"` | `auto` tries `/Applications/Tailscale.app/Contents/MacOS/Tailscale`, then `tailscale` on PATH. |
| `serve_host` | this node's MagicDNS name | The only `Host` (and `X-Forwarded-Host`) the issuer answers, such as `issuer.example-tailnet.ts.net`. Left out, the issuer reads `Self.DNSName` from `tailscale status --json` once at startup and refuses to start if it cannot. |
| `devices` | `[]` | Default allowlist. An entry matches a node by stable ID (exact), short name, or MagicDNS name with or without the trailing dot. Use stable IDs (see below). |
| `[[audiences]] origin` | required | The consumer's origin. This one list is the CORS allowlist, the `return_to` allowlist and the set of keys. |
| `[[audiences]] devices` | top-level `devices` | Replaces the default allowlist for this origin. |
| `[[audiences]] users` | any user | Logins allowed on this origin. |
| `[[audiences]] refuse_automation` | `false` | Refuse requests with `a=1` or a `HeadlessChrome` user agent. |

The issuer refuses with one of these codes, checked in this order: `wrong_host` (421), `not_behind_serve` (421), `funnel_request`, `unknown_audience`, `unknown_peer`, `tagged_node`, `identity_mismatch`, `not_on_allowlist`, `user_not_allowed`, `automation` (all 403). Tagged nodes are always refused.

### Allowlist entries: use stable IDs

A stable ID such as `nEXAMPLE1CNTRL` names one node and survives renames. Short names (`laptop`) and MagicDNS names are neither unique nor stable. A device that is renamed, or a node shared into your tailnet from another tailnet, can carry a name that is already on your list. The issuer's status page prints the stable ID line for the device you open it on.

The verifier's own `devices` re-check is narrower than the issuer's matching. It compares the token's stable ID or short name exactly and case-sensitively, and never MagicDNS names, so `Laptop` or `laptop.example-tailnet.ts.net` in a verifier list matches nothing.

### Routes

- `GET /v1/claim?a=0|1` answers `{"token"}` or `{"error"}` to a configured `Origin`, with `Access-Control-Allow-Origin` set to that origin, `Vary: Origin`, `Access-Control-Allow-Private-Network: true` and `Cache-Control: no-store`. An unknown origin gets a 403 with no CORS headers. `OPTIONS /v1/claim` answers the preflight.
- `GET /v1/start?return_to=URL&a=0|1` takes the audience from `return_to`'s origin and answers with a form that posts the token to `return_to`. The page has `Referrer-Policy: no-referrer`, a CSP that allows only its one inline script by hash and posts only to that origin, and a visible button for browsers without JavaScript.
- `GET /` is the status page. `GET /healthz` answers `ok`.

### Listening on loopback or a unix socket

With loopback TCP, any process on the issuer host can connect to the issuer, send its own `X-Forwarded-For` and mint a token for any allowlisted device. The issuer host's local users are therefore trusted. A web page is not one of those local users. A page open in a browser on the issuer host could point its own name at 127.0.0.1 (DNS rebinding) and then reach the issuer as same-origin, forged headers included, but its `Host` header stays its own name. The issuer answers only requests whose `Host` is its serve name (`serve_host`), port and case ignored, and refuses everything else as `wrong_host`. `/healthz` answers any host. A unix socket at mode 0660 limits that to the socket's owner and group: set `listen = "unix:/run/tailisman/issuer.sock"` and run `tailscale serve --bg --https=8443 unix:/run/tailisman/issuer.sock`. Under the macOS Tailscale app, serve answered 502 for a unix socket target, because its network extension cannot reach the socket. On Linux it is expected to work but has not been measured.

## Automation refusal is best effort

`refuse_automation` stops a default Playwright, Puppeteer or headless Chrome session. It does not stop anyone who sets `navigator.webdriver` to false or edits the snippet, because the browser reports these signals about itself. Leave it off for sites where your own agents should sign in.

## Gating whole sites

The gate is for sites you do not want to change. A browser on an allowlisted tailnet device is signed in through the gate's own tailnet listener, and any other browser gets a password form. The tailnet listener runs the issuer's device checks but answers a one-time code that only this gate process can redeem, so there is no separate issuer, no key per site, and nothing for a sleeping laptop to take down. One sign-in can cover every host under a domain, and named guest passwords open only the sites they were given, revocable one at a time. Behind a Cloudflare Tunnel the gate is the proxy: the tunnel points every gated hostname at the gate, and each site's `upstream` names the app's loopback port, with streaming, uploads, Range requests and websockets passed through. Behind Caddy, Caddy asks the gate about every request through `forward_auth`. [docs/GATE.md](docs/GATE.md) has both setups, the config reference, guests, service files and the caveats.

```sh
tailisman keygen ~/.config/tailisman/gate-secret
cp gate.example.toml ~/.config/tailisman/gate.toml      # edit sites and [tailnet] (serve_host, devices)
tailisman passwd --config ~/.config/tailisman/gate.toml --generate --out ~/.config/tailisman/gate-passphrase
tailscale serve --bg --https=8443 http://127.0.0.1:8470  # the tailnet listener; never Funnel
tailisman gate run --config ~/.config/tailisman/gate.toml
```

For a tunnel, give each `[[sites]]` entry an `upstream = "http://127.0.0.1:9000"` and set the tunnel's ingress `service` for that hostname to `http://127.0.0.1:8471`. For Caddy:

```caddy
(tailisman_gate) {
	header ?Cache-Control "private"
	header >Cache-Control "public" "private"
	header -CDN-Cache-Control
	header -Cloudflare-CDN-Cache-Control
	header -Surrogate-Control
	route {
		reverse_proxy /.tailisman/* 127.0.0.1:8471
		forward_auth 127.0.0.1:8471 {
			uri /.tailisman/verify
		}
	}
}

tools.example.com {
	import tailisman_gate
	reverse_proxy 127.0.0.1:9000
}
```

`tailisman gate status --config ~/.config/tailisman/gate.toml` then checks that every site sends an anonymous visitor to the sign-in page. `tailisman share https://notes.example.com/reports/ --to NAME` gives someone a guest password for that folder, or for a whole site when the path is `/`.

## Development

```sh
uv run --with pytest pytest          # Python verifier, issuer, gate, CLI, demo
node --test js/                      # Node verifier and the snippet with stubbed browser globals (the tests are TypeScript, so Node 22.18 or later)
uv run python scripts/make_vectors.py  # regenerate testdata/vectors.json; a test fails if it is stale
```

`e2e/browser_check.py` loads the demo consumer in a real browser and prints one JSON line of evidence. `--spoof-automation` hides the automation signals and `--simulate-off-tailnet` makes `*.ts.net` unresolvable in Chrome. For a local run without a tailnet, `e2e/fake_tailscale.py` answers `whois` and `status` from a JSON file and `e2e/fake_serve.py` adds the headers serve would (it passes `Host` through, so set `serve_host = "127.0.0.1"` for such a run). `e2e/LIVE.md` is the live sequence on a real tailnet.

```sh
uv run --with playwright python e2e/browser_check.py --demo https://demo.example.com --browser chromium --grant-lna --expect signed-in
```

The gate has its own end to end runs through a real Caddy, described in [docs/GATE.md](docs/GATE.md#testing): `e2e/gate_e2e.py` over HTTP and `e2e/gate_browser_check.py` in Playwright Chromium.

## Findings

These come from one live run on a real tailnet on 23 October 2026, with Tailscale 1.102.4 on macOS. `e2e/LIVE.md` is the sequence to repeat it on your own tailnet. The issuer ran on one Mac behind `tailscale serve --https=8443`. The demo consumer ran behind a temporary public HTTPS tunnel, so the browsers saw a real public origin calling a tailnet address, which is the situation a site behind Cloudflare is in. A page on `http://localhost` would not show the same behaviour, because browsers treat loopback as more private than the tailnet.

### What worked

- An allowlisted Mac got a token from the issuer, and so did a second allowlisted Mac over the tailnet. Both verifiers (Python and Node) accepted the token, refused it a second time as `replayed`, refused it under a different audience as `wrong_audience`, refused a tampered copy as `bad_signature`, and refused it after 60 seconds as `expired`.
- With the first Mac removed from the allowlist, its requests got `not_on_allowlist`, while the second Mac still got a token. A Linux tailnet machine that was never on the allowlist also got `not_on_allowlist`.
- A request that sent its own `X-Forwarded-For` and `Tailscale-User-Login` headers was still identified as the device it really came from. `tailscale serve` replaces both headers before the issuer sees them.
- An unknown `Origin` got a 403 with no CORS headers, so a browser on another site cannot read the answer.
- From a server that is not on the tailnet, the issuer's name did not resolve (`curl` exit 6), and connecting to its tailnet IP directly timed out (`curl` exit 28). Public DNS has no record for the name.
- After the DNS rebinding fix, a second live run checked both sides. A request through serve from an allowlisted Mac still got a token, and a request sent straight to the loopback listener with a forged `X-Forwarded-For` and a foreign `Host` got `421 wrong_host`.

### Browser matrix

| Browser (Playwright, headless) | Silent fetch | Button (top-level navigation) |
| --- | --- | --- |
| Chrome 155 with the Local Network Access permission granted | signed in | not needed |
| Chrome 155 without the permission | blocked, button shown | signed in |
| WebKit 27.2 (Playwright's build, not Safari itself) | signed in, no prompt | not tested |
| Firefox 157 | waits on a permission prompt, then times out, button shown | signed in |
| Chrome 155 with the issuer name made unresolvable, to stand in for a visitor off the tailnet | fails at DNS, button shown, no prompt | not tested |

On the navigation path the consumer's `Set-Cookie` on the answer to the issuer's cross-site form POST was kept in both Chrome and Firefox, and the page showed the visitor as signed in.

Observed once by hand, not in this matrix: real Safari on macOS, in a private window on a live site, signed in silently with no prompt. Not tested: Safari on iPhone and iPad, Chrome on Android, and the permission prompt as a person sees it in a normal (headed) Chrome or Firefox window. A headless browser cannot show a prompt, so Chrome denies straight away and Firefox waits.

### Local Network Access

This is the main thing to know. Chrome 155 and Firefox 157 treat tailnet addresses (100.64.0.0/10) as the `local` address space. A page on a public origin that fetches a `local` address needs the Local Network Access permission for that site. Chrome's console message was "Permission was denied for this request to access the `local` address space", and Firefox's was "Local Network Access permission required". CORS headers alone do not help. Chrome sent no preflight in these runs, so the older `Access-Control-Allow-Private-Network` response header (which the issuer still sends) made no difference.

What does work:

1. Granting the permission once per site. After that the silent fetch works with no visible step. In Chrome, `navigator.permissions.query({name: "local-network-access"})` reports the state. Firefox and WebKit do not support that query.
2. A top-level navigation. Clicking a link or button that goes to the issuer is not gated in any browser tested. That is why the snippet falls back to a button and the issuer answers `/v1/start` with a form that posts the token back.
3. WebKit 27.2 under Playwright, headless, showed no such gate, and the silent fetch just worked there. Real Safari on macOS, observed once by hand in a private window, also signed in with no prompt, likely because WebKit has not shipped Local Network Access (inferred, not measured). Safari on iOS was not run.

The browser checks Local Network Access after DNS. A visitor who is not on the tailnet fails at DNS first and never sees a prompt.

The snippet passes `targetAddressSpace: "local"` to `fetch`. Chrome fails the fetch if the declared space does not match where the address really is, so a local test against an issuer on 127.0.0.1 needs `"loopback"` instead.

### Security caveats

- The device allowlist is the real control. Anything that runs on an allowlisted device can get a token. A script or AI agent on your laptop can call the issuer with any `Origin` header it likes (curl can), get a token, and sign in to your site as you. tailisman cannot tell your browser from your agent on the same machine. Keep the allowlist to devices where that is acceptable.
- The automation refusal is a speed bump. With `refuse_automation = true`, a default Playwright Chrome was refused as `automation`. The same browser with `navigator.webdriver` overridden, Playwright's globals removed and a normal user agent signed in. That took three lines.
- DNS rebinding. Without a host check, a page in a browser on the issuer host could rebind its own name to 127.0.0.1, send its own `X-Forwarded-For` and read a token. The issuer refuses any request whose `Host` or `X-Forwarded-Host` is not its serve name, as `wrong_host`, before any other check. Run `tailisman check` to confirm the name serve uses is the one the issuer expects.
- Loopback TCP trusts every local user of the issuer host, as described above. A unix socket narrows this on Linux but does not work under the macOS Tailscale app.
- Each consumer's key can sign tokens for that consumer. That is no worse than the consumer itself being compromised, since it controls its own sessions. The master secret stays on the issuer host.
- A token is a bearer token for up to 60 seconds. The verifier refuses a second use of the same nonce, but only within one replay store. A server with several processes needs a shared store.
- Tagged devices are always refused, because they have no user identity.
- Login CSRF. Anyone can send a visitor to `/v1/start` or post a token to a consumer's exchange, so a token minted on one allowlisted device could sign another visitor's browser in as that device's identity. With a single-owner allowlist this is harmless, since every identity is yours. It matters when an audience allows several users. A consumer that cares should keep one user per audience, or refuse a claim whose login differs from the session the browser already has.
- Each claim runs one `tailscale whois` subprocess, and any peer on your tailnet can make the issuer run it as often as it likes. That is a known limitation of v0.1, which has no whois cache and no rate limit.
- The issuer refuses Funnel traffic, and `tailisman check` reports Funnel. Do not turn Funnel on for the issuer anyway.
