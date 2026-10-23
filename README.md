# tailisman

tailisman lets a public web app learn that the visitor's browser runs on one of your own tailnet devices. The app gets a signed claim that lives 60 seconds, verifies it on its server, and turns it into its own session cookie.

It is for a single owner with a site on the public internet (for example `heckle.example.com` behind Cloudflare) who wants their laptop and phone signed in without a password, and nobody else. It checks the device as well as the user, because the owner's own scripts and agents run as the owner's user.

There are three parts in this repository, all MIT licensed.

- The issuer is a small Python HTTP server on a tailnet host, reachable only through `tailscale serve`.
- The browser snippet is `client/tailisman.js`, one ES module with no dependencies.
- The verifiers are a Python package (`tailisman`, standard library only) and a Node package (`js/`, `node:crypto` only).

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

The silent fetch works without a prompt in Safari. Chrome and Firefox gate it behind a one-time Local Network Access permission per site. When the fetch fails, the snippet shows a button. Clicking it navigates to the issuer, which answers with a form that posts the token back to the same `/auth/tailisman` endpoint. A top-level navigation is never gated, so the button works in every browser.

A visitor who is not on the tailnet cannot resolve the issuer's `*.ts.net` name, so their fetch fails at DNS and they never see a permission prompt. They see the button only, and clicking it leads to a DNS error page.

The token is `tsm1.<base64url payload>.<base64url HMAC-SHA256>`. The payload holds the node stable ID, the short node name, the user login, the audience origin, issue and expiry times, and a random nonce. Each audience has its own key, `K_aud = HMAC-SHA256(master, "tailisman/v1/aud:" + origin)`, so a consumer only ever holds a key that can sign tokens for itself.

## Quickstart

### 1. Run the issuer on a tailnet host

```sh
uv tool install git+https://github.com/adisidev/tailisman   # not on PyPI
tailisman keygen /etc/tailisman/secret
cp issuer.example.toml /etc/tailisman/issuer.toml   # then edit devices and audiences
tailisman run --config /etc/tailisman/issuer.toml
tailscale serve --bg --https=8443 http://127.0.0.1:8470
tailisman check --config /etc/tailisman/issuer.toml
```

Never put the issuer behind `tailscale funnel`. The issuer refuses any request that carries serve's `Tailscale-Funnel-Request` header, and `tailisman check` exits non-zero when Funnel is on for the host that proxies to the issuer.

Open `https://<issuer-host>.example-tailnet.ts.net:8443/` from any of your devices. The status page shows that device's name, stable ID, login and whether it is tagged. A device that at least one configured site accepts also sees which sites would accept it. Any other device sees only its own identity and the TOML line to add, nothing about the configured sites, and a tagged device is told that tagged devices are always refused.

### 2. Give each consumer its key

```sh
tailisman key --config /etc/tailisman/issuer.toml --aud https://heckle.example.com
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

Python:

```python
import os
from tailisman import TailismanError, Verifier, extract_token

verifier = Verifier(key=os.environ["TAILISMAN_KEY"], audience="https://heckle.example.com")

def exchange(content_type: str, body: bytes):
    claim = verifier.verify(extract_token(content_type, body))   # raises TailismanError with .code
    return claim.node_id, claim.node_name, claim.login
```

Node runs the package's TypeScript sources directly, so it needs a Node that strips types by default (22.18 or later; tested on 26). Node refuses to strip types for files under `node_modules`, so install it as a link with `npm install /path/to/tailisman/js` (npm links a local folder) or copy `js/src` into your project. There is no published build yet.

```ts
import { TailismanError, Verifier, extractToken } from "tailisman";

const verifier = new Verifier({ key: process.env.TAILISMAN_KEY!, audience: "https://heckle.example.com" });
const claim = verifier.verify(extractToken(req.headers["content-type"], body));   // throws TailismanError with .code
```

Answer the JSON body (silent path) with a 2xx and the form body (navigation path) with a 303 to a page, and set your own cookie in both. `demo/consumer.py` is a complete consumer in about a hundred lines.

## The verifier

`Verifier(key, audience, replay=None, devices=None, leeway=5, clock=time.time)` checks, in this order, the format and MAC (`malformed`, `bad_signature`), the audience (`wrong_audience`), the time window with `leeway` seconds of skew (`expired`, `not_yet_valid`), single use of the nonce (`replayed`), and, when you pass `devices`, that the node's stable ID or short name is in your own list (`device_not_allowed`). Every failure raises `TailismanError` with one of those codes. The Node verifier has the same options in camelCase and the same codes.

The default replay store is a dictionary in memory, which is correct for one process. A server with several worker processes needs one store they all share. Pass any object with one method:

```python
class ReplayStore(Protocol):
    def claim(self, nonce: str, until: int, now: int) -> bool:
        """True the first time this nonce is seen, False on every later call before `until`."""
```

The method must be atomic across workers. With Redis that is `SET nonce 1 NX EXAT until`. With SQLite it is `INSERT OR IGNORE` on a primary key and a check that one row changed. The store only needs to remember a nonce for about 65 seconds.

`extract_token(content_type, body)` (`extractToken` in Node) reads the token from either body the snippet sends, JSON `{"token": "..."}` or a form field named `token`.

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
| `devices` | `[]` | Default allowlist. An entry matches a node by stable ID (exact), short name, or MagicDNS name with or without the trailing dot. |
| `[[audiences]] origin` | required | The consumer's origin. This one list is the CORS allowlist, the `return_to` allowlist and the set of keys. |
| `[[audiences]] devices` | top-level `devices` | Replaces the default allowlist for this origin. |
| `[[audiences]] users` | any user | Logins allowed on this origin. |
| `[[audiences]] refuse_automation` | `false` | Refuse requests with `a=1` or a `HeadlessChrome` user agent. |

The issuer refuses with one of these codes, checked in this order: `wrong_host` (421), `not_behind_serve` (421), `funnel_request`, `unknown_audience`, `unknown_peer`, `tagged_node`, `identity_mismatch`, `not_on_allowlist`, `user_not_allowed`, `automation` (all 403). Tagged nodes are always refused.

### Routes

- `GET /v1/claim?a=0|1` answers `{"token"}` or `{"error"}` to a configured `Origin`, with `Access-Control-Allow-Origin` set to that origin, `Vary: Origin`, `Access-Control-Allow-Private-Network: true` and `Cache-Control: no-store`. An unknown origin gets a 403 with no CORS headers. `OPTIONS /v1/claim` answers the preflight.
- `GET /v1/start?return_to=URL&a=0|1` takes the audience from `return_to`'s origin and answers with a form that posts the token to `return_to`. The page has `Referrer-Policy: no-referrer`, a CSP that allows only its one inline script by hash and posts only to that origin, and a visible button for browsers without JavaScript.
- `GET /` is the status page. `GET /healthz` answers `ok`.

### Listening on loopback or a unix socket

With loopback TCP, any process on the issuer host can connect to the issuer, send its own `X-Forwarded-For` and mint a token for any allowlisted device. The issuer host's local users are therefore trusted. A web page is not one of those local users. A page open in a browser on the issuer host could point its own name at 127.0.0.1 (DNS rebinding) and then reach the issuer as same-origin, forged headers included, but its `Host` header stays its own name. The issuer answers only requests whose `Host` is its serve name (`serve_host`), port and case ignored, and refuses everything else as `wrong_host`. `/healthz` answers any host. A unix socket at mode 0660 limits that to the socket's owner and group: set `listen = "unix:/run/tailisman/issuer.sock"` and run `tailscale serve --bg --https=8443 unix:/run/tailisman/issuer.sock`. Under the macOS Tailscale app, serve answered 502 for a unix socket target, because its network extension cannot reach the socket. On Linux it is expected to work but has not been measured.

## Automation refusal is best effort

`refuse_automation` stops a default Playwright, Puppeteer or headless Chrome session. It does not stop anyone who sets `navigator.webdriver` to false or edits the snippet, because the browser reports these signals about itself. Leave it off for sites where your own agents should sign in.

## Development

```sh
uv run --with pytest pytest          # Python verifier, issuer, CLI, demo
node --test js/                      # Node verifier and the snippet with stubbed browser globals
uv run python scripts/make_vectors.py  # regenerate testdata/vectors.json; a test fails if it is stale
```

`e2e/browser_check.py` loads the demo consumer in a real browser and prints one JSON line of evidence. For a local run without a tailnet, `e2e/fake_tailscale.py` answers `whois` from a JSON file and `e2e/fake_serve.py` adds the headers serve would.

```sh
uv run --with playwright python e2e/browser_check.py --demo https://demo.example.com --browser chromium --grant-lna --expect signed-in
```

## Findings

These come from one live run on a real tailnet on 23 October 2026, with Tailscale 1.102.4 on macOS. The issuer ran on one Mac behind `tailscale serve --https=8443`. The demo consumer ran behind a temporary public HTTPS tunnel, so the browsers saw a real public origin calling a tailnet address, which is the situation a site behind Cloudflare is in. A page on `http://localhost` would not show the same behaviour, because browsers treat loopback as more private than the tailnet.

### What worked

- An allowlisted Mac got a token from the issuer, and so did a second allowlisted Mac over the tailnet. Both verifiers (Python and Node) accepted the token, refused it a second time as `replayed`, refused it under a different audience as `wrong_audience`, refused a tampered copy as `bad_signature`, and refused it after 60 seconds as `expired`.
- With the first Mac removed from the allowlist, its requests got `not_on_allowlist`, while the second Mac still got a token. A Linux tailnet machine that was never on the allowlist also got `not_on_allowlist`.
- A request that sent its own `X-Forwarded-For` and `Tailscale-User-Login` headers was still identified as the device it really came from. `tailscale serve` replaces both headers before the issuer sees them.
- An unknown `Origin` got a 403 with no CORS headers, so a browser on another site cannot read the answer.
- From a server that is not on the tailnet, the issuer's name did not resolve (`curl` exit 6), and connecting to its tailnet IP directly timed out (`curl` exit 28). Public DNS has no record for the name.

### Browser matrix

| Browser (Playwright, headless) | Silent fetch | Button (top-level navigation) |
| --- | --- | --- |
| Chrome 155 with the Local Network Access permission granted | signed in | not needed |
| Chrome 155 without the permission | blocked, button shown | signed in |
| WebKit 27.2 (the engine inside Safari) | signed in, no prompt | not tested |
| Firefox 157 | waits on a permission prompt, then times out, button shown | signed in |
| Chrome 155 with the issuer name made unresolvable, to stand in for a visitor off the tailnet | fails at DNS, button shown, no prompt | not tested |

On the navigation path the consumer's `Set-Cookie` on the answer to the issuer's cross-site form POST was kept in both Chrome and Firefox, and the page showed the visitor as signed in.

Not tested: real Safari on macOS, Safari on iPhone and iPad, Chrome on Android, and the permission prompt as a person sees it in a normal (headed) Chrome or Firefox window. A headless browser cannot show a prompt, so Chrome denies straight away and Firefox waits.

### Local Network Access

This is the main thing to know. Chrome 155 and Firefox 157 treat tailnet addresses (100.64.0.0/10) as the `local` address space. A page on a public origin that fetches a `local` address needs the Local Network Access permission for that site. Chrome's console message was "Permission was denied for this request to access the `local` address space", and Firefox's was "Local Network Access permission required". CORS headers alone do not help. Chrome sent no preflight in these runs, so the older `Access-Control-Allow-Private-Network` response header (which the issuer still sends) made no difference.

What does work:

1. Granting the permission once per site. After that the silent fetch works with no visible step. In Chrome, `navigator.permissions.query({name: "local-network-access"})` reports the state. Firefox and WebKit do not support that query.
2. A top-level navigation. Clicking a link or button that goes to the issuer is not gated in any browser tested. That is why the snippet falls back to a button and the issuer answers `/v1/start` with a form that posts the token back.
3. Safari's engine has no such gate, so the silent fetch just works there.

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
- The issuer refuses Funnel traffic, and `tailisman check` reports Funnel. Do not turn Funnel on for the issuer anyway.
