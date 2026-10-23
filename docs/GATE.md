# tailisman gate

The gate puts one sign-in in front of any number of sites, with no change to the apps behind them. A browser on one of your allowlisted tailnet devices is let in through the gate's own tailnet listener, usually without a click. Every other browser gets a password form, so a borrowed laptop, a phone off the tailnet or a Chrome that has not yet been granted Local Network Access can still get in with the backup password.

The gate is one small standard-library Python process with two loopback listeners. The public listener serves the sites. The tailnet listener sits behind `tailscale serve` and tells allowlisted devices apart. Each site uses the public listener in one of two ways. In proxy mode, for pages published through a Cloudflare Tunnel, the tunnel sends the site's traffic to the gate and the gate forwards each allowed request to the app. In `forward_auth` mode, for sites served by Caddy, Caddy asks the gate about every request and proxies the gate's own pages under `/.tailisman/` to it. One gate serves both kinds of site at once, and both ask the same decision function.

## Request flow

```
 browser                         Caddy (tools.example.com)                gate (127.0.0.1:8471)
 -------                         -------------------------                ---------------------
 GET /notes                 -->  forward_auth GET /.tailisman/verify  -->  Host, X-Forwarded-Method, X-Forwarded-Uri, Cookie
                                                                           open rule?        200
                                                                           valid session?    200, X-Tailisman-Session
                                                                           page navigation?  302 /.tailisman/login?next=/notes
                                                                           anything else?    401 {"error": ...}
 <-- 302 /.tailisman/login  <--  passes a non-2xx answer through as is
 GET /.tailisman/login      -->  reverse_proxy /.tailisman/*           -->  sign-in page
   login.js: claim() from the tailnet listener, POST the code to /.tailisman/exchange   Set-Cookie: tailisman_gate (method tailnet)
   or the password form: POST /.tailisman/login                                Set-Cookie: tailisman_gate (method password)
 GET /notes with the cookie -->  forward_auth: 200                    -->  reverse_proxy to the app
```

The sign-in page tries the tailnet path first. It loads `/.tailisman/login.js`, which imports the browser snippet from `/.tailisman/tailisman.js` and asks the gate's tailnet listener, at `https://<serve_host>:8443`, for a code without any visible step. When that works, the page says "Recognised laptop, signing you in" and goes to the page the visitor asked for. When the tailnet listener cannot be reached (off the tailnet, or Local Network Access not granted yet), the page shows a "Sign in from this device" button, which takes the navigation path through the tailnet listener and comes back to `/.tailisman/exchange`. The password form is always there and works without JavaScript.

## The tailnet listener

The tailnet listener runs the same device checks as the standalone issuer, with the same code: the request must name this machine's serve name in `Host` and `X-Forwarded-Host`, come through serve, not come through Funnel, come from a gated site's origin, and come from a peer `tailscale whois` knows, that is not tagged, whose login matches serve's header, whose device is on the allowlist, and whose user and automation policy pass. It answers with the same CORS headers and the same navigation fallback as the issuer's `/v1/claim` and `/v1/start`, so the browser snippet is unchanged. What it hands back is not a signed token. It is a one-time code, 32 random bytes, held only in the gate's memory, bound to the site's origin, carrying the device's name, stable ID and login, and valid for 60 seconds. `/.tailisman/exchange` on the public listener redeems it once. A code that is unknown, expired, already used or shown to another site is refused with 403 and `malformed`, `expired`, `replayed` or `wrong_audience`, and a code shown to the wrong site is burned.

Because both listeners are one process, nothing is signed and there is no key to hand out or rotate. Run the gate on the machine that serves the sites. An issuer on another machine would make the device path depend on that machine being awake, while here, if the page loads, the device path works. A restart forgets codes that were in flight, which costs at most a second click.

`[tailnet]` in `gate.toml`:

```toml
[tailnet]
listen = "127.0.0.1:8470"
serve_host = "gate.example-tailnet.ts.net"
devices = ["nEXAMPLE1CNTRL", "laptop"]
```

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:8470   # never tailscale funnel
```

Every site is a tailnet audience unless it sets `tailnet = false`. `gate status` checks that the tailnet listener answers, that `tailscale serve` fronts it under `serve_host`, and that Funnel is off for it, as `tailisman check` does for the standalone issuer. The device check refuses Funnel traffic on every request as well.

## Quickstart

On the machine that runs Caddy, with tailisman installed as in the README:

```sh
mkdir -p ~/.config/tailisman
tailisman keygen ~/.config/tailisman/gate-secret
cp gate.example.toml ~/.config/tailisman/gate.toml         # from a checkout; edit sites and [tailnet]
chmod 600 ~/.config/tailisman/gate.toml
tailisman passwd --config ~/.config/tailisman/gate.toml --generate --out ~/.config/tailisman/gate-passphrase
tailisman gate run --config ~/.config/tailisman/gate.toml
```

`passwd --generate` writes a passphrase such as `bavu-tiko-relu-mazo-pine-dusa` to the `--out` file and its hash to the config's `password_file`, both mode 0600, and prints only the two paths (each as written, so the hash path is the config's `password_file` value). The gate reads `gate.toml` once at startup, so restart it after editing that file; the password and guest files are re-read on change. Read the passphrase from the file, store it in your password manager, and delete the file. Without `--generate`, `passwd` asks for a password twice (at least 12 characters).

For the tailnet path, fill in `[tailnet]` with this machine's MagicDNS name and the devices to allow, and put the tailnet listener behind serve:

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:8470
```

`gate run` starts both listeners. To find a device's stable ID, open `https://<serve_host>:8443/` from it, which shows what the gate sees for that device.

Then either point the tunnel at the gate and give each site an `upstream` (proxy mode, below), or add the snippet to the Caddyfile and reload Caddy. Check every site from outside:

```sh
tailisman gate status --config ~/.config/tailisman/gate.toml
```

It prints each site's upstream (or `forward_auth`), scope, guest count and bearer count, checks that an anonymous visitor is sent to sign in, and for a proxy site that its upstream accepts connections.

## Cloudflare Tunnel (proxy mode, no Caddy)

This is the simplest setup when the pages go through a tunnel. cloudflared terminates TLS but has no way to ask anyone before it hands a request to the app, so point the tunnel at the gate and give each site an `upstream`, the app's own loopback port:

```yaml
# ~/.cloudflared/config.yml
ingress:
  - hostname: tools.example.com
    service: http://127.0.0.1:8471
  - hostname: notes.example.com
    service: http://127.0.0.1:8471
  - service: http_status:404
```

```toml
[[sites]]
host = "tools.example.com"
cookie_domain = "example.com"
upstream = "http://127.0.0.1:9000"

[[sites]]
host = "notes.example.com"
cookie_domain = "example.com"
upstream = "http://127.0.0.1:9100"
```

Every gated hostname goes to the gate's one port. The gate tells the sites apart by `Host`, answers `/.tailisman/` itself, and runs the same check `forward_auth` would on everything else, using the request's own method and path, never `X-Forwarded-*` headers a client could set. An allowed request goes to the upstream. A page navigation without a session gets 302 to the sign-in page, anything else 401 with the same JSON body as `verify`.

What the proxy handles, each checked by `e2e/gate_proxy_e2e.py` against a real app:

- Request and response bodies stream through without being held in memory. Uploads of any size (Content-Length or chunked) reach the app as they arrive, with no limit from the gate. Answers of unknown length, chunked answers and server-sent events reach the browser as the app sends them, and Range requests get the app's 206 and `Content-Range`.
- Long polls wait as long as the app takes. The connect timeout is 10 seconds, and there is no read timeout once connected.
- A client has 60 seconds for each read of a request line or header block, on the public and the tailnet listener alike, and an idle keep-alive connection closes after 60 seconds. The timeout is lifted once a proxied request is allowed, so long polls, event streams, uploads and websockets are not cut off. A chunked upload may end with at most 32 trailer lines.
- Websockets. An allowed `Upgrade: websocket` request goes on to the app, and after its 101 the gate copies bytes both ways until either side closes. An anonymous upgrade gets 401, and an upgrade with a body gets 400. When the app answers the upgrade with anything but a 101 to websocket, the gate relays that answer and closes the connection, so nothing the client sent behind the upgrade reaches the app unjudged.
- HTTP/1.1 keep-alive towards the tunnel, HEAD, 204 and 304.
- When the app is down, 502 with a short text body. The gate logs that once, and once more when the app answers again.

Headers sent on to the app: hop-by-hop headers are dropped (`Connection` and the names it lists, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade` except on a websocket upgrade). So is every header whose name contains `_`, as nginx and Caddy do by default: CGI, WSGI and PHP turn both `-` and `_` into `_`, so `X_Tailisman_Session` would otherwise reach such an app as the identity header. A request with a folded header line (obs-fold, a value carrying CR or LF) gets 400. The gate's own cookies, `tailisman_gate` and `tailisman_csrf`, are removed from `Cookie`, so the app never sees the session. Any client-sent `X-Tailisman-Session` and `X-Tailisman-User` are removed, then set from the session: the method, and for a guest their name. `Host` stays as the browser sent it. `X-Forwarded-For` gets the peer appended, `X-Forwarded-Proto` keeps cloudflared's value and is `https` when there is none, and `X-Forwarded-Host` is the `Host`. The gate appends to `X-Forwarded-For` rather than replacing it, so an app behind it should not trust the leftmost entry, which any client can set; behind cloudflared, use `CF-Connecting-IP` for the visitor's address.

Headers sent back: hop-by-hop headers are dropped and the rest pass through, each `Set-Cookie` on its own line. The same cache rule as the Caddy snippet applies: an answer with no `Cache-Control` gets `Cache-Control: private`, and `public` in one the app sent becomes `private`. `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control` and `Surrogate-Control` are removed, since Cloudflare honours them ahead of `Cache-Control`. A tunnel's own HTTP cache is Cloudflare's edge cache, which honours `private`, so this keeps gated answers out of it. Purge the zone's cache for a host when you first gate it, because the edge may still hold copies from before.

Open rules work as they do behind Caddy, and the gate refuses to match them against the same suspicious paths.

## Caddy

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

The `header` lines keep gated pages out of shared caches. Without them Cloudflare caches responses it considers static (`.js`, `.css`, images, PDFs) at its edge, and serves the cached copy to anyone who asks, with no request reaching Caddy or the gate. This was measured on a live site: a `.js` file fetched before the gate was put in front was still served from the edge cache afterwards, until the cache was purged. The first line marks a response `private` when the app set no `Cache-Control`, and the second, deferred with `>` until the app has answered, turns an app's `public` into `private`. The three `-` lines remove `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control` and `Surrogate-Control`, which Cloudflare honours ahead of `Cache-Control`, so an app that sends one could still have a gated answer cached at the edge. Caddy defers a `-` until the app has answered (`caddy adapt` shows `"deferred": true`), so the app's own copy is removed. Purge the CDN's cache for a host when you first gate it.

The `route` block keeps the order: the gate's own pages first, then the check for everything else. The same snippet works when Caddy terminates TLS itself and when a Cloudflare Tunnel terminates TLS and talks plain HTTP to Caddy (`http://tools.example.com { ... }`). The gate sets its cookies `Secure` either way, because the browser is always on HTTPS.

To pass the sign-in method on to the app, add `copy_headers X-Tailisman-Session X-Tailisman-User` inside `forward_auth`. The app then sees `password`, `tailnet` or `guest` in `X-Tailisman-Session`, and for a guest their name in `X-Tailisman-User`. Measured on Caddy 2.11.7: a client that sends its own copy of either header has it replaced by the gate's value, and removed when the gate's answer does not carry it (an open rule, or `X-Tailisman-User` on an owner session).

If the site's own `header` directive sets a `Content-Security-Policy`, scope it with `not path /.tailisman/*`. The gate sends its own policy on its pages, and a site-wide one that lacks the tailnet listener's origin in `connect-src` blocks the silent tailnet path.

What Caddy 2.11.7 does here was measured with `e2e/gate_e2e.py`, not assumed. `forward_auth` sends the original `Host`, `X-Forwarded-Method` and `X-Forwarded-Uri` to the gate, and the URI is raw, so `/api/../secret` arrives as written. It also appends the original query string to the verify URI. A 302 or 401 from the gate reaches the browser unchanged, `Location` and body included, and a `Set-Cookie` from `/.tailisman/*` reaches the browser. Caddy matches its own `path` matchers against the cleaned path but proxies the raw one, so an upstream can receive `/api/../secret` and resolve it to `/secret` itself. That is why the gate refuses to match open rules against such paths.

## Machine callers: exempt by credential, not by path

Some apps have machine callers, a feed reader or a deploy hook, that already send a static `Authorization: Bearer <token>`, often on paths that also serve anonymous visitors. An open rule would let everyone through on those paths, and letting any request with an `Authorization` header through would let anyone in who types one. Instead, list the digests of the tokens the gate should know:

```sh
tailisman gate bearer-hash        # paste the token; it is read from stdin without echo, never from argv, so it stays out of shell history
```

```toml
[[sites]]
host = "notes.example.com"
bearers = ["sha256$<base64>"]     # one digest per machine caller
```

A request whose one `Authorization` header is `Bearer <token>`, with a token whose SHA-256 is listed for that site, is let in with no session. The check runs after the open rules and before the session check. The header goes on to the app unchanged, so the app still checks the token itself, and the app sees `X-Tailisman-Session: bearer`. A token that is not listed, a second `Authorization` header or another scheme counts as no bearer at all, and the request goes on to the usual session check and sign-in, so the gate does not tell anyone whether a token was close. The path checks that guard open rules do not apply here, because the token, not the path, is the proof. This is the way to keep machine callers working. Use open rules only for callers that send no credential.

The digest is unsalted SHA-256, so a short or guessable token can be guessed back from it. Use tokens with real entropy and keep `gate.toml` mode 0600. Measured on Caddy 2.11.7 with `e2e/gate_e2e.py`: `forward_auth` passes the original `Authorization` header to the gate, and the app still receives it.

## Config reference

`gate.example.toml` is a complete example.

| Key | Meaning |
| --- | --- |
| `listen` | Loopback address and port. Default `127.0.0.1:8471`. |
| `session_secret_file` | 32 bytes from `tailisman keygen`. Relative paths resolve against the config file's directory. |
| `password_file` | One scrypt hash line written by `tailisman passwd`. When it is missing or malformed the owner's password path is off. That is not a startup error. The sign-in page shows the password form while the owner password or a guest for that site exists, and otherwise says password sign-in is not set up. |
| `guest_file` | Optional, default `guest-passwords` next to the config. The guest records written by `tailisman passwd --add`. A missing file means no guests. |
| `session_days` | How long a session lasts, 1 to 400. Default 30. |
| `[tailnet]` | Optional. The tailnet listener. Without it only the password paths exist. |
| `[tailnet] listen` | Loopback address and port, or `unix:/path`. Default `127.0.0.1:8470`. Must differ from `listen`. |
| `[tailnet] serve_host` | This machine's MagicDNS name, which serve passes as `Host`. Required. |
| `[tailnet] port`, `origin` | Where browsers reach the listener: `https://<serve_host>:<port>`, port 8443 by default. `origin` overrides the whole origin. |
| `[tailnet] devices` | Stable IDs, short names or MagicDNS names of the devices that may sign in this way. Required. |
| `[tailnet] users`, `refuse_automation` | Optional. The issuer's per-audience policy, applied to every tailnet site: only these logins, and refuse default automation. |
| `[tailnet] ttl_seconds` | How long a code lives, 10 to 300. Default 60. |
| `[tailnet] tailscale_bin` | `"auto"` (default) or the path of the tailscale CLI, used for `whois` and by `gate status` for `serve status`. |
| `rate_limit` | `per_ip` (default 5), `global` (default 30), `window_seconds` (default 900). |
| `[[sites]] host` | The host the browser uses. A port is allowed for a site on a nonstandard HTTPS port. |
| `[[sites]] cookie_domain` | Optional. The cookie's `Domain`, which must be the host or a parent of it. One sign-in then covers every host under it. Without it the cookie is host-only. |
| `[[sites]] tailnet` | Optional, default `true`. `false` leaves the site with the password paths only. |
| `[[sites]] upstream` | Optional. Makes the site a proxy site: `http://HOST:PORT` of the app, with no path, query or user name, and plain HTTP only. Without it the site is a `forward_auth` site behind Caddy. |
| `[[sites]] bearers` | Optional. SHA-256 digests, `sha256$<base64>` from `tailisman gate bearer-hash`, of machine callers' bearer tokens that may pass without a session. |
| `[[sites]] open` | Optional. Requests the gate lets through without a session: `"/healthz"` exact, `"/api/*"` everything under `/api/`, `"POST /report"` one method only. The app behind must guard these itself. |

`[tailnet] address_space` is a test knob. It is `"local"` by default, which is where Chrome places tailnet addresses. The local browser check sets it to `"loopback"`, because there the page and the serve stand-in are both on 127.0.0.1, and Chrome fails a fetch whose declared address space does not match.

The `sites` table is the only list of gated hosts. The verify check, the proxy, the sign-in pages and `gate status` all read it, and a request for any other host is refused.

## Routes

All routes live under `/.tailisman/` on each gated host. On a proxy site every other path is checked and proxied to the upstream. On a `forward_auth` site every other path reaching the gate gets 404.

| Route | What it does |
| --- | --- |
| `GET /.tailisman/verify` | The `forward_auth` target. 200 with an empty body to allow, plus `X-Tailisman-Session` when there is a session or a listed bearer (`bearer`) and `X-Tailisman-User` for a guest. 302 to the sign-in page for a page navigation (`GET` or `HEAD` that accepts `text/html`), 401 with a small JSON body otherwise. |
| `GET /.tailisman/login?next=` | The sign-in page. `next` must be a path on the same host. Anything else becomes `/`. A browser that already has a session goes straight to `next`. |
| `POST /.tailisman/login` | Checks the rate limit, then CSRF, then the guest passwords for this site, then the owner password. Success sets the session cookie and answers 303 to `next`. |
| `POST /.tailisman/exchange?next=` | Redeems a code from the tailnet listener for a session. A JSON post (the silent path) gets `{"device", "next"}`. The tailnet listener's form post (the navigation path) gets a 303 to `next`. A refused code gets 403 with its error. |
| `GET /.tailisman/` | Says how this browser is signed in and until when, with a Sign out button. |
| `POST /.tailisman/logout` | Clears the cookie and answers 303 to the sign-in page. After sign-out the page waits for a click before trying the tailnet path again, so Sign out works on a tailnet device too. |
| `GET /.tailisman/healthz` | Answers `ok`. |

## Sessions

The owner's cookie is `tailisman_gate=tsg1.<base64url payload>.<base64url HMAC-SHA256>`. The payload holds the method (`password` or `tailnet`), the device name for a tailnet session, the scope (the cookie domain or the host), and issue and expiry times. The gate keeps no session state.

Its MAC key is `HMAC-SHA256(session_secret, "tailisman/gate/v1:" + password hash line)`. Changing the owner password changes the key, so it signs every owner session out, tailnet sessions included, without a restart or a session store.

A guest's cookie is `tailisman_gate=tsg1g.<NAME>.<base64url payload>.<base64url HMAC-SHA256>`, with the method `guest` and the guest's name in the payload. Its MAC key is `HMAC-SHA256(session_secret, "tailisman/gate/guest/v1:" + NAME + "\n" + the guest's digest)`. The name is in clear because the key depends on it. The gate checks the MAC under that guest's key before it reads the payload, and refuses a payload whose name differs from the clear one.

The cookie is `HttpOnly; Secure; SameSite=Lax; Path=/`, with `Max-Age` from `session_days` and `Domain` when `cookie_domain` is set. A session is accepted on a host only when the host is its scope or ends with `.` plus its scope. A browser can hold a parent-domain cookie and a host-only one under the same name, and the gate accepts the request if either is valid.

## Guests

A guest password lets one person into one or a few of the sites, and can be taken back without touching anyone else's sign-in.

```sh
tailisman passwd --config ~/.config/tailisman/gate.toml --add alice --sites notes.example.com,tools.example.com
tailisman passwd --config ~/.config/tailisman/gate.toml --list
tailisman passwd --config ~/.config/tailisman/gate.toml --revoke alice
```

`--add` generates a passphrase, writes it to `guests/alice` next to the config (mode 0600, in a 0700 directory), and adds the record to `guest_file`. It prints the paths, the name and the sites, never the passphrase. Hand the passphrase over and delete the file. `--sites` is required and every host must be a `[[sites]]` host of this gate, so a guest is never given every site by default. Adding a name that exists is refused unless `--force`, which replaces their password and so ends their sessions. `--revoke` removes the record and the passphrase file, and their sessions end on the next request. `--list` prints names and sites only. The gate re-reads the guest file when it changes, so none of these needs a restart.

The guest file has one line per guest, `NAME SITES DIGEST`, such as `alice notes.example.com,tools.example.com sha256$<base64>`. `NAME` is 1 to 32 of `a-z`, `0-9`, `_` and `-`, starting with a letter or digit. `DIGEST` is SHA-256 over a fixed label and the passphrase, unsalted. That is safe only because guest passphrases are always generated, with about 80 bits like the owner's `--generate`, so nobody can guess one back from its digest. It keeps a login to one dictionary lookup plus the owner's scrypt. A malformed line is skipped, logged once, and kept when `passwd` rewrites the file.

A guest's session is accepted on a host only when that host is still in the guest's sites, on top of the scope check every session gets. Their cookie carries the site's `cookie_domain`, so one sign-in covers all their sites, and the browser sends it to the owner's other sites under that domain too. The site check is what refuses it there. A guest's password typed into another site's form counts as a wrong password, with the same message and the same rate limit.

Sessions are independent. Changing the owner password does not sign guests out, and revoking a guest does not sign the owner out. The session page says "Signed in as alice (guest)", the gate's log names the guest but never the password, and `gate status` prints how many guests each site has, without names.

## Password and rotation

The hash line is `scrypt$15$8$1$<salt>$<hash>` (log2 N, r, p, base64 salt and hash). Verification runs scrypt with N = 2^15, which takes about 45 ms on an Apple silicon Mac, and compares with `hmac.compare_digest`. Only one scrypt runs at a time, which bounds memory to 32 MiB.

To rotate, run `tailisman passwd` again. The gate re-reads the file when its modification time or size changes, so the new password works on the next request, and every existing owner session ends. Guest sessions do not.

## Rate limiting

Only failed passwords count. Each client IP has a sliding window, and one more window counts failures from all IPs together. While either is full, a login attempt gets 429 with `Retry-After`, before CSRF is checked and without running scrypt. A success does not reset the global window. The windows live in memory, so a restart clears them.

The client IP is `CF-Connecting-IP` when present, then the first `X-Forwarded-For` entry, then the connection's peer. A request that reaches Caddy without going through Cloudflare can set `CF-Connecting-IP` to anything, so a determined guesser can get a fresh per-IP window on every attempt. The global window exists for that case: it caps guesses from everyone at `global` per `window_seconds`, which for the defaults is 2,880 a day. A generated passphrase has about 80 bits, so that rate does not matter for it. It also means that someone guessing can lock the password path for everyone, the owner included, for the rest of the window. The tailnet path is not rate limited and keeps working.

## CSRF

The sign-in and sign-out forms use a double-submit token: a random value in the cookie `tailisman_csrf` (`HttpOnly; Secure; SameSite=Strict; Path=/.tailisman/`) and the same value in a hidden field. A post must carry both, matching, and its `Origin`, when present, must be the site's own origin. Gate pages send `Referrer-Policy: same-origin` rather than `no-referrer`, because under `no-referrer` Chrome 156 sends `Origin: null` on the page's own form posts, which this check refuses.

`/.tailisman/exchange` takes no CSRF token. The one-time code is the proof, and the cross-site form post from the tailnet listener is how the navigation path works. Anyone can post a valid code they hold, which matters only when `[tailnet]` allows devices of several users.

Gate pages send `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' <tailnet origin>; form-action 'self'; base-uri 'none'; frame-ancestors 'none'` and `Cache-Control: no-store`. There is no inline script.

## Running it as a service

launchd, as `~/Library/LaunchAgents/com.example.tailisman-gate.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>com.example.tailisman-gate</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Users/owner/.local/bin/tailisman</string>
		<string>gate</string>
		<string>run</string>
		<string>--config</string>
		<string>/Users/owner/.config/tailisman/gate.toml</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardErrorPath</key><string>/Users/owner/Library/Logs/tailisman-gate.log</string>
</dict>
</plist>
```

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.tailisman-gate.plist
```

systemd, as `/etc/systemd/system/tailisman-gate.service`:

```ini
[Unit]
Description=tailisman gate
After=network.target

[Service]
User=tailisman
ExecStart=/usr/local/bin/tailisman gate run --config /etc/tailisman/gate.toml
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

The gate only reads files, so `ProtectSystem=strict` costs it nothing. Run `tailisman passwd` as a user that can write `password_file`.

## Caveats

- A parent-domain cookie is sent to every host under that domain, including hosts the gate does not cover. Any app on such a host can read the cookie from its requests and replay it to a gated host. Use a host-only cookie, or a `cookie_domain` that covers only gated hosts, when some host under the domain is not yours to trust.
- The cookie is a bearer token for its whole lifetime. Sign out clears it only in that browser. To end every owner session, change the password. To end a guest's, revoke them.
- Changing the owner password signs out every owner session, tailnet sessions included, and no guest.
- A request that skips Cloudflare can choose its own `CF-Connecting-IP`. The global rate limit is the backstop.
- If the site's own `header` directive sets a `Content-Security-Policy`, scope it with `not path /.tailisman/*`, or the silent tailnet path is blocked.
- Open rules are the app's responsibility. The gate refuses to match one against a path with a `..` segment, an empty segment (`//`, which also keeps a leading `//x` from being read as a host), a `;`, an encoded `.`, `/` or `\`, or a backslash, but whatever an open rule lets through reaches the app with no session.
- Rate limits, the one-time codes and the scrypt lock live in one process. Run one gate per host.

## Testing

```sh
uv run --with pytest pytest                                     # includes tests/test_gate.py
uv run python e2e/gate_e2e.py                                   # a real Caddy, the gate with its tailnet listener behind the serve stand-in, an upstream
uv run python e2e/gate_proxy_e2e.py                             # proxy mode with no Caddy: streaming, uploads, Range, websockets, guests, a dead app
uv run --with playwright python e2e/gate_browser_check.py      # the same stack with Caddy's own TLS, in Playwright Chromium
```

`e2e/gate_e2e.py` needs `caddy` on `PATH` (or `--caddy`). It runs Caddy on plain HTTP, as behind a Cloudflare Tunnel, so its client sends the session cookie itself: the cookies are `Secure` and a cookie jar would not send them over HTTP. It prints one line per check and exits non-zero on any failure. `e2e/gate_browser_check.py` resolves `*.example.com` and `*.example.net` to 127.0.0.1 inside Chromium, accepts Caddy's internal certificate, and drives the silent tailnet path, the button, sign-out and the password form. `--screenshots DIR` saves what it saw.
