---
name: tailisman
description: This skill should be used when the user asks to lock, secure, password-protect, put a login in front of, or make private their personal pages, self-hosted sites, dashboards, or tools on their own domain, for example "Lock my personal pages with adisidev/tailisman". It sets up the tailisman gate, which signs the owner in silently from their own Tailscale devices and asks everyone else for a password, in front of sites served through Cloudflare Tunnel, Caddy, nginx, or tailscale serve.
---

# Lock personal pages with tailisman

You are setting up the tailisman gate for one owner. When you finish, every chosen page answers an anonymous visitor with a sign-in page, the owner's own tailnet devices get in without typing anything, a backup password works everywhere else, and every script or app that used to call those pages still works.

Work through the steps in order. Each step ends in a check. Do not go to the next step until the check passes.

If you read this file from GitHub, fetch each relative link from `https://raw.githubusercontent.com/adisidev/tailisman/main/skills/tailisman/` plus the link. The two references are [references/front-doors.md](references/front-doors.md) (discovery and config for each way pages are served) and [references/cloudflare.md](references/cloudflare.md) (tunnel API, cache purge, timeouts). [docs/GATE.md](https://github.com/adisidev/tailisman/blob/main/docs/GATE.md) is the full gate reference.

Rules for the whole run:

- Never print, log, or paste a password, passphrase, session secret, or bearer token. Read them from files or stdin. Show file paths instead.
- Never put the gate's tailnet listener behind `tailscale funnel`. It goes behind `tailscale serve` only.
- Back up every config file before you change it, and write a rollback before you switch traffic (step 4).
- Do not assume a port is free. Check it.

## 1. Find how the pages are served

Find the front door for each hostname the user might mean. Run what applies.

```sh
ps aux | grep -E '[c]loudflared|[c]addy|[n]ginx|[t]ailscaled'
cloudflared tunnel list                      # tunnels this machine has credentials for
ls ~/.cloudflared/ /etc/cloudflared/ 2>/dev/null
tailscale serve status; tailscale funnel status
lsof -nP -iTCP -sTCP:LISTEN                  # macOS; on Linux: ss -ltnp
```

On macOS the `tailscale` CLI may not be on `PATH`. Use `/Applications/Tailscale.app/Contents/MacOS/Tailscale` in its place.

[references/front-doors.md](references/front-doors.md) has the commands that read each front door's config, and the gate config for each. Pick the gate mode from this table.

| Front door | Gate mode |
| --- | --- |
| Cloudflare Tunnel, config file (`cloudflared ... --config` or `~/.cloudflared/config.yml`) | Proxy mode. Point each hostname's `service` at the gate and give the site an `upstream`. This is the simplest setup. |
| Cloudflare Tunnel, remotely managed (`cloudflared tunnel run --token ...`) | Proxy mode. Change the hostname's service through the API or dashboard. |
| Caddy | `forward_auth` snippet, or proxy mode with `reverse_proxy` to the gate. Both tested. |
| nginx | Proxy mode with `proxy_pass` to the gate (recommended). An `auth_request` config exists in the reference but is untested. |
| `tailscale serve` only, no Funnel | The pages are already reachable only on the tailnet. Tell the user so. Gate them only if they want a password for tailnet guests. |
| `tailscale funnel` | Public. Proxy mode behind the Funnel handler is possible but untested. Prefer moving the site to a tunnel or Caddy. |
| A bare port open to the internet | Put a TLS front door first (a tunnel or Caddy). The gate speaks plain HTTP on loopback and its cookies are `Secure`, so browsers need HTTPS. |

For every site, also find the app's own listener (its port and bind address). If the app listens on `0.0.0.0` or `*` and the machine is reachable from the internet, gating the front door does not stop anyone who connects to the port directly. Plan to bind the app to `127.0.0.1` or close the port.

**Check.** you can write one line per hostname that names the machine, the front door, the app's `host:port`, and the gate mode.

## 2. Ask the user in one message

Send one short message. Ask only these things, and offer what you found.

1. Which of these hostnames (list them) are "only for me"?
2. Which devices count as yours? Show the device list from the command below, and say you will allowlist them by stable ID, because names can be reused.
3. Does anyone else need in? If yes, who, and to which hostnames? They get their own guest password.
4. If a Cloudflare proxy or a remotely managed tunnel is involved, can they save a Cloudflare API token to a file for you ([permissions](references/cloudflare.md#an-api-token)), or would they rather do the dashboard steps themselves?

```sh
tailscale status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); [print(n["ID"], n["HostName"], n["OS"], "tagged" if n.get("Tags") else "", "online" if n.get("Online") else "offline") for n in [d["Self"], *d.get("Peer", {}).values()]]'
```

The first column is the stable ID (`n...CNTRL`). Tagged devices are always refused, so leave them out. Find everything else yourself.

**Check.** You have the list of hostnames to gate, the stable IDs to allow, and a list of guests (possibly empty).

## 3. Install one gate per serving machine

Run one gate on each machine that serves gated pages. Each gate has its own config, its own `[tailnet]` listener behind that machine's `tailscale serve`, and its own owner password.

Install the CLI (Python 3.11 or later, no dependencies).

```sh
uv tool install git+https://github.com/adisidev/tailisman
# without uv
pipx install git+https://github.com/adisidev/tailisman
```

Pick two free loopback ports, one for the public listener (default 8471) and one for the tailnet listener (default 8470), and one free tailnet HTTPS port for serve (default 8443). An empty answer means the port is free.

```sh
lsof -nP -iTCP:8471 -sTCP:LISTEN; lsof -nP -iTCP:8470 -sTCP:LISTEN   # Linux: ss -ltn 'sport = :8471'
tailscale serve status                                                # 8443 must not already have a handler
```

Create the secret and the config. `keygen` refuses to overwrite an existing file.

```sh
mkdir -p ~/.config/tailisman && chmod 700 ~/.config/tailisman
tailisman keygen ~/.config/tailisman/gate-secret
tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))'   # serve_host
```

Write `~/.config/tailisman/gate.toml` and `chmod 600` it. This is a proxy-mode site. For a `forward_auth` site behind Caddy, leave out `upstream`.

```toml
listen = "127.0.0.1:8471"
session_secret_file = "gate-secret"
password_file = "gate-password"

[tailnet]
listen = "127.0.0.1:8470"
serve_host = "gate.example-tailnet.ts.net"
port = 8443
devices = ["nEXAMPLE1CNTRL", "nEXAMPLE2CNTRL"]

[[sites]]
host = "tools.example.com"
upstream = "http://127.0.0.1:9000"
```

Add `cookie_domain = "example.com"` to sites only when every host under that domain is served by this same gate and is yours to trust. Otherwise leave cookies host-only. The tailnet sign-in is silent, so a sign-in per host costs a tailnet device nothing.

Make the owner's backup password. It prints only paths. Do not `cat` the passphrase file. The user moves it into their password manager and deletes the file after step 8.

```sh
tailisman passwd --config ~/.config/tailisman/gate.toml --generate --out ~/.config/tailisman/gate-passphrase
```

Put the tailnet listener behind serve, never Funnel.

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:8470
```

Run the gate as a service. The launchd plist and the systemd unit are in [docs/GATE.md, "Running it as a service"](https://github.com/adisidev/tailisman/blob/main/docs/GATE.md#running-it-as-a-service). Use the path from `command -v tailisman` in `ProgramArguments` or `ExecStart`, and the config path you chose. The systemd unit there runs as a `tailisman` user with `/etc/tailisman/gate.toml`. If you keep that, put the config, secret, and password file there and make them readable by that user.

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.tailisman-gate.plist   # macOS
sudo systemctl enable --now tailisman-gate                                                  # Linux
```

The gate reads `gate.toml` only at startup. Restart it after every edit to that file (`launchctl kickstart -k gui/$(id -u)/com.example.tailisman-gate` or `sudo systemctl restart tailisman-gate`). Password and guest changes need no restart.

**Check.** Do this before any traffic goes through the gate. Point `gate status` at the loopback listener with one `--base-url-for HOST=http://127.0.0.1:8471` per site. The `tailnet:` line must say `ok, served, Funnel off`, and every proxy-mode site line must end in `ok`. A `forward_auth` site answers 404 here until Caddy or nginx sits in front, so its line passes only after step 6.

```sh
tailisman gate status --config ~/.config/tailisman/gate.toml --base-url-for tools.example.com=http://127.0.0.1:8471
```

## 4. Back up and write the rollback

Before you change any front door, copy each config you will change to a timestamped file, and write one rollback command per host. [references/front-doors.md](references/front-doors.md#rollback) has the backup and rollback commands for each front door.

```sh
mkdir -p ~/.config/tailisman/backups
cp ~/.cloudflared/config.yml ~/.config/tailisman/backups/cloudflared-config.yml.$(date +%Y%m%d-%H%M%S)
```

Write each rollback as a script, `~/.config/tailisman/backups/rollback-<host>.sh`, that prints its commands instead of running them when `DRY_RUN=1` is set.

**Check.** `DRY_RUN=1 sh ~/.config/tailisman/backups/rollback-<host>.sh` prints the restore command for every host. The backup it names validates (`cloudflared tunnel --config <backup> ingress validate`, `caddy validate --config <backup> --adapter caddyfile`, or `nginx -t`).

## 5. Keep machine callers working

Find everything that calls these hostnames without a browser: cron jobs, launchd agents, systemd timers, scripts, phone apps and shortcuts, feed readers, webhooks from other services, and other agents.

```sh
rg -l --hidden -e 'tools\.example\.com' ~ /etc 2>/dev/null | grep -v -e '/\.git/' -e node_modules   # or grep -rIl
crontab -l; ls ~/Library/LaunchAgents /etc/systemd/system 2>/dev/null; systemctl list-timers 2>/dev/null
```

Then read the app's access log (or the front door's) for the last few days and list user agents that are not browsers, such as `curl`, `python-requests`, `Go-http-client`, `okhttp`, `node`, or an app name with `CFNetwork`. Ask the user about any caller you cannot place.

For each caller, choose in this order.

1. It sends `Authorization: Bearer <token>` already. List the token's digest in that site's `bearers`. The gate reads the token from stdin, so it stays out of shell history. Pipe it from wherever the caller keeps it, without echoing it.

	```sh
	tailisman gate bearer-hash < /path/to/the/callers/token-file
	```

	```toml
	bearers = ["sha256$<base64>"]
	```

	Only a token whose digest is listed passes. Never write an open rule that lets through any request with an `Authorization` header. Many apps answer a request with a missing or wrong token as an anonymous visitor and serve their public view to it. Under such a rule, anyone who sends `Authorization: Bearer x` gets that view of a gated site with no sign-in.

2. It sends its credential another way (a query string, a cookie, an HMAC signature on a webhook). Add an `open` rule for that exact path only if the app itself refuses the request without a valid credential. Check that by calling the path with no credential and seeing a 401 or 403 from the app. Open rules are the app's job to guard, not the gate's.

3. It sends nothing. Ask the user whether it should keep working. If yes, give it a bearer token the app checks, or leave that path open only if its content is fine to be public.

**Check.** After a restart of the gate, `tailisman gate status` shows the expected `bearers` count per site. After step 6, each caller succeeds in a real run (trigger the cron job, re-deliver the webhook, run the script), and the app's log shows its request answered 200.

## 6. Switch the front door

Change each front door as [references/front-doors.md](references/front-doors.md) shows for its kind: the tunnel ingress `service` to `http://127.0.0.1:8471`, the Caddy snippet, or nginx's `proxy_pass`. Reload it. If step 1 found the app listening publicly, bind it to `127.0.0.1` now.

**Check.** `tailisman gate status --config ~/.config/tailisman/gate.toml` (no `--base-url-for` this time) ends every line in `ok` and exits 0.

## 7. Purge the Cloudflare cache

Skip this when no Cloudflare proxy sits in front of the host. Cloudflare caches `.js`, `.css`, images, and PDFs at its edge even when the app sent no `Cache-Control`, and serves those copies to anyone without asking the origin. The gate marks its answers `private` from now on, but copies cached before you gated the host stay at the edge until you purge them. [references/cloudflare.md](references/cloudflare.md#purge-the-cache) has the API call and the dashboard path.

**Check.** Fetch a real asset path from the site anonymously. It must answer 401 or 302, and `cf-cache-status` must not be `HIT`.

```sh
curl -sI https://tools.example.com/app.js | grep -iE '^(HTTP|cf-cache-status|cache-control)'
```

## 8. Verify everything

Run these from a machine that is not signed in. Use real paths from the site.

```sh
tailisman gate status --config ~/.config/tailisman/gate.toml
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -H 'Accept: text/html' https://tools.example.com/   # 302 .../.tailisman/login?next=%2F
curl -s -w ' %{http_code}\n' https://tools.example.com/api/anything                                        # {"error": "sign_in_required"} 401
curl -s -o /dev/null -w '%{http_code}\n' https://tools.example.com/app.js                                  # 401
```

Sign in with the password through the form. The passphrase file ends in a newline, which the form does not strip, so remove it on the way in. A wrong password counts against the rate limit.

```sh
U=https://tools.example.com J=$(mktemp)
CSRF=$(curl -s -c "$J" "$U/.tailisman/login?next=/" | sed -n 's/.*name=csrf value="\([^"]*\)".*/\1/p')
tr -d '\n' < ~/.config/tailisman/gate-passphrase | curl -s -b "$J" -c "$J" -o /dev/null -w '%{http_code} %{redirect_url}\n' \
	--data-urlencode "csrf=$CSRF" --data-urlencode "next=/" --data-urlencode "password@-" "$U/.tailisman/login"   # 303 https://tools.example.com/
curl -s -b "$J" -o /dev/null -w '%{http_code}\n' "$U/"                                                      # 200
rm -f "$J"
```

Check the tailnet path from an allowlisted device. If the machine you run on is on the `devices` list, curl does the whole round trip.

```sh
CODE=$(curl -s -H "Origin: https://tools.example.com" "https://gate.example-tailnet.ts.net:8443/v1/claim?a=0" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -s -H 'Content-Type: application/json' -d "{\"token\": \"$CODE\"}" "https://tools.example.com/.tailisman/exchange?next=/"   # {"device": "<name>", "next": "/"}
```

Then ask the user to open the site in a browser on one listed device. The page should say "Recognised <device>, signing you in" and land on the page. Opening `https://gate.example-tailnet.ts.net:8443/` on a device shows what the gate sees for it, including its stable ID.

Run every machine caller from step 5 for real once more.

## 9. Add guests

Give each guest from step 2 a generated password for named sites only.

```sh
tailisman passwd --config ~/.config/tailisman/gate.toml --add alice --sites tools.example.com,notes.example.com
tailisman passwd --config ~/.config/tailisman/gate.toml --list
tailisman passwd --config ~/.config/tailisman/gate.toml --revoke alice
```

`--add` writes the passphrase to `guests/alice` next to the config, mode 0600, and prints paths only. Do not print the file. Tell the user its path, and that they should send it to the guest over a private channel (a password manager share, or a message that expires), then delete the file. Every host in `--sites` must be a `[[sites]]` host of this gate. `--revoke` ends the guest's sessions on their next request. None of these needs a restart.

**Check.** `--list` shows each guest with only their sites.

## Done when

- [ ] `tailisman gate status` exits 0 on every serving machine, with `ok, served, Funnel off` on the `tailnet:` line.
- [ ] An anonymous page gets 302 to `/.tailisman/login`, an API path gets 401, and an asset gets 401 with no `cf-cache-status: HIT`.
- [ ] The password signs in through the form, and a listed device signs in with no typing.
- [ ] Every machine caller succeeded in a real run after gating.
- [ ] No app listens publicly on its own port.
- [ ] Each host has a backup and a rollback script whose dry run prints the restore.
- [ ] The user has the owner passphrase in their password manager and the file `gate-passphrase` is deleted. Guest passphrase files are handed over and deleted.
- [ ] You told the user the gate's config path, how to roll back, and how to add or revoke a guest.

## What can go wrong

- The first time a Chrome or Firefox visits a gated site from a listed device, the browser asks for local network access. Tell the user to allow it once per site. Until then, the page shows a "Sign in from this device" button, which works without the permission. Safari on macOS was observed signing in silently with no prompt. Safari on iOS has not been tested.
- A `cookie_domain` cookie goes to every host under that domain, including hosts that no gate covers, and any app on such a host can read and replay it. Two gates on different machines that share one `cookie_domain` also overwrite each other's cookie, so the user is signed out of one each time they sign in to the other. Keep cookies host-only in both cases.
- Five failed passwords from one IP, or thirty from everyone, in 15 minutes lock the password form with 429 for the rest of the window. Restarting the gate clears it. The tailnet path keeps working.
- Open rules let requests through to the app with no session. Whatever the app serves on an open path is public.
- Cloudflare's proxy ends a request with a 524 when the origin sends no response headers for 100 seconds. A long poll longer than that breaks behind Cloudflare with or without the gate. The gate itself has no read timeout.
- Behind nginx, set `X-Forwarded-For` to `$remote_addr`. Without it every visitor shares one rate-limit window.
- Changing the owner password signs out every owner session, tailnet sessions included. Guests stay signed in.
