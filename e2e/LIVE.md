# Reproducing the Findings on your own tailnet

This is the sequence behind the README's Findings section. It needs two of your own tailnet devices that can run a browser under Playwright: device A runs the issuer, the demo consumer and most browser checks, device B is a second allowlisted device. It also needs one machine that is not on the tailnet, and `cloudflared` on device A for a temporary public origin. Everything below uses placeholders. Replace `laptop.example-tailnet.ts.net` with device A's MagicDNS name and `nEXAMPLE...CNTRL` with real stable IDs.

The run adds one serve handler on a spare port and removes it at the end. It does not touch anything else in your serve config, and it never uses Funnel.

## 1. Prepare device A

```sh
git clone https://github.com/adisidev/tailisman && cd tailisman   # on device B as well
uv run --with playwright playwright install chrome chromium webkit firefox
mkdir -p ~/tailisman-live
tailscale serve status --json > ~/tailisman-live/serve-before.json
uv run tailisman keygen ~/tailisman-live/secret
```

Start a quick tunnel for the demo consumer and keep it running in its own terminal. It prints a `https://<random>.trycloudflare.com` origin.

```sh
cloudflared tunnel --url http://127.0.0.1:8080
```

```sh
export DEMO=https://<random>.trycloudflare.com
export ISSUER=https://laptop.example-tailnet.ts.net:8444
```

## 2. Two configs

`~/tailisman-live/live-1.toml` allows both devices:

```toml
secret_file = "secret"
listen = "127.0.0.1:8470"
devices = ["nEXAMPLEACNTRL", "nEXAMPLEBCNTRL"]

[[audiences]]
origin = "https://<random>.trycloudflare.com"
```

`~/tailisman-live/live-2.toml` drops device A and refuses automation:

```toml
secret_file = "secret"
listen = "127.0.0.1:8470"
devices = ["nEXAMPLEBCNTRL"]

[[audiences]]
origin = "https://<random>.trycloudflare.com"
refuse_automation = true
```

If you do not know the stable IDs yet, start the issuer with either config, open `$ISSUER/` on each device, and copy the `devices = [...]` line the status page prints.

## 3. Serve the issuer on a spare port

Run the issuer in its own terminal (it stays in the foreground), then add the serve handler.

```sh
uv run tailisman run --config ~/tailisman-live/live-1.toml
```

```sh
tailscale serve --bg --https=8444 http://127.0.0.1:8470
uv run tailisman check --config ~/tailisman-live/live-1.toml
```

`check` must end with `Funnel off` and show `$ISSUER` as the served host.

## 4. Demo consumer

In another terminal on device A:

```sh
export TAILISMAN_KEY=$(uv run tailisman key --config ~/tailisman-live/live-1.toml --aud "$DEMO")
uv run python demo/consumer.py --port 8080 --origin "$DEMO" --issuer "$ISSUER"
```

## 5. curl checks (config 1)

From device A:

```sh
curl -s -H "Origin: $DEMO" "$ISSUER/v1/claim?a=0"                  # {"token": "tsm1...."}
curl -s -H "Origin: $DEMO" -H "X-Forwarded-For: 192.0.2.9" -H "Tailscale-User-Login: someone@example.com" "$ISSUER/v1/claim"
                                                                    # still a token for device A; the issuer log says "issued for laptop"
curl -si -H "Origin: https://evil.example.com" "$ISSUER/v1/claim"   # 403 unknown_audience and no Access-Control-Allow-Origin
curl -s -H "Host: rebind.example" -H "X-Forwarded-For: 192.0.2.9" -H "X-Forwarded-Proto: https" -H "Origin: $DEMO" http://127.0.0.1:8470/v1/claim
                                                                    # {"error": "wrong_host"}, what a DNS-rebinding page would get
```

From device B, the first command again gives a token for device B.

Verify a token with both verifiers. Each line reads one token; get a fresh one from the first curl for each.

```sh
T=$(curl -s -H "Origin: $DEMO" "$ISSUER/v1/claim" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
uv run python -c 'import os,sys; from tailisman import Verifier; v=Verifier(key=os.environ["TAILISMAN_KEY"], audience=sys.argv[1]); print(v.verify(sys.argv[2])); v.verify(sys.argv[2])' "$DEMO" "$T"
                                                                    # prints the claim, then raises replayed
(cd js && node -e 'import("./src/index.js").then(m => { const v = new m.Verifier({ key: process.env.TAILISMAN_KEY, audience: process.argv[1] }); console.log(v.verify(process.argv[2])); })' "$DEMO" "$T")
                                                                    # a fresh T: the same claim
```

For the other refusals, take a fresh `T` each time and verify it with the same key but `audience="https://other.example.com"` (`wrong_audience`), with its last character changed (`bad_signature`), or 66 seconds later (`expired`).

From the machine that is not on the tailnet:

```sh
curl -sS --max-time 10 "$ISSUER/healthz"; echo "exit=$?"            # exit=6, the name does not resolve
curl -sSk --max-time 10 https://<device A tailnet IP>:8444/healthz; echo "exit=$?"
                                                                    # exit=28, the tailnet IP is unreachable
```

## 6. Browser matrix (config 1, on device A)

```sh
check() { uv run --with playwright python e2e/browser_check.py --demo "$DEMO" "$@"; }
check --browser chrome --grant-lna --expect signed-in
check --browser chrome --expect unreachable
check --browser chrome --transport navigate --expect signed-in
check --browser webkit --expect signed-in
check --browser firefox --expect unreachable --timeout 40
check --browser firefox --transport navigate --expect signed-in
check --browser chrome --simulate-off-tailnet --expect unreachable
```

Each run prints one JSON line and exits non-zero when the outcome is not the one expected. Add `--screenshot PATH` to keep a picture. The WebKit run is Playwright's WebKit build, headless, not Safari itself.

## 7. Allowlist removal and automation (config 2)

Stop the issuer and start it with `live-2.toml`. The demo keeps its key, because the key depends only on the secret and the origin.

```sh
uv run tailisman run --config ~/tailisman-live/live-2.toml
```

On device A, `curl -s -H "Origin: $DEMO" "$ISSUER/v1/claim"` now answers `{"error": "not_on_allowlist"}`. On device B:

```sh
curl -s -H "Origin: $DEMO" "$ISSUER/v1/claim"                       # a token for device B
check() { uv run --with playwright python e2e/browser_check.py --demo "$DEMO" --browser chrome --grant-lna "$@"; }
check --expect refused                                              # refused as automation
check --expect signed-in --spoof-automation                         # the same browser with its signals hidden signs in
```

## 8. Restore

```sh
tailscale serve --https=8444 off
tailscale serve status --json > ~/tailisman-live/serve-after.json
diff ~/tailisman-live/serve-before.json ~/tailisman-live/serve-after.json && echo "serve config restored"
```

Stop the issuer, the demo and `cloudflared`, then delete `~/tailisman-live`.
