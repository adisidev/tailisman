# Front doors

How to read each kind of front door, how to put the gate behind it, and how to roll it back. Every example uses `tools.example.com` for a gated host, `127.0.0.1:9000` for the app, `127.0.0.1:8471` for the gate's public listener, and `gate.example-tailnet.ts.net` for the gate machine's MagicDNS name. Replace them with what you found.

On macOS the `tailscale` CLI may not be on `PATH`. The app's binary is `/Applications/Tailscale.app/Contents/MacOS/Tailscale`.

## Cloudflare Tunnel with a config file

A locally managed tunnel runs as `cloudflared tunnel run <name>` or `cloudflared tunnel --config <file> run`, and its ingress rules live in that file. The default is `~/.cloudflared/config.yml`, and a system service usually reads `/etc/cloudflared/config.yml`.

```sh
ps aux | grep '[c]loudflared'                     # which file, which tunnel
cloudflared tunnel --config ~/.cloudflared/config.yml ingress validate
cloudflared tunnel --config ~/.cloudflared/config.yml ingress rule https://tools.example.com/   # the rule and service this host uses today
```

The old `service` for the host is the app's address. Put it in the gate's site as `upstream`, then point the tunnel at the gate. The upstream must be plain `http://HOST:PORT`. If the old service was `https://...`, find the app's plain HTTP port, or put the gate on the far side of whatever terminated TLS.

```yaml
ingress:
  - hostname: tools.example.com
    service: http://127.0.0.1:8471
  - service: http_status:404
```

```toml
[[sites]]
host = "tools.example.com"
upstream = "http://127.0.0.1:9000"
```

Restart cloudflared after the edit, the way it was started (`systemctl restart cloudflared`, or `launchctl kickstart -k` on the label `launchctl list | grep -i cloudflare` shows). cloudflared does not re-read the file by itself.

Check: `ingress rule https://tools.example.com/` prints `service: http://127.0.0.1:8471`, and `tailisman gate status` passes.

Look through every ingress rule for the same app address under another hostname or a wildcard. Any rule that still points at the app goes around the gate.

## Cloudflare Tunnel, remotely managed

A remotely managed tunnel runs as `cloudflared tunnel run --token ...` (or `cloudflared service install <token>`), and its ingress rules live in Cloudflare. Change them through the API ([cloudflare.md](cloudflare.md#tunnel-configuration-api)) or in the dashboard under Zero Trust, **Networks**, **Tunnels**, the tunnel, and its published hostnames. The new service URL is resolved on the machine that runs the connector, so the gate runs on that machine.

The changes and checks are the same as for a config file. A pushed configuration takes effect without a restart.

## Caddy

Find the Caddyfile from `ps aux | grep '[c]addy'` (the `--config` argument), or look in `/etc/caddy/Caddyfile` and `$(brew --prefix)/etc/Caddyfile`.

```sh
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

`forward_auth` mode leaves the app behind Caddy and asks the gate about each request. Leave `upstream` out of the gate's site. This snippet is the one in `docs/GATE.md`, measured on Caddy 2.11.7.

```caddy
(tailisman_gate) {
	header ?Cache-Control "private"
	header >Cache-Control "public" "private"
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

Behind a Cloudflare Tunnel that talks plain HTTP to Caddy, the site block is `http://tools.example.com { ... }`. If the site sets its own `Content-Security-Policy` with `header`, scope it with `not path /.tailisman/*`, or the silent tailnet path is blocked.

Proxy mode works behind Caddy too. Give the gate's site an `upstream` and replace the site's `reverse_proxy` target with the gate. Caddy keeps the original `Host`, which the gate needs.

```caddy
tools.example.com {
	reverse_proxy 127.0.0.1:8471
}
```

## nginx

```sh
nginx -T 2>/dev/null | grep -nE 'server_name|proxy_pass|listen|include'   # the whole loaded config
nginx -t && nginx -s reload                                                # or systemctl reload nginx
```

### Proxy mode in front of nginx's upstream (recommended)

nginx sends everything for the host to the gate, and the gate proxies to the app. The gate side is the tested proxy mode. This nginx block has not been run against the gate.

```nginx
map $http_upgrade $connection_upgrade { default upgrade; "" close; }

server {
	server_name tools.example.com;
	# keep the existing listen and TLS lines

	location / {
		proxy_pass http://127.0.0.1:8471;
		proxy_set_header Host $http_host;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto https;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection $connection_upgrade;
		proxy_buffering off;
		proxy_request_buffering off;
		proxy_read_timeout 1h;
	}
}
```

`Host` must be the browser's host, because the gate picks the site by it. `X-Forwarded-For` is set, not appended, because the gate's rate limit reads its first entry. Put the app's old `proxy_pass` target in the gate's site as `upstream`. If nginx had `proxy_cache` on for this host, turn it off or make sure it honours `Cache-Control: private`.

### auth_request (untested)

This is the nginx counterpart of Caddy's `forward_auth`. It has not been run. nginx's `auth_request` treats only 2xx, 401, and 403 from the check as answers and turns anything else, the gate's 302 included, into a 500. So the block hides `Accept` from the gate, which then always answers 401 without a session, and nginx makes the redirect itself. A `next` path that contains `&` loses everything after it.

```nginx
map $http_accept $tailisman_page { default 0; ~text/html 1; }
map $upstream_http_cache_control $tailisman_cache_control { "" private; ~*public private; default $upstream_http_cache_control; }

server {
	server_name tools.example.com;

	location /.tailisman/ {
		proxy_pass http://127.0.0.1:8471;
		proxy_set_header Host $http_host;
		proxy_set_header X-Forwarded-For $remote_addr;
	}

	location = /.tailisman-auth {
		internal;
		proxy_pass http://127.0.0.1:8471/.tailisman/verify;
		proxy_pass_request_body off;
		proxy_set_header Content-Length "";
		proxy_set_header Accept "";
		proxy_set_header Host $http_host;
		proxy_set_header X-Forwarded-Method $request_method;
		proxy_set_header X-Forwarded-Uri $request_uri;
		proxy_set_header X-Forwarded-For $remote_addr;
	}

	location @tailisman_signin {
		if ($tailisman_page) { return 302 /.tailisman/login?next=$request_uri; }
		default_type application/json;
		return 401 '{"error": "sign_in_required"}';
	}

	location / {
		auth_request /.tailisman-auth;
		error_page 401 = @tailisman_signin;
		auth_request_set $tailisman_session $upstream_http_x_tailisman_session;
		auth_request_set $tailisman_user $upstream_http_x_tailisman_user;
		proxy_set_header X-Tailisman-Session $tailisman_session;
		proxy_set_header X-Tailisman-User $tailisman_user;
		proxy_hide_header Cache-Control;
		add_header Cache-Control $tailisman_cache_control always;
		proxy_pass http://127.0.0.1:9000;
	}
}
```

`nginx -V 2>&1 | grep -o http_auth_request_module` must print the module name. The two `proxy_set_header X-Tailisman-*` lines replace any copy a client sent, and nginx drops a header whose value is empty.

## tailscale serve and Funnel

```sh
tailscale serve status --json
tailscale funnel status
```

A handler that `serve status` lists without Funnel is reachable only from the tailnet. Tell the user those pages are already private to their tailnet and need no gate, unless they want guests on the tailnet to need a password.

A handler with Funnel on is public. Proxy mode behind the Funnel handler (`tailscale funnel --bg --https=443 http://127.0.0.1:8471`, with the app as `upstream`) has not been tested. Funnel only accepts ports 443, 8443, and 10000, so the gate's tailnet listener must use another serve port when Funnel holds 8443. Set `[tailnet] port` to match. The tailnet listener itself never goes behind Funnel.

## A bare port

An app that listens on a public address with no proxy in front has no TLS, and the gate's cookies are `Secure`. Put Caddy (automatic HTTPS) or a Cloudflare Tunnel in front, follow that section, and bind the app to `127.0.0.1`.

## Rollback

Keep every backup and rollback script in `~/.config/tailisman/backups/`. Write the rollback with absolute paths and this shape, so `DRY_RUN=1` prints each command instead of running it.

```sh
#!/bin/sh
set -eu
run() { if [ "${DRY_RUN:-0}" = 1 ]; then echo "+ $*"; else "$@"; fi; }
run cp /home/owner/.config/tailisman/backups/cloudflared-config.yml.20261023-101500 /home/owner/.cloudflared/config.yml
run sudo systemctl restart cloudflared
```

The backup and restore for each front door:

| Front door | Back up | Restore | Dry-run check |
| --- | --- | --- | --- |
| Tunnel, config file | `cp` the config file | `cp` it back, restart cloudflared | `cloudflared tunnel --config <backup> ingress rule https://<host>/` prints the old service |
| Tunnel, remote | save the `GET .../configurations` answer ([cloudflare.md](cloudflare.md#tunnel-configuration-api)) | `PUT` `{"config": <saved result.config>}` | print the hostname and service pairs from the saved file |
| Caddy | `cp` the Caddyfile | `cp` it back, `caddy reload` | `caddy validate --config <backup> --adapter caddyfile` |
| nginx | `cp` the site's file | `cp` it back, `nginx -t && nginx -s reload` | `diff` the backup against the live file |

Removing the gate entirely also takes `tailscale serve --https=8443 off` for its tailnet handler and stopping its service. A front door that is restored no longer sends traffic to the gate, so that part can wait.
