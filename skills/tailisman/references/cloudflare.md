# Cloudflare

API calls for a remotely managed tunnel and for the cache purge, and the Cloudflare behaviour that affects a gated site.

## An API token

Ask the user for a token only if the tunnel is remotely managed or you purge through the API. Otherwise the user can do the dashboard steps. The token needs **Account**, **Cloudflare Tunnel**, **Edit** for the tunnel, and **Zone**, **Cache Purge**, **Purge** for the purge, on the zones of the gated hosts. Have the user save it to a file, then turn it into a header file so it never appears on a command line.

```sh
chmod 600 ~/.config/tailisman/cf-token
{ printf 'Authorization: Bearer '; cat ~/.config/tailisman/cf-token; } > ~/.config/tailisman/cf-auth-header
chmod 600 ~/.config/tailisman/cf-auth-header
H=@$HOME/.config/tailisman/cf-auth-header
curl -s -H "$H" https://api.cloudflare.com/client/v4/user/tokens/verify      # "status": "active"
```

The account and zone IDs:

```sh
curl -s -H "$H" https://api.cloudflare.com/client/v4/accounts | python3 -c 'import json,sys; [print(a["id"], a["name"]) for a in json.load(sys.stdin)["result"]]'
curl -s -H "$H" "https://api.cloudflare.com/client/v4/zones?name=example.com" | python3 -c 'import json,sys; [print(z["id"], z["name"]) for z in json.load(sys.stdin)["result"]]'
```

## Tunnel configuration API

```sh
A=https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID
curl -s -H "$H" "$A/cfd_tunnel?is_deleted=false" | python3 -c 'import json,sys; [print(t["id"], t["name"], t["status"]) for t in json.load(sys.stdin)["result"]]'
B=~/.config/tailisman/backups/tunnel-$TUNNEL_ID.$(date +%Y%m%d-%H%M%S).json
curl -s -H "$H" "$A/cfd_tunnel/$TUNNEL_ID/configurations" > "$B"
python3 -c 'import json,sys; [print(r.get("hostname", "*"), r["service"]) for r in json.load(open(sys.argv[1]))["result"]["config"]["ingress"]]' "$B"
```

Point the gated hostnames at the gate and push the result. Everything else in the configuration stays as it was.

```sh
python3 - "$B" tools.example.com,notes.example.com http://127.0.0.1:8471 > /tmp/tunnel-new.json <<'EOF'
import json, sys
config = json.load(open(sys.argv[1]))["result"]["config"]
hosts = set(sys.argv[2].split(","))
for rule in config["ingress"]:
    if rule.get("hostname") in hosts:
        rule["service"] = sys.argv[3]
print(json.dumps({"config": config}))
EOF
curl -s -X PUT -H "$H" -H 'Content-Type: application/json' --data @/tmp/tunnel-new.json "$A/cfd_tunnel/$TUNNEL_ID/configurations" | python3 -c 'import json,sys; print(json.load(sys.stdin)["success"])'
```

The rollback is the same `PUT` with `{"config": ...}` built from the saved file's `result.config`.

## Purge the cache

Purge each gated host once, right after its front door points at the gate.

```sh
curl -s -X POST -H "$H" -H 'Content-Type: application/json' --data '{"hosts": ["tools.example.com"]}' \
	"https://api.cloudflare.com/client/v4/zones/$ZONE_ID/purge_cache" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["success"], d.get("errors"))'
```

If the API refuses a purge by host on the zone's plan, purge the asset URLs you know with `{"files": ["https://tools.example.com/app.js"]}`, or the whole zone with `{"purge_everything": true}` after telling the user it empties the cache for every host on the zone. In the dashboard, open the zone, then **Caching**, **Configuration**, **Purge Cache**.

Check Cache Rules and Page Rules for the zone too. A rule that caches everything on a gated host, or one that overrides the edge TTL regardless of the origin's `Cache-Control`, keeps caching gated answers after the purge. Remove the gated hosts from such rules.

`cf-cache-status` on a response says what the edge did. `HIT` means the edge answered from a stored copy without asking the origin. A gated asset fetched anonymously must answer 401 or 302, with `cf-cache-status` of `DYNAMIC`, `BYPASS`, or `MISS`.

## The 100 second timeout

Cloudflare's proxy answers 524 when the origin sends no response headers within 100 seconds, on the Free, Pro, and Business plans. A long poll that waits longer breaks behind Cloudflare whether or not the gate is there. The gate has a 10 second connect timeout to the upstream and no read timeout. Server-sent events and websockets are not affected once the first headers are sent.
