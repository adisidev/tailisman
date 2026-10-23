#!/usr/bin/env python3
"""Stands in for the tailscale CLI in tests and local demos. Never talks to a tailnet.

Reads the JSON file named by FAKE_TAILSCALE_STATE:
  {"whois": {"192.0.2.1": <whois --json output>}, "status": {"Self": {"DNSName": "..."}}, "serve_status": {...}, "serve_status_text": "..."}
"""
import json
import os
import sys

state = json.load(open(os.environ["FAKE_TAILSCALE_STATE"]))
args = sys.argv[1:]
if args[:2] == ["whois", "--json"] and len(args) == 3:
    peer = state.get("whois", {}).get(args[2])
    if peer is None:
        sys.stderr.write("peer not found\n")
        sys.exit(1)
    print(json.dumps(peer))
elif args == ["status", "--json"]:
    print(json.dumps(state.get("status", {})))
elif args == ["serve", "status", "--json"]:
    print(json.dumps(state.get("serve_status", {})))
elif args == ["serve", "status"]:
    print(state.get("serve_status_text", "No serve config"))
else:
    sys.stderr.write("fake tailscale: unsupported command %s\n" % args)
    sys.exit(2)
