# tailisman design

This records why tailisman has the shape it has. The README covers how to use it.

## The problem

A public web app wants to know that its visitor's browser runs on one of the owner's allowlisted tailnet devices, and to get a short-lived signed claim it can turn into its own session. The issuer can only be reached over the tailnet, so the public page has to make the visitor's browser talk to a `*.ts.net` origin and carry the answer back.

Facts measured on a real tailnet (Tailscale 1.102.4) fixed most of the design.

- `tailscale serve` in front of a loopback backend replaces any client-sent `X-Forwarded-For` with exactly one value, the peer's tailnet IP, and replaces `Tailscale-User-Login` with the real login. It sends no node name or node ID.
- `tailscale whois --json <ip>` returns the node's stable ID, names and tags, and the user's login. Tagged nodes report the login `tagged-devices` and get no `Tailscale-User-*` headers. The CLI works with both the macOS app and Linux; the LocalAPI socket does not exist under the macOS app.
- Chrome 155 and Firefox 157 gate a cross-origin fetch from a public page to a 100.64.0.0/10 address behind a Local Network Access permission. WebKit does not. A top-level navigation is never gated.
- Off the tailnet, public DNS has no answer for `*.ts.net` machine names, so the fetch fails before any permission prompt.
- Python's standard library has HMAC but no Ed25519, and the Python verifier must be standard library only.

## How the design was chosen

Two runners designed it independently and converged on three things: per-audience HMAC keys, identity from `X-Forwarded-For` plus `whois` with a login cross-check, and a silent fetch with a top-level navigation as the fallback.

The base is the second candidate, because it gives the consumer less to learn: one `Verifier.verify`, one snippet `mount`, and a stateless issuer. Its replay check in the verifier is what the requirements asked for.

From the first candidate it takes three things.

- The status page at `/`, so the owner can see what the issuer sees for a device and copy the stable ID to allowlist it.
- A refusal for Funnel traffic, as a structural guard in case someone turns Funnel on by mistake.
- The measured decision about unix sockets. Serve answered 502 for a unix socket target under the macOS app, so loopback TCP is the default and the unix socket is offered with that caveat.

It rejects the first candidate's `Gate.handle` consumer, which owns fixed routes, and its consumer nonce bound to a cookie. That binding is stronger and needs no server state, but it forces every consumer onto fixed routes and a 303 callback with the token in the URL. The issuer's nonce plus the consumer's replay store is enough, because only an allowlisted device can mint a token, and that device is already trusted.

It drops the second candidate's SQLite replay store and multi-key rotation, because neither has earned its place yet. The `ReplayStore` protocol stays, with one in-memory implementation, and the README shows what a shared store needs.

## Signing

Tokens are HMAC-SHA256 under a key derived per audience, `K_aud = HMAC-SHA256(master, "tailisman/v1/aud:" + origin)`. The Python verifier must be standard library only, and Python has no standard library Ed25519. A consumer's key can forge tokens only for that consumer, which already controls its own sessions, so asymmetric signing would buy nothing here.

The MAC covers the ASCII bytes `tsm1.<payload-b64>`, so neither side canonicalises JSON. The verifier decodes the payload only after the MAC matches. Base64url is strict and canonical in both languages, and the payload must have exactly seven keys with integer times, so a payload that one verifier accepts the other accepts too. `testdata/vectors.json` pins this, including origin normalisation, and both test suites run it.

## Identity

`decide()` in `src/tailisman/issuer/decision.py` is the only place that refuses. It checks, in order, that `Host` (and `X-Forwarded-Host`, when present) is the issuer's own serve name, which stops a DNS-rebinding page that reaches the loopback listener with forged headers, that the request came through serve (`X-Forwarded-Proto: https` and exactly one `X-Forwarded-For`), that it is not Funnel traffic, that the origin is a configured audience, that `whois` knows the peer, that the node is not tagged, that serve's login header matches `whois`, that the device is on the audience's allowlist, that the user is allowed, and the automation policy. The status page calls the same function for each audience, so it cannot disagree with what `/v1/claim` would do.

The `audiences` table, keyed by normalised origin, is the CORS allowlist, the `return_to` allowlist and the key list. An origin cannot be configured for one and not the others.

## What was measured while building

- Chrome fails a fetch whose `targetAddressSpace` does not match where it places the target. Declaring `local` for an issuer on 127.0.0.1 failed with "Request had a target IP address space of `local` yet the resource is in address space `loopback`". The snippet defaults to `local`, which is where Chrome places tailnet addresses, and takes `targetAddressSpace` as an option for local test setups.
- Node strips TypeScript types only outside `node_modules`. The Node package works through a linked install and fails with `ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING` when copied into `node_modules`.
- With a stand-in for serve on loopback, the navigation path signed in under Playwright's Chromium 156, WebKit 27.2 and Firefox 157, and the silent path did too once the address space matched. These runs do not exercise Local Network Access, which needs the live tailnet.

- Under launchd, the macOS app binary started straight from Python prints "The Tailscale GUI failed to start" with exit status 0 instead of answering `whois`, so every claim was refused as `unknown_peer`. It answers as the CLI once `SHLVL` or `TERM` is in its environment, so the issuer sets `SHLVL` when the environment has neither.

## The gate

The gate is a consumer like any other, built for sites that should not change. It holds one verifier per gated origin and turns a claim into its own cookie, and it adds a backup password for browsers the issuer cannot reach. Behind Caddy it answers `forward_auth`. Behind a Cloudflare Tunnel, which terminates TLS but cannot ask anyone before it hands a request on, it is the reverse proxy itself, so a site that publishes through a tunnel needs no Caddy. Both modes build the same request shape and ask the same `decide()`, so they cannot disagree about who gets in. Its cookie needs no server state: the owner's MAC key mixes the password hash into the session secret, so changing the password ends every owner session, and each guest's key mixes in that guest's digest, so revoking one guest ends only theirs. A guest cookie can share a parent domain with the owner's, so the gate checks the guest's site list on every request rather than trusting the cookie's scope. `docs/GATE.md` covers the rest.

## What it does not do

No JWT, no key IDs, no refresh, no issuer-side sessions, no whois cache, no Funnel support, and no device enrolment flow. Only the gate mints cookies; a consumer of the verifier owns its own session format.
