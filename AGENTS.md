# Agent notes

## If the user asked you to lock, secure, or make private their pages

Follow [skills/tailisman/SKILL.md](skills/tailisman/SKILL.md) from step 1. Everything else in this file is for changing tailisman itself.

## If the user asked you to share a page, or give someone a password

Follow [Share a page with someone](skills/tailisman/SKILL.md#share-a-page-with-someone), which `tailisman guide share` also prints. In short: `tailisman share <url> --to <name> --json`, a folder when the URL ends in `/`, else that exact link. Never print the passphrase; report its file path.

## If you are changing tailisman

Run the tests before you commit.

```sh
uv run --with pytest pytest                                  # Python verifier, issuer, gate, CLI, demo
node --test js/                                              # Node verifier and the snippet (Node 22.18 or later)
uv run python e2e/gate_e2e.py                                # the gate behind a real Caddy (needs caddy on PATH)
uv run python e2e/gate_proxy_e2e.py                          # proxy mode: streaming, uploads, Range, websockets, guests
uv run --with playwright python e2e/gate_browser_check.py    # the gate in Playwright Chromium
uv run python scripts/make_vectors.py                        # after a token format change; a test fails if vectors are stale
```

- The Python package uses the standard library only. `dependencies = []` in `pyproject.toml` stays empty, and the Node package imports only `node:` modules.
- This repository is public. Use `example.com`, `example-tailnet`, `nEXAMPLE...CNTRL`, and `owner@example.com` in code, tests, docs, and commit messages. Never write a real domain, tailnet name, device name, stable ID, login, or host name.
- A command or flag in the docs must match `src/tailisman/cli.py`, `src/tailisman/issuer/cli.py`, and `src/tailisman/gate/cli.py`. Check with `uv run tailisman <command> --help`.
