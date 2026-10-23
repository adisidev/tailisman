"""A stand-in for `tailscale serve` for local browser runs: forwards to the issuer and sets the headers serve would.

    uv run python e2e/fake_serve.py --listen 127.0.0.1:8443 --backend 127.0.0.1:8470 --peer 100.64.0.1 --login owner@example.com

Like serve, it drops any client-sent X-Forwarded-* and Tailscale-* headers. It speaks plain HTTP, so it only
stands in for serve on loopback; it is not a security boundary.
"""

from __future__ import annotations

import argparse
import http.client
import http.server

DROP = ("x-forwarded-", "tailscale-")
HOP = {"connection", "keep-alive", "transfer-encoding", "host", "content-length"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:8443")
    parser.add_argument("--backend", default="127.0.0.1:8470")
    parser.add_argument("--peer", default="100.64.0.1", help="the tailnet IP to report in X-Forwarded-For")
    parser.add_argument("--login", default="owner@example.com", help="Tailscale-User-Login to send; empty for a tagged node")
    args = parser.parse_args()
    backend_host, backend_port = args.backend.rsplit(":", 1)

    class Proxy(http.server.BaseHTTPRequestHandler):
        def _forward(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            headers = {k: v for k, v in self.headers.items() if not k.lower().startswith(DROP) and k.lower() not in HOP}
            headers.update({"X-Forwarded-For": args.peer, "X-Forwarded-Proto": "https", "X-Forwarded-Host": self.headers.get("Host", "")})
            if args.login:
                headers["Tailscale-User-Login"] = args.login
            conn = http.client.HTTPConnection(backend_host, int(backend_port), timeout=30)
            conn.request(self.command, self.path, body=body or None, headers=headers)
            response = conn.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in HOP:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_OPTIONS = _forward

    host, port = args.listen.rsplit(":", 1)
    http.server.ThreadingHTTPServer((host, int(port)), Proxy).serve_forever()


if __name__ == "__main__":
    main()
