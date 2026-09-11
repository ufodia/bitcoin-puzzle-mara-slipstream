#!/usr/bin/env python3
"""Loopback-only mock of the narrow MARA submission contract used for tests."""

from __future__ import annotations

import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 18765
PATH = "/v1/transaction/submit"
MAX_BODY = 2_000_000


class Handler(BaseHTTPRequestHandler):
    server_version = "PuzzleSlipstreamMock/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        # Deliberately do not log request bodies or transaction hex.
        print(f"{self.address_string()} - {fmt % args}")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != PATH:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 1 <= length <= MAX_BODY:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            tx_hex = payload["tx_hex"]
            if not isinstance(tx_hex, str) or len(tx_hex) % 2 or any(c not in "0123456789abcdefABCDEF" for c in tx_hex):
                raise ValueError("invalid tx_hex")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            self.send_error(400)
            return

        reference = hashlib.sha256(bytes.fromhex(tx_hex)).hexdigest()[:24]
        response = json.dumps({
            "accepted": True,
            "status": "mock_accepted_not_confirmed",
            "reference": reference,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


if __name__ == "__main__":
    print(f"Mock Slipstream listening only on http://{HOST}:{PORT}{PATH}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
