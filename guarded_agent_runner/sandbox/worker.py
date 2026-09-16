from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HealthHandler(BaseHTTPRequestHandler):
    healthy = False
    generation = 0

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_error(404)
            return

        payload = json.dumps(
            {
                "status": "healthy" if self.healthy else "unhealthy",
                "pid": os.getpid(),
                "generation": self.generation,
            }
        ).encode("utf-8")
        self.send_response(200 if self.healthy else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:
        del format, args


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--healthy", action="store_true")
    args = parser.parse_args()

    HealthHandler.healthy = args.healthy
    HealthHandler.generation = args.generation
    print(
        json.dumps(
            {
                "event": "worker_started",
                "pid": os.getpid(),
                "generation": args.generation,
                "status": "healthy" if args.healthy else "unhealthy",
            }
        ),
        flush=True,
    )
    ThreadingHTTPServer(("127.0.0.1", args.port), HealthHandler).serve_forever()


if __name__ == "__main__":
    main()

