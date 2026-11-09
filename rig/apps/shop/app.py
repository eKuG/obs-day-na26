# The legitimate service: a small shop API on 8080. CPU work so the profiler has Python frames to show.
import json, os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)


def price_cart(path):
    return fib(20 + len(path) % 3) % 97


class Shop(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "total": price_cart(self.path)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Shop).serve_forever()
