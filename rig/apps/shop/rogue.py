# What an attacker drops into a compromised container. Two tells, both visible to eBPF:
#   1. it opens an unplanned HTTP port (4444)  -> shows up in OBI network flows
#   2. it burns CPU in a mining loop in the background -> shows up in the profiler, under this PID
# The mining loop is deliberately pure-Python so the hot path has a readable name in the flamegraph.
import os, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

_ROUNDS = 0


def grind_nonce(seed: int) -> int:
    # A proof-of-work style hash grind. No real coin; just a CPU-bound hot path with an obvious name.
    h = seed & 0xFFFFFFFF
    for _ in range(500_000):
        h = (h * 1103515245 + 12345) & 0xFFFFFFFF
        h ^= (h >> 16)
    return h


def mine_forever():
    global _ROUNDS
    nonce = 0
    while True:
        grind_nonce(nonce)
        nonce += 1
        _ROUNDS += 1


class Implant(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"rounds={_ROUNDS}".encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    for _ in range(int(os.environ.get("MINER_THREADS", "1"))):
        threading.Thread(target=mine_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "4444"))), Implant).serve_forever()
