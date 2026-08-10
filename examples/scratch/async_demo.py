"""
Phase 0 scratch: the async concurrency pattern WrongDoor's executor depends on.

This is a THROWAWAY learning script, not part of the tool. It demonstrates the
exact shape §5.9 (Async Executor) will use for real:

    httpx.AsyncClient  +  asyncio.gather  +  asyncio.Semaphore(limit)

We fire REQUEST_COUNT independent GETs two ways and time them:
  1. Sequentially  -- await one request at a time (the slow baseline).
  2. Concurrently  -- many in flight at once, capped by a semaphore.

To keep it self-contained and reproducible (no external host, no flakiness),
we run a tiny local HTTP server in a background thread that sleeps LATENCY_S
per request to simulate real network latency. The only third-party import is
httpx, which is already a WrongDoor dependency.

Run it:  python examples/scratch/async_demo.py
"""

import asyncio
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import httpx

# --- knobs you can tweak and re-run ---------------------------------------
REQUEST_COUNT = 50      # how many GETs to fire
CONCURRENCY_LIMIT = 10  # max requests in flight at once (the semaphore cap)
LATENCY_S = 0.1         # simulated per-request server latency (100 ms)


# --- a tiny local target so we don't hit anyone else's server -------------
class _SleepyHandler(BaseHTTPRequestHandler):
    """Responds 200 with a tiny JSON body after sleeping LATENCY_S.

    The sleep stands in for network + server processing time -- it is what
    makes the difference between sequential and concurrent visible.
    """

    def do_GET(self):
        time.sleep(LATENCY_S)                     # pretend the backend is slow
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):                 # silence per-request logging
        pass


def _start_server() -> tuple[ThreadingHTTPServer, str]:
    """Start the sleepy server on a free port in a daemon thread.

    ThreadingHTTPServer handles each request in its own thread, so it can
    actually serve CONCURRENCY_LIMIT requests at the same time -- a
    single-threaded server would serialize them and hide the async win.
    Binding to port 0 lets the OS pick a free port.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SleepyHandler)
    port = server.server_address[1]
    Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{port}/"


# --- the two strategies ----------------------------------------------------
async def run_sequential(base_url: str) -> list[int]:
    """Baseline: await each request one at a time. Total time ~= N * latency."""
    async with httpx.AsyncClient() as client:
        statuses = []
        for _ in range(REQUEST_COUNT):
            resp = await client.get(base_url)     # nothing else runs until this returns
            statuses.append(resp.status_code)
        return statuses


async def run_concurrent(base_url: str) -> list[int]:
    """Concurrent: many requests in flight, capped by a semaphore.

    asyncio.gather schedules all the coroutines together; the semaphore ensures
    no more than CONCURRENCY_LIMIT are actually in flight at once. That cap is
    exactly how the real executor avoids hammering (DoS-ing) a target.
    Total time ~= ceil(N / limit) * latency.
    """
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async with httpx.AsyncClient() as client:
        async def one_request() -> int:
            async with semaphore:                 # wait for a free slot, then go
                resp = await client.get(base_url)
                return resp.status_code

        # build all the coroutines, then run them concurrently and wait for all
        tasks = [one_request() for _ in range(REQUEST_COUNT)]
        return await asyncio.gather(*tasks)


async def _timed(label: str, coro) -> float:
    start = time.perf_counter()
    statuses = await coro
    elapsed = time.perf_counter() - start
    assert len(statuses) == REQUEST_COUNT, f"{label}: expected {REQUEST_COUNT} responses"
    assert all(s == 200 for s in statuses), f"{label}: not every response was 200"
    print(f"  {label:<12} {REQUEST_COUNT} requests in {elapsed:6.3f}s")
    return elapsed


async def main() -> None:
    server, base_url = _start_server()
    try:
        print(
            f"\nFiring {REQUEST_COUNT} GETs at {base_url} "
            f"({LATENCY_S * 1000:.0f}ms latency each, concurrency cap {CONCURRENCY_LIMIT})\n"
        )
        seq = await _timed("sequential", run_sequential(base_url))
        con = await _timed("concurrent", run_concurrent(base_url))
        print(f"\n  speedup: {seq / con:.1f}x faster with the semaphore-bounded gather\n")
    finally:
        server.shutdown()                         # stop the background server
        server.server_close()


if __name__ == "__main__":
    asyncio.run(main())
