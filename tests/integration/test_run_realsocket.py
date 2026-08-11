"""Real-socket golden variant (the Phase 4 fold-in): run the full pipeline against
the vulnerable demo served by uvicorn over an actual TCP port, transport=None.

This complements the in-process ASGI golden test — it exercises real HTTP,
real auth round-trips, and the real network path the tool uses in production.
A full Docker/Testcontainers variant can layer on top once the demo image
(examples/vulnerable-api/Dockerfile) is used in CI.
"""

import asyncio
import socket
import threading
import time
from collections import Counter
from pathlib import Path

import uvicorn

from app import app as vulnerable_app

from wrongdoor.cli import _run_pipeline
from wrongdoor.config.schema import Config
from wrongdoor.engine.verdict import findings
from wrongdoor.safety.guard import SafetyGuard
from wrongdoor.spec.openapi import load_operations

_VULN = Path(__file__).resolve().parents[2] / "examples" / "vulnerable-api"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_run_over_a_real_socket(monkeypatch):
    monkeypatch.setenv("ALICE_PW", "alice-pw")
    monkeypatch.setenv("BOB_PW", "bob-pw")

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(vulnerable_app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "uvicorn did not start"

        cfg = Config.model_validate(
            {
                "target": {"base_url": f"http://127.0.0.1:{port}", "allow": ["127.0.0.1"]},
                "identities": [
                    {"id": "alice", "attributes": {"tenant": "A"}, "auth": {"type": "login", "url": "/login", "username": "alice", "password_env": "ALICE_PW"}},
                    {"id": "bob", "attributes": {"tenant": "B"}, "auth": {"type": "login", "url": "/login", "username": "bob", "password_env": "BOB_PW"}},
                ],
                "resources": {"invoices": {"sensitivity": "high"}},
            }
        )
        ops = load_operations(_VULN / "openapi.yaml")
        guard = SafetyGuard(allow=cfg.target.allow, confirm_own_target=True)

        judgments = asyncio.run(_run_pipeline(cfg, ops, guard))  # transport=None -> real TCP
        fs = findings(judgments)
        assert len(fs) == 6  # 4 BOLA (invoices + notes) + 2 MISSING_AUTH (notes)
        assert Counter(f.request.check for f in fs) == {"bola": 4, "unauth": 2}
    finally:
        server.should_exit = True
        thread.join(timeout=5)
