"""Generate examples/har/demo.har: a small, realistic HAR capture of the demo
API's resource traffic, used as WrongDoor's HAR-import fixture.

We drive the demo in-process (ASGI, no running server), authenticate for real so
the captured requests return 2xx, and record ONLY resource traffic
(invoices/documents) plus a bit of static noise. Auth is out of scope for HAR
import, so:

  * login requests are NOT recorded (the HAR is resource traffic, not auth), and
  * every recorded ``Authorization`` header is scrubbed to a placeholder before
    writing, so the committed fixture contains no token, cookie, or password.

Regenerate with:  python examples/har/capture_demo.py
"""

import asyncio
import json
import sys
from pathlib import Path

import httpx

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "vulnerable-api"))
from app import app  # noqa: E402  (import after sys.path tweak)

_BASE = "http://127.0.0.1:8000"  # a plausible captured origin
_SCRUBBED = "Bearer REDACTED"  # what recorded Authorization headers are replaced with
_OUT = _HERE / "demo.har"


def _entry(method: str, path: str, *, body=None, status: int, resp) -> dict:
    """One HAR 1.2 entry. Authorization is written scrubbed, never the real token."""
    req_headers = [{"name": "Authorization", "value": _SCRUBBED}]
    request = {
        "method": method,
        "url": _BASE + path,
        "httpVersion": "HTTP/1.1",
        "headers": req_headers,
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": -1,
    }
    if body is not None:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps(body)}
    response = {
        "status": status,
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "headers": [{"name": "content-type", "value": "application/json"}],
        "cookies": [],
        "content": {"size": -1, "mimeType": "application/json", "text": json.dumps(resp)},
        "headersSize": -1,
        "bodySize": -1,
        "redirectURL": "",
    }
    return {
        "startedDateTime": "2026-01-01T00:00:00.000Z",
        "time": 0,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }


async def _capture() -> list[dict]:
    entries: list[dict] = []
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_BASE) as c:
        for user, pw in (("alice", "alice-pw"), ("bob", "bob-pw")):
            # Authenticate for real so the resource calls return 2xx. This login
            # is NOT recorded into the HAR (auth is out of scope for import).
            tok = (await c.post("/login", json={"username": user, "password": pw})).json()["access_token"]
            auth = {"Authorization": f"Bearer {tok}"}

            inv_body = {"amount": 100.0, "memo": f"{user}-memo"}
            inv = (await c.post("/invoices", json=inv_body, headers=auth)).json()
            entries.append(_entry("POST", "/invoices", body=inv_body, status=201, resp=inv))
            got = await c.get(f"/invoices/{inv['id']}", headers=auth)
            entries.append(_entry("GET", f"/invoices/{inv['id']}", status=got.status_code, resp=got.json()))

            doc_body = {"title": f"{user}-doc", "body": "hello"}
            doc = (await c.post("/documents", json=doc_body, headers=auth)).json()
            entries.append(_entry("POST", "/documents", body=doc_body, status=201, resp=doc))
            gotd = await c.get(f"/documents/{doc['id']}", headers=auth)
            entries.append(_entry("GET", f"/documents/{doc['id']}", status=gotd.status_code, resp=gotd.json()))

        # A little static noise, to prove the importer's noise filter.
        entries.append(_entry("GET", "/favicon.ico", status=200, resp=None))
    return entries


def main() -> None:
    entries = asyncio.run(_capture())
    har = {"log": {"version": "1.2", "creator": {"name": "wrongdoor-capture-demo", "version": "1"}, "entries": entries}}
    _OUT.write_text(json.dumps(har, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(entries)} entries to {_OUT}")


if __name__ == "__main__":
    main()
