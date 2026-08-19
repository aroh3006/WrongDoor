"""Async Executor (§5.9): replay the planned matrix, capture what came back.

Sends each PlannedRequest as its acting identity's client, concurrently but
bounded by a semaphore so WrongDoor can't accidentally hammer the target. Returns
(request, response) pairs: that pairing is the evidence a finding is built from.

Lower-risk than the rest of the engine: it is I/O plumbing, not a security
decision point. It only records the status and (size-capped) body for the
verdict engine to judge.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from ..identity.base import AuthedClient
from .planner import PlannedRequest

_DEFAULT_CONCURRENCY = 10
_MAX_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class ObservedResponse:
    status: int  # 0 means the request never completed (network error/timeout)
    body: Any  # parsed JSON (dict/list), capped text, or None


async def execute(
    planned: list[PlannedRequest],
    registry: dict[str, AuthedClient],
    *,
    concurrency: int = _DEFAULT_CONCURRENCY,
) -> list[tuple[PlannedRequest, ObservedResponse]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run_one(req: PlannedRequest) -> tuple[PlannedRequest, ObservedResponse]:
        client = registry[req.acting_identity].client
        async with semaphore:  # cap concurrent in-flight requests (§5.9)
            try:
                resp = await client.request(req.method, req.path)
            except httpx.HTTPError as e:
                return req, ObservedResponse(status=0, body={"error": str(e)})
        return req, _observe(resp)

    # gather preserves order, so results line up with `planned`.
    return await asyncio.gather(*(run_one(r) for r in planned))


def _observe(resp: httpx.Response) -> ObservedResponse:
    return ObservedResponse(status=resp.status_code, body=_capture_body(resp))


def _capture_body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        text = resp.content[:_MAX_BODY_BYTES].decode("utf-8", "replace")
        return text or None
