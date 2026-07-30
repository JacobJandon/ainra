# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Framework-agnostic ASGI gate (mirrors the TypeScript ``ainraGate``).

Wrap any ASGI app (Starlette, FastAPI, Quart, …). Every gated request must carry
a valid AINRA passport or it is denied **403, fail closed** — the absence of a
passport is a deny, and any structural break is a deny, never a pass. On allow,
the request flows through and the response carries the M16 verdict event in
``x-ainra-verdict``; on deny, the 403 carries ``x-ainra-reason`` (the frozen
reason) and ``x-ainra-verdict``.

The bundle is read from the ``x-ainra-passport`` header (base64url of canonical
JSON, or raw JSON for local testing); if absent, from the JSON request body field
``ainra_passport``. Verification never needs the body, so the header form is
streaming-safe. No telemetry.
"""

from __future__ import annotations

import json
import time

from ._b64 import decode as b64d
from .verdict import Verdict
from .verifier import Verifier

HEADER = "x-ainra-passport"
BODY_FIELD = "ainra_passport"


def parse_bundle(value) -> dict | None:
    """Decode a presentation bundle: base64url(canonical JSON) or raw JSON."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, (str, bytes)):
        return None
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None
    raw = b64d(value)
    if raw is not None:
        try:
            obj = json.loads(raw.decode("utf-8"))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    try:
        obj = json.loads(value)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


class AinraGate:
    """ASGI3 middleware that denies any request without a VALID passport."""

    def __init__(self, app, verifier: Verifier, now=None) -> None:
        self.app = app
        self.verifier = verifier
        # `now` may be an int (fixed clock, e.g. for tests) or a zero-arg callable.
        if now is None:
            self._now = lambda: int(time.time())
        elif callable(now):
            self._now = now
        else:
            self._now = lambda: int(now)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        bundle = None
        raw_header = headers.get(HEADER)
        if raw_header is not None:
            bundle = parse_bundle(raw_header)

        if bundle is None:
            # Fall back to the JSON body field, buffering + replaying the body.
            body, receive = await _buffer_body(receive)
            if body:
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict) and BODY_FIELD in parsed:
                        bundle = parse_bundle(parsed[BODY_FIELD])
                except Exception:
                    bundle = None

        if bundle is None:
            verdict = Verdict(False, "schema_violation")
        else:
            verdict = self.verifier.verify(bundle, self._now())

        event_header = json.dumps(verdict.event(), separators=(",", ":")).encode("latin1")

        if not verdict.valid:
            await _deny(send, verdict.reason or "schema_violation", event_header)
            return

        scope = dict(scope)
        scope["ainra"] = {"event": verdict.event()}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-ainra-verdict", event_header)
                ]
            await send(message)

        await self.app(scope, receive, send_wrapper)


async def _buffer_body(receive):
    """Consume the request body, returning (bytes, a replaying receive)."""
    chunks = []
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.request":
            chunks.append(message.get("body", b"") or b"")
            more = message.get("more_body", False)
        elif message["type"] == "http.disconnect":
            more = False
        else:
            more = False
    body = b"".join(chunks)
    delivered = False

    async def replay():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return body, replay


async def _deny(send, reason: str, event_header: bytes) -> None:
    body = json.dumps({"error": "forbidden", "reason": reason}, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"x-ainra-reason", reason.encode("latin1")),
                (b"x-ainra-verdict", event_header),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# Convenience alias mirroring the TS export name.
def ainra_gate(verifier: Verifier, now=None):
    """Return an ASGI middleware factory: ``app -> AinraGate(app, verifier)``."""
    def factory(app):
        return AinraGate(app, verifier, now=now)

    return factory
