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
from .presentation import (
    POP_HEADER, PRIME_PATH, is_presentation_ref, join_presentation, presentation_ref, split_presentation,
    verify_presentation,
)
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


class PresentationStore:
    """Bundles sent once to ``PRIME_PATH`` (D-065) — bounded, idlest-first eviction, nothing outlives its expiry.
    Only bundles that verified when they arrived are stored, and every request re-verifies what it names."""

    def __init__(self, max_entries: int = 1024) -> None:
        self._max = max(1, int(max_entries))
        self._m: dict[str, tuple[dict, int]] = {}

    def get(self, ref: str, now: int):
        e = self._m.pop(ref, None)
        if e is None:
            return None
        if now >= e[1]:
            return None
        self._m[ref] = e          # most recently used last
        return e[0]

    def put(self, ref: str, stable: dict, expires: int) -> None:
        self._m.pop(ref, None)
        self._m[ref] = (stable, int(expires))
        while len(self._m) > self._max:
            self._m.pop(next(iter(self._m)))


def check_binding(scope, body: bytes, bundle: dict, now: int, seen=None) -> str | None:
    """D-062: is THIS request bound to the presentation? ``None`` if so, else the presentation reason.

    The signed-over view of an ASGI request: the method, the Host the client addressed, the path WITH its query as
    sent (``raw_path`` when the server provides it), every header, and the raw body. The instance credential's id and
    key come from the (already verified) bundle.
    """
    inst = bundle.get("instance")
    if not isinstance(inst, dict):
        return "presentation_unsigned"
    headers = [(k.decode("latin1").lower(), v.decode("latin1")) for k, v in scope.get("headers", [])]
    host = next((v for k, v in headers if k == "host"), "")
    raw = scope.get("raw_path")
    path = raw.decode("latin1") if isinstance(raw, (bytes, bytearray)) and raw else scope.get("path", "/")
    qs = scope.get("query_string", b"")
    if qs:
        path += "?" + (qs.decode("latin1") if isinstance(qs, (bytes, bytearray)) else str(qs))
    ik = inst.get("ikey") if isinstance(inst.get("ikey"), dict) else {}
    ed, ml = b64d(ik.get("ed25519")), b64d(ik.get("mldsa65"))
    if ed is None or ml is None or not isinstance(inst.get("iid"), str):
        return "presentation_sig_invalid"
    r = verify_presentation(method=scope.get("method", "GET"), authority=host, path=path, headers=headers,
                            body=body or None, iid=inst["iid"], ikey_ed25519=ed, ikey_mldsa65=ml, now=now, seen=seen)
    return None if r["ok"] else r["reason"]


class AinraGate:
    """ASGI3 middleware that denies any request without a VALID passport.

    Options (all off by default, so existing integrations behave exactly as before):
      * ``require_signature`` — the REQUEST must be signed by the running copy's instance key (RFC 9421, D-062).
      * ``seen_nonce`` — ``callable(nonce) -> bool``; closes the replay window completely. Asked only after the
        signature verified.
      * ``store`` — a :class:`PresentationStore`; enables send-once (D-065): ``POST PRIME_PATH`` stores a verified
        bundle and answers ``201 {"ref"}``; a request naming an unknown ref is ``428 presentation_unknown``.
    """

    def __init__(self, app, verifier: Verifier, now=None, *, require_signature: bool = False, seen_nonce=None,
                 store: PresentationStore | None = None, prime_path: str = PRIME_PATH) -> None:
        self.app = app
        self.verifier = verifier
        self.require_signature = bool(require_signature)
        self.seen_nonce = seen_nonce
        self.store = store
        self.prime_path = prime_path
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
        now = self._now()
        body = b""

        # ── send once (D-065): verify in full, keep the stable part, answer with its digest ─────────────────────
        if self.store is not None and scope.get("method") == "POST" and scope.get("path") == self.prime_path:
            body, receive = await _buffer_body(receive)
            try:
                bundle = json.loads(body) if body else None
            except Exception:
                bundle = None
            if not isinstance(bundle, dict):
                await _deny(send, "schema_violation", b"{}")
                return
            verdict = self.verifier.verify(bundle, now)
            if not verdict.valid:
                await _deny(send, verdict.reason or "schema_violation",
                            json.dumps(verdict.event(), separators=(",", ":")).encode("latin1"))
                return
            stable, _ = split_presentation(bundle)
            inst = bundle.get("instance")
            expires = inst["exp"] if isinstance(inst, dict) and isinstance(inst.get("exp"), int) else now + 300
            ref = presentation_ref(bundle)
            self.store.put(ref, stable, expires)
            await _respond(send, 201, {"ref": ref, "expires": expires}, [])
            return

        bundle = None
        raw_header = headers.get(HEADER)
        if raw_header is not None and is_presentation_ref(raw_header):
            stable = self.store.get(raw_header.strip(), now) if self.store is not None else None
            if stable is None:
                await _respond(send, 428, {"error": "send the presentation first", "reason": "presentation_unknown",
                                           "prime": self.prime_path},
                               [(b"x-ainra-reason", b"presentation_unknown"),
                                (b"link", f'<{self.prime_path}>; rel="ainra-prime"'.encode("latin1"))])
                return
            pop = parse_bundle(headers[POP_HEADER]) if POP_HEADER in headers else None
            bundle = join_presentation(stable, pop)
        elif raw_header is not None:
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
            verdict = self.verifier.verify(bundle, now)

        event_header = json.dumps(verdict.event(), separators=(",", ":")).encode("latin1")

        if not verdict.valid:
            await _deny(send, verdict.reason or "schema_violation", event_header)
            return

        # The credential is good; bind it to THIS request before anything else sees it (D-062).
        if self.require_signature:
            if not body:
                body, receive = await _buffer_body(receive)
            reason = check_binding(scope, body, bundle, now, self.seen_nonce)
            if reason is not None:
                await _deny(send, reason, event_header)
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


async def _respond(send, status: int, payload: dict, extra_headers) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), *extra_headers]})
    await send({"type": "http.response.body", "body": body})


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
def ainra_gate(verifier: Verifier, now=None, **options):
    """Return an ASGI middleware factory: ``app -> AinraGate(app, verifier, **options)``."""
    def factory(app):
        return AinraGate(app, verifier, now=now, **options)

    return factory
