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
      * ``decisions`` — a :class:`ainra.decision.DecisionLog`; every decision about a named passport is recorded,
        signed and chained (D-079). The operator is recorded only on a valid decision; recording never changes the
        decision.
    """

    def __init__(self, app, verifier: Verifier, now=None, *, require_signature: bool = False, seen_nonce=None,
                 store: PresentationStore | None = None, prime_path: str = PRIME_PATH, decisions=None) -> None:
        self.app = app
        self.verifier = verifier
        self.require_signature = bool(require_signature)
        self.seen_nonce = seen_nonce
        self.store = store
        self.prime_path = prime_path
        self.decisions = decisions
        # `now` may be an int (fixed clock, e.g. for tests) or a zero-arg callable.
        if now is None:
            self._now = lambda: int(time.time())
        elif callable(now):
            self._now = now
        else:
            self._now = lambda: int(now)

    def _record(self, scope, headers, bundle, verdict, reason, now) -> None:
        _record_decision(self.decisions, scope, headers, bundle, verdict, reason, now)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # A field sent on several lines is ONE field, its lines joined by ", " (RFC 9110 §5.3) — the rule the Node
        # and edge gates get from their HTTP layers. A dict comprehension here kept only the LAST line, so a request
        # with `x-ainra-passport` twice was allowed by this gate and refused by the other two (D-072).
        headers: dict[str, str] = {}
        for k, v in scope.get("headers", []):
            name, value = k.decode("latin1").lower(), v.decode("latin1")
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
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
            self._record(scope, headers, bundle, verdict, verdict.reason or "schema_violation", now)
            await _deny(send, verdict.reason or "schema_violation", event_header)
            return

        # The credential is good; bind it to THIS request before anything else sees it (D-062).
        if self.require_signature:
            if not body:
                body, receive = await _buffer_body(receive)
            reason = check_binding(scope, body, bundle, now, self.seen_nonce)
            if reason is not None:
                self._record(scope, headers, bundle, verdict, reason, now)
                await _deny(send, reason, event_header)
                return

        self._record(scope, headers, bundle, verdict, None, now)

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


def _record_decision(log, scope, headers, bundle, verdict, reason, now) -> None:
    """D-079: write one decision when the request named a passport. Never raises, never changes the decision."""
    if log is None:
        return
    try:
        from .decision import request_digest
        from ._crypto import sha256
        from ._b64 import encode as b64e

        sub = verdict.event().get("name")
        if not isinstance(sub, str) or not sub:
            return
        valid = reason is None and verdict.valid
        path = scope.get("path", "/")
        qs = scope.get("query_string") or b""
        if qs:
            path += "?" + qs.decode("latin1")
        rec = {
            "at": now, "kind": "passport", "subject": sub, "verdict": "valid" if valid else "invalid",
            "request": request_digest(scope.get("method", "GET"), headers.get("host", ""), path,
                                      headers.get("content-digest", "")),
        }
        if valid:
            rec["operator"] = sub.split(":")[2]
        else:
            rec["reason"] = reason or verdict.reason or "schema_violation"
        b = bundle if isinstance(bundle, dict) else {}
        if isinstance(b.get("status_uri"), str) and isinstance(b.get("status_issued_at"), int) \
                and isinstance(b.get("status_list"), str):
            rec["status"] = {"uri": b["status_uri"], "issued_at": b["status_issued_at"],
                             "list": b64e(sha256(b["status_list"].encode("utf-8")))}
        cp = b.get("checkpoint")
        if isinstance(cp, dict) and isinstance(cp.get("origin"), str) and isinstance(cp.get("size"), int) \
                and isinstance(cp.get("root"), str):
            rec["checkpoint"] = {"origin": cp["origin"], "size": cp["size"], "root": cp["root"]}
        log.record(rec)
    except Exception as e:  # a log that cannot be written is the operator's alarm, not the agent's refusal
        import sys
        print(f"ainra: decision not recorded: {e}", file=sys.stderr)


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


class AinraLinkGate:
    """ASGI3 middleware in link mode (D-078): your own signature check verifies the request; AINRA says who stands
    behind the key. Requests whose key is linked to an accountable operator, and not revoked, pass with
    ``scope["ainra_link"]`` set; everything else gets 403 and a named reason, ``not_linked`` included.

    * ``verified_key(scope, headers) -> bytes | None`` — the Ed25519 key that verified THIS request, or None.
    * ``source() -> (index, status)`` — the registrar's link index and signed status publication (GET /links,
      GET /status-list); cache them as you like, inside the verifier's freshness class.
    * ``capability(scope) -> str | None`` — the capability the request exercises, if links may be narrowed.
    * ``decisions`` — a :class:`ainra.decision.DecisionLog`; link decisions are recorded, signed and chained.
    """

    def __init__(self, app, verifier: Verifier, verified_key, source, now=None, *, capability=None,
                 decisions=None) -> None:
        self.app, self.verifier, self.verified_key, self.source = app, verifier, verified_key, source
        self.capability, self.decisions = capability, decisions
        self._now = (lambda: int(time.time())) if now is None else (now if callable(now) else (lambda: int(now)))

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        from .link import link_from_index, presented_key_thumbprint

        headers: dict[str, str] = {}
        for k, v in scope.get("headers", []):
            name, value = k.decode("latin1").lower(), v.decode("latin1")
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
        now = self._now()
        try:
            key = self.verified_key(scope, headers)
        except Exception:
            key = None
        # A key of either Link algorithm (D-082): 32 bytes Ed25519, 33 a compressed secp256k1 point.
        tp = presented_key_thumbprint(bytes(key)) if isinstance(key, (bytes, bytearray)) else None
        if tp is None:
            result = {"verdict": "invalid", "reason": "sig_invalid"}
        else:
            try:
                index, status = self.source()
                link = link_from_index(index, status, tp)
            except Exception:
                link = None
            cap = self.capability(scope) if self.capability else None
            result = self.verifier.verify_link(link, bytes(key), now, cap) if link else \
                {"verdict": "invalid", "reason": "not_linked"}
        if self.decisions is not None and tp is not None:
            try:
                from .decision import request_digest

                path = scope.get("path", "/")
                if scope.get("query_string"):
                    path += "?" + scope["query_string"].decode("latin1")
                rec = {"at": now, "kind": "link", "subject": tp, "verdict": result["verdict"],
                       "request": request_digest(scope.get("method", "GET"), headers.get("host", ""), path,
                                                 headers.get("content-digest", ""))}
                if result["verdict"] == "valid":
                    rec.update(passport=result["passport"], operator=result["operator"])
                else:
                    rec["reason"] = result["reason"]
                self.decisions.record(rec)
            except Exception as e:
                import sys
                print(f"ainra: decision not recorded: {e}", file=sys.stderr)
        if result["verdict"] == "valid":
            scope = dict(scope)
            scope["ainra_link"] = result
            await self.app(scope, receive, send)
            return
        body = json.dumps({"error": "forbidden", "reason": result["reason"]}, separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"),
                                (b"x-ainra-reason", result["reason"].encode("latin1"))]})
        await send({"type": "http.response.body", "body": body})


# Convenience alias mirroring the TS export name.
def ainra_gate(verifier: Verifier, now=None, **options):
    """Return an ASGI middleware factory: ``app -> AinraGate(app, verifier, **options)``."""
    def factory(app):
        return AinraGate(app, verifier, now=now, **options)

    return factory
