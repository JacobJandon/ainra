# SPDX-License-Identifier: Apache-2.0 OR MIT
"""A standalone origin running the Python gate (`ainra.AinraGate`), the sibling of tools/gate-origin.mjs (D-072).

    PYTHONPATH=packages/sdk-py python3 tools/gate-origin.py

Same contract as the Node origin: trust from the published directory and roots (AINRA_ARTIFACTS), 127.0.0.1 at PORT
(default: any free port), `LISTENING <port>` on stdout when ready; send-once and signed requests required; an allowed
request answers 200 `{"ok":true,"as":"<credential name>"}`, a refused one the gate's own status and `x-ainra-reason`.

The gate is ASGI and the standard library has no ASGI server, so this file carries the smallest HTTP/1.1 host that can
put one behind a socket: one request per connection, a Content-Length body, 16 KiB of headers at most (Node's
default, so the three origins refuse the same oversized requests). It exists so the gate can be exercised over real
sockets by real agents. It is not a server to deploy — put the gate in the ASGI server you already run.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.request

from ainra import AinraGate, PresentationStore, Verifier

ART = os.environ.get("AINRA_ARTIFACTS", "http://127.0.0.1:8091")
AUD = os.environ.get("AINRA_AUDIENCE", "https://shop.example")
MAX_HEADER_BYTES = 16 * 1024


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


try:
    directory, roots = _get(f"{ART}/directory.json"), _get(f"{ART}/roots.json")
except OSError:
    print(f"gate-origin: no published directory at {ART} — run `make stage-up` first", file=sys.stderr)
    sys.exit(2)
# The default freshness class, F2 — the same policy the Node and edge origins run.
verifier = Verifier.from_directory(directory, roots["root_ed25519"], roots["root_slh"], audience=AUD)
if verifier is None:
    print("gate-origin: the published directory does not verify against the roots", file=sys.stderr)
    sys.exit(1)

_seen: set[str] = set()


def seen_nonce(nonce: str) -> bool:
    had = nonce in _seen
    _seen.add(nonce)
    return had


async def app(scope, receive, send):
    body = json.dumps({"ok": True, "as": scope["ainra"]["event"]["name"]}).encode("utf-8")
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


gate = AinraGate(app, verifier, require_signature=True, seen_nonce=seen_nonce, store=PresentationStore())


async def _answer(writer, status: int, headers, body: bytes) -> None:
    out = [f"HTTP/1.1 {status} \r\n".encode("latin1")]
    out += [k + b": " + v + b"\r\n" for k, v in headers]
    out.append(f"content-length: {len(body)}\r\nconnection: close\r\n\r\n".encode("latin1"))
    writer.write(b"".join(out) + body)
    await writer.drain()


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            await _answer(writer, 431, [], b"")
            return
        lines = head.decode("latin1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = []
        for line in lines[1:]:
            if line:
                name, _, value = line.partition(":")
                headers.append((name.strip().lower().encode("latin1"), value.strip().encode("latin1")))
        length = int(dict(headers).get(b"content-length", b"0"))
        body = await reader.readexactly(length) if length else b""
        path, _, query = target.partition("?")
        scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode("latin1"),
                 "query_string": query.encode("latin1"), "headers": headers}
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        response = {"status": 500, "headers": [], "body": b""}

        async def send(message):
            if message["type"] == "http.response.start":
                response["status"], response["headers"] = message["status"], list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                response["body"] += message.get("body", b"")

        await gate(scope, receive, send)
        await _answer(writer, response["status"], response["headers"], response["body"])
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle, "127.0.0.1", int(os.environ.get("PORT", "0")), limit=MAX_HEADER_BYTES)
    print(f"LISTENING {server.sockets[0].getsockname()[1]}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
