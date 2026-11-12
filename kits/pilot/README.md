<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kits/pilot: an AINRA gate in front of any service, in one command

For a design partner's first week. Nothing in their service changes: the pilot sits in front of it, refuses by name
what should not get in, forwards the rest with the operator named, and keeps a signed, hash-chained record of every
decision ([DECISION-RECORDS.md](../../docs/DECISION-RECORDS.md)).

```
node kits/pilot/pilot.mjs --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --directory directory.json --roots roots.json \
  --mode link --registrar https://registrar.example --freshness F1 \
  --decisions decisions.jsonl --gate-key gate.key
```

| Mode | The request arrives with | What the pilot checks |
|---|---|---|
| `link` | a signature-agent signature (the Web Bot Auth profile) | an independent open-source verifier checks the signature against the operator's key directory; [AINRA Link](../../docs/LINKS.md) then says who stands behind the key, from the registrar's index and signed status list, cached inside the freshness class |
| `passport` | an AINRA presentation, signed per request by the agent's running copy (RFC 9421) | the standard `@ainra/middleware` gate, with send-once and single-use nonces |

Forwarded requests carry `x-ainra-operator` and `x-ainra-passport-name`; the presentation headers are stripped.
`GET /.well-known/ainra-decisions-head` returns the log's head digest, the gate's public key and the latest receipt.
With `--publish-head https://registrar.example` the pilot hands its signed head to that registrar's transparency log
every `--head-every` decisions (100) or `--head-seconds` (300), whichever comes first, and keeps the receipt in
`<decisions>.receipt.json`; anyone can then check the log with `ainra verify-decisions --receipt` and see a cut tail as
`truncated` ([D-081](../../docs/DECISION-RECORDS.md)). Records after the latest logged head are what it could still
lose, so the interval is that bound.

## Watch mode

To try the check alone, beside one route, before it can refuse anything. `--watch` puts the gate beside the route
instead of in front of it. Every request is served as before, and the pilot writes down what the gate would have
decided and how long the check took on this machine. It works with `--mode link` and `--mode passport`.

```
# In the path: every request goes on to the service at once, as it came.
node kits/pilot/pilot.mjs --watch --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --directory directory.json --roots roots.json \
  --mode link --registrar https://registrar.example --observations watch.jsonl

# A mirror target: no --upstream. A proxy sends it copies, and it answers each one 204 at once.
node kits/pilot/pilot.mjs --watch --listen 127.0.0.1:8081 \
  --directory directory.json --roots roots.json \
  --mode link --registrar https://registrar.example
```

- **The check never refuses a request and never holds one up.** In the path, a request goes on to the service as
  soon as its headers arrive, and its body streams on as it comes. A service that cannot be reached still gives 502.
  As a mirror target, the pilot answers 204 before it reads the request. The check runs on a copy, on a second
  thread: the thread that forwards never runs a signature check and never waits for one.
- **Header lines as sent.** Every header line goes on with its name, case, order and duplicates as the client sent
  it. Only Host's value changes, to the service's, as without `--watch`. Node adds what its own connection to the
  service needs: a `Connection` line when the client sent none, and `Transfer-Encoding: chunked` with an empty body
  when a POST, PUT, PATCH or other method that may carry a body came with no length. The service's answer comes back
  the same way: status, reason phrase and header lines as it sent them, and Node adds a `Date` line if it sent none,
  and a `Connection` line for its own connection to the client.
- **What Node itself still refuses.** The pilot takes headers up to 256 KiB, so a whole presentation sent in a header
  goes on (a server left at Node's default limits refuses it with 431; see
  [PRESENTATION.md](../../docs/PRESENTATION.md)). It sets no deadline for a body. Headers that take more than 60 s to
  arrive get 408, headers over 256 KiB get 431, and a request Node's parser rejects gets 400, including an HTTP/1.1
  request with no Host. These never reach the service or the file.
- **The pilot's own paths.** `GET /.well-known/ainra-watch` (the summary, below), and in passport mode the prime path.
  The prime path answers as it does without `--watch`: the same handler and store, so the same answer. It answers at
  once even while checks wait, and what it stores takes its place behind the checks of requests that came before it.
  It takes a body up to 1 MiB; a larger one gets 413. Everything else goes to the service.
- **What it writes.** One JSON line per request, to `--observations` (default `watch.jsonl` in the directory it runs
  from, created with mode 0600). A checked request:

  ```json
  {"time":"2026-11-12T09:41:07.512Z","method":"GET","path":"/orders","signatures":["signature-agent","rfc9421"],"decision":"refuse","status":403,"reason":"not_linked","check_ms":3.41}
  ```

  `signatures` lists what the request carried: a `Signature-Agent` header (`signature-agent`), an RFC 9421
  `Signature` or `Signature-Input` header (`rfc9421`), an AINRA presentation header (`ainra-presentation`). `decision`
  is `admit` or `refuse`. A refusal has the status and the named reason the gate would have answered. An admission
  names the `operator` and the `passport`. `check_ms` runs from the start of the check to the decision, including any
  key directory or status list it had to fetch. A line is written when its check ends, so lines can be out of
  arrival order; `time` is when the request arrived.

  A request that was not checked still gets a line, with `"decision":"unchecked"` and the reason in `not_checked`:
  `check_busy` (the check had fallen behind), `body_over_1_mib` (passport mode copies no larger body) or
  `check_failed` (the gate could not decide, for example on a `Signature-Agent` header it cannot parse). A request
  whose client goes away before the end of its body gets no line.
- **What it never writes:** the client's address, the query string, the body, or any other header. The path is
  written as sent, without its query string, so a path that holds an identifier puts it in the file too. The file
  stays on this machine, and the pilot sends it nowhere. When a check or the prime path fails, the log (stderr) names
  the kind of failure, once for each kind, and never its text, which can hold a request's query string or Host. In
  link mode the check fetches what the gate always fetches: the signature agent's key directory, and the registrar's
  link index and status list.
- **Turning the file over.** Each line is appended by name, so moving the file aside starts a new one with the next
  line, without a restart. Restarting with another `--observations` does the same.
- **The summary.** `GET /.well-known/ainra-watch` returns the running counts as JSON: requests seen, how many were
  checked and how many not (by reason), the signature kinds, decisions, refusals by reason, and `check_ms` p50, p95
  and p99. It answers only a client connecting from a loopback address (127.x.x.x or ::1), and gives anyone else
  403, even a program on this machine that connects from one of its other addresses. It also refuses with 403 a
  request carrying `Forwarded`, `X-Forwarded-For` or `X-Real-IP`, because a proxy on this machine would otherwise make
  every visitor look local. If a proxy in front of the pilot adds none of these headers, block the path at the proxy.
- **The report.** `node kits/pilot/watch-report.mjs watch.jsonl` prints the requests seen; the share of all of them
  carrying any signature, a Signature-Agent header, an RFC 9421 signature and an AINRA presentation; how many were
  checked, and of those how many the gate would admit and refuse, with refusals by reason; how many were not checked,
  and why; and the check time on this machine (p50, p95, p99). It reads the file a piece at a time, so a large file is
  fine. It exits 2 when the file is missing or cannot be read.
- **No decision log.** `--watch` with `--decisions` exits 2. A signed record saying "refused" for a request that was
  in fact served would be false evidence ([D-105](../../docs/DECISIONS.md)).
- **When the check falls behind.** At most 1,000 copies, or 32 MiB of them (headers and body, counted as they are
  copied), wait for the check. Past that the request still goes on, and its line says `check_busy`. In link mode the
  checks waiting on the registrar share one fetch of its index and status list, and a fetch gives up after 5 s. The
  check keeps at most 512 signature agents' key directories, each for at most an hour.
- **Do not act on `x-ainra-*` headers while watching.** Nothing is stripped, so a client's own `x-ainra-operator`
  reaches the service.

### Feeding it from a reverse proxy

Many reverse proxies can copy each request to a second address and discard the copy's answer. This is called request
mirroring or shadowing. Point the copy at the pilot's `--listen` address, and keep the Host header the client sent,
because signatures cover it. The pilot answers each copy at once, so the proxy is not kept waiting for the check.
With the mirror module of open-source nginx:

```nginx
location /orders {
    mirror /ainra-mirror;               # a copy of each request; its answer is discarded
    proxy_pass http://127.0.0.1:3000;   # the service, unchanged
}
location = /ainra-mirror {
    internal;
    proxy_pass http://127.0.0.1:8081$request_uri;
    proxy_set_header Host $http_host;   # the Host the client signed over
}
```

| Command | What it proves |
|---|---|
| `make pilot-e2e` (after `make live-up` and `make stage-up`; in `make live-drills`) | Both modes, live. **Link:** a linked key's request reaches the upstream with the operator named; an unlinked key is refused `not_linked` and a revoked one `revoked` (after the 10-second status cache), neither reaching the upstream. **Passport:** an agent with its own key and a passport for it sends its bundle once, then a signed request reaches the upstream with the operator named and no presentation headers; unsigned (`presentation_unsigned`), replayed (`presentation_replayed`) and post-revocation (`revoked`) requests are refused and never forwarded. Each pilot's decisions verify and the last is the published head. **Heads:** the passport-mode pilot logs its head at the registrar; the receipt verifies against the published directory, and with the last record cut the chain alone still holds while the receipt reads `truncated`. **Watch:** requests go out with exact header lines and the upstream echoes the lines that reached it. In passport mode the prime path answers as before (the same ref); a signed and an unsigned request, each with a query and a body, reach the upstream with every header line as sent but Host's value, and neither answer carries `x-ainra-reason` or `x-ainra-verdict`; a whole bundle in one header and a body over 1 MiB reach it too; a bundle naming a subject with U+20AC, sent to the prime path, gets 403 and the next request still goes on. In link mode a linked key's request, an unlinked key's and an unsigned one reach the upstream the same way, and a `Signature-Agent` the verifier cannot parse is served and logged by kind only. The files record `admit`, `not_linked`, `sig_invalid`, `presentation_unsigned`, `schema_violation` and `unchecked`, with no address, query string, body or header value in them. The summary answers 403 to a relayed request and to a client on a non-loopback address. With a registrar that never answers, signed requests still reach the upstream within 1 s, and their checks share one fetch that gives up after 5 s. As a mirror target the pilot answers 204 and the upstream sees nothing. `watch-report.mjs` prints the counts and gets a file of known values right, and `--watch --decisions` exits 2. |

This is a test root over http on 127.0.0.1. It proves the mechanism; it is not evidence that anyone runs it.
