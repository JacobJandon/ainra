// SPDX-License-Identifier: Apache-2.0 OR MIT
// The site's one network gateway. Every read any page performs goes through here, for one reason:
//
//   a fetch with no deadline is not a slow fetch, it is a hung page.
//
// A refused connection rejects in milliseconds, so the "no registrar reachable" path was always well tested. A host
// that ACCEPTS the packet and never answers — a firewall that drops instead of resets, a wedged daemon, a laptop that
// closed its lid mid-request — never rejects at all. Before M27 that left `?reg=<such-a-host>` in a state with no
// name: the honest "unavailable" note never appeared, the buttons never got their listeners, and the page sat there
// looking ready while being incapable. Failing closed means every wait ends, and ends in words.
//
// One deadline for the whole site, in one place, so no future caller can forget it.

export const NET_TIMEOUT_MS = 8000;

// AbortSignal.timeout is the right tool and is everywhere current; the controller fallback keeps an older browser
// from silently reverting to the unbounded wait this module exists to abolish.
function deadline(ms) {
  if (typeof AbortSignal !== "undefined" && AbortSignal.timeout) return AbortSignal.timeout(ms);
  const c = new AbortController();
  setTimeout(() => c.abort(), ms);
  return c.signal;
}

/** fetch() that always has a deadline. Same signature; `timeoutMs` overrides the default. */
export function fetchT(url, opts = {}) {
  const { timeoutMs, ...rest } = opts;
  return fetch(url, { ...rest, signal: deadline(timeoutMs ?? NET_TIMEOUT_MS) });
}

/** fetchT + a non-2xx is an error, not a body to parse. Callers that need headers use fetchT directly. */
export async function getJSON(url, opts = {}) {
  const res = await fetchT(url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/** Say which failure it was: a host that never answered is a different problem from one that said no. */
export function why(e, url) {
  const n = e?.name === "TimeoutError" || e?.name === "AbortError";
  return n ? `no answer from ${url} within ${NET_TIMEOUT_MS / 1000}s` : `could not reach ${url}`;
}
