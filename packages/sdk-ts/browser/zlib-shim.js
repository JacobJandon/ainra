// SPDX-License-Identifier: Apache-2.0 OR MIT
// Browser shim for `node:zlib`'s inflateSync — the ONLY Node builtin @ainra/sdk touches (status-list decompress).
// Node's zlib.inflateSync decodes ZLIB-wrapped data (RFC 1950); fflate's UNZLIBsync is the matching decoder
// (fflate.inflateSync is raw RFC-1951 deflate — the wrong one). Synchronous, browser-safe, MIT.
import { unzlibSync } from "fflate";
export function inflateSync(data, opts) {
  const input = data instanceof Uint8Array ? data : new Uint8Array(data);
  const max = opts && opts.maxOutputLength;
  // A fixed-size `out` bounds the output (fflate throws if the stream would exceed it) — the same zlib-bomb guard
  // the SDK relies on. Any trailing bytes past the real length stay zero and are never indexed (bound by bit_len).
  return max ? unzlibSync(input, { out: new Uint8Array(max) }) : unzlibSync(input);
}
