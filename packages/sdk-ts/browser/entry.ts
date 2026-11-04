// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The browser bundle's entry: the package root, plus the corpus runners as one namespace. A page replays a vector
// with `conformance.runVector` — the same split `@ainra/sdk` and `@ainra/sdk/conformance` make for an installed SDK,
// so a page's import says which of the two it is doing (D-074).
export * from "../src/index.js";
export * as conformance from "../src/conformance.js";
