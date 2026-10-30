// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// @ainra/sdk/conformance — replay the public test vectors.
//
// These functions answer what a VECTOR says, which is the point of a conformance corpus: `runVector` believes the
// vector's own clock, freshness class and status list, so it can pin every reason deterministically. That is exactly
// why it must never decide whether to trust a presenter — a revoked agent carrying an all-clear list of its own would
// read valid (D-074). To decide, use `Verifier` from the package root. This entry point exists so that the difference
// is in the import path, not only in a comment.
export {
  runVector,
  expectedVerdict,
  runDeltaVector,
  runDirectoryVector,
  runGateVector,
  runLinkVector,
  runDecisionVector,
} from "./index.js";
export { runPresentationVector } from "./presentation.js";
