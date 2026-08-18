// SPDX-License-Identifier: Apache-2.0 OR MIT
// ADR-019: the audience is the VERIFIER's, and it is load-bearing.
//
// HISTORY THIS TEST ENCODES. The conformance corpus carries an `audience` field on the presentation so vectors can
// pin audience cases deterministically — exactly as it carries `now` and `revoked_delegates`. The first version of
// `Verifier.verify()` passed that field straight through, so a presenter could set it to match a stolen
// credential's `aud` and audience binding would be present, documented, and worth nothing. The first FIX
// overrode the field after decoding; the second removed the temptation entirely — `decodePresentation` now takes
// the audience as an argument and never reads the bundle's. A field nobody reads cannot be forgotten by a later
// edit, which is a stronger guarantee than a line that must keep being there.
//
// WITNESS — could these assertions fail? Yes, and the first draft of this file could NOT, which is why it was
// rewritten: it asserted on a constructor field while verifying a bundle that carried no instance credential, so
// deleting the entire audience mechanism left it green. The assertions below run REAL instance vectors from the
// corpus through the TS verifier and vary exactly one field, so removing the audience check turns them red.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { runVector, Verifier } from "../dist/index.js";

const V1 = new URL("../../../vectors/v1/", import.meta.url).pathname;
const names = readdirSync(V1).filter((f) => f.startsWith("instance-valid-")).sort();
const vec = JSON.parse(readFileSync(V1 + names[0], "utf8"));

test("the fixture is a genuine ACCEPTED instance presentation", () => {
  assert.ok(names.length > 0, "the corpus must contain accepted instance vectors");
  assert.equal(vec.expect.verdict, "valid", "otherwise every assertion below proves nothing");
  assert.ok(vec.presentation.instance, "the fixture must actually carry an instance credential");
  assert.ok(vec.presentation.audience?.length, "the fixture must name an audience");
  assert.deepEqual(runVector(vec), { verdict: "valid" });
});

test("presenting to the wrong audience is refused", () => {
  // ONE field changed: the audience this verifier believes itself to be. The credential, its signature, its
  // window, its scope and its proof-of-possession are untouched and all still valid.
  const elsewhere = structuredClone(vec);
  elsewhere.presentation.audience = "https://not-this-service.example";
  assert.deepEqual(runVector(elsewhere), { verdict: "invalid", reason: "instance_pop_invalid" });
});

test("a verifier that has not said who it is accepts no instance credential", () => {
  // The fail-closed default. An empty audience is not "any audience" — it is "nobody has told me who I am", and
  // a service in that state cannot be the intended recipient of anything.
  const anonymous = structuredClone(vec);
  anonymous.presentation.audience = "";
  assert.deepEqual(runVector(anonymous), { verdict: "invalid", reason: "instance_pop_invalid" });
});

test("the GA Verifier's audience is a constructor argument with a fail-closed default", () => {
  const ART = new URL("../../../kits/verifier/sample-artifacts/", import.meta.url).pathname;
  const j = (f) => JSON.parse(readFileSync(ART + f, "utf8"));
  const [directory, roots] = [j("directory.json"), j("roots.json")];
  assert.equal(Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh).audience, "");
  assert.equal(
    Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F2", false, "https://api.example").audience,
    "https://api.example",
  );
});
