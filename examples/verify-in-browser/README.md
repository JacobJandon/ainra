<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Verify an agent credential — in your browser

The smallest honest demonstration of the whole idea: **the real verifier, running on your machine, with nothing
sent anywhere.** No account, no key, no server — the page performs no network request at verification time.

```sh
npm install
npm run dev      # http://localhost:8080
```

Edit the bundle in the box and press Verify. Change one byte of a signature and it refuses with a named reason —
that is the point. The recorded verdict shown beside yours is the answer the other three independent
implementations produce for the same bytes, from the published CC0 corpus.

**Why this is the demo and not a video:** an agent-identity root asking to be trusted is a contradiction. The only
argument that works is *check it yourself*, and the shortest path to that is a page that verifies in front of you.

Runs anywhere modern; embedding it in a hosted playground works best in Chromium-based browsers. The same
verification runs on the project's own site with no third-party platform involved at all.
