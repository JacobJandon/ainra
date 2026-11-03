<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# apps/registrar-box — the operator console

`console.html` is the open registrar console, compiled into the `registrar-box` daemon and served at `GET /console`.
The daemon itself — the self-hostable registrar over `ainra-core` (issuance, renewal, revocation, links, the public
demo door) — lives in [`services/ainra-services/src/bin/registrar_box.rs`](../../services/ainra-services/src/bin/registrar_box.rs);
its HTTP surface is described by `tools/openapi.mjs`. See [../../docs/STATUS.md](../../docs/STATUS.md).
