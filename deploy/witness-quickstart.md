<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Run an AINRA witness — <10 minutes, your own infra

A witness independently cosigns the log's append-only growth and **refuses to cosign a fork**. The more independent
operators witness, the harder equivocation becomes. Staging has **open seats** — witnessing staging now is how
witness recruitment (a pending DoD row) begins for real.

## Run it

```sh
# from a clone (or the released image)
cargo build --release -p ainra-services --bin witnessd
cp kits/witness/witness.config.json witness.config.json   # edit operator/region/contact; set a long random `seed`
./target/release/witnessd 0.0.0.0:4991 witness.config.json # the config is OPTIONAL: `witnessd 0.0.0.0:4991` also works
```

Your witness's key comes from the `seed` in your one-file config (pin a long random secret so the key is stable across
restarts) — or, with no config, it is derived from the address. Either way you are a *distinct* witness, not a copy of
ours. Tell the network operator your `http://<your-host>:4991` and your public key (`GET /root`, alias `GET /key`);
they add you to the witness set. `GET /meta` serves your **self-declared** operator/region card (verified by no one —
it just lets relying parties see witness diversity). A relying party sets its own quorum `k` (never a cert's) — see
D-021 and the quorum-k worked examples in `kits/witness/README.md`.

## Prove it works (catch a fork)

```sh
make drill-networked        # runs N independent witnessd processes; an injected fork is refused by the quorum
```

This is real: your witness will refuse to cosign a checkpoint that forks the log it already cosigned. That refusal,
from an operator we do not control, on infra we do not control, is exactly the property the "≥3 independent
witnesses on separate infra" DoD row needs. Machinery is ready; the humans are the remaining work.
