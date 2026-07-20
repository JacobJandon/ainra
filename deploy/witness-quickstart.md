<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Run an AINRA witness — <10 minutes, your own infra

A witness independently cosigns the log's append-only growth and **refuses to cosign a fork**. The more independent
operators witness, the harder equivocation becomes. Staging has **open seats** — witnessing staging now is how
witness recruitment (a pending DoD row) begins for real.

## Run it

```sh
# from a clone (or the released image)
cargo build --release -p ainra-services --bin witnessd
./target/release/witnessd 0.0.0.0:4991 ./witness-data
# or:  docker run -p 4991:4991 -v witness:/data ainra/services:staging witnessd 0.0.0.0:4991 /data
```

Your witness generates its OWN key on first boot (into `./witness-data`) — you are a *distinct* witness, not a copy
of ours. Tell the network operator your `http://<your-host>:4991` and your public key (`GET /root`); they add you to
the witness set. A relying party sets its own quorum `k` (never a cert's) — see D-021.

## Prove it works (catch a fork)

```sh
make drill-networked        # runs N independent witnessd processes; an injected fork is refused by the quorum
```

This is real: your witness will refuse to cosign a checkpoint that forks the log it already cosigned. That refusal,
from an operator we do not control, on infra we do not control, is exactly the property the "≥3 independent
witnesses on separate infra" DoD row needs. Machinery is ready; the humans are the remaining work.
