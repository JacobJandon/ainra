<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Run an AINRA witness — <10 minutes, your own infra

A witness independently cosigns the log's append-only growth and **refuses to cosign a fork**. The more independent
operators witness, the harder equivocation becomes. There are **zero** independent witnesses today and the seats are
open — recruiting them is a pending Definition-of-Done row, and the genesis board counts them from evidence.

## Run it

```sh
# from a clone
bash kits/witness/be-a-witness.sh --operator "Your Institution" --region EU
```

That builds `witnessd`, keeps your witness's identity in `~/.ainra-witness` (a random key made on first start, 0600,
and the state that lets it refuse a fork after a restart — keep that folder), takes every log's key from the
root-signed directory (the copy published at https://ainra.org/net/, or `--directory`/`--roots`; the daemon verifies it
against the roots before it starts), starts it on `0.0.0.0:4991`, and runs the fork drill from the same binary. A
public witness without a key file or a directory refuses to start. By hand: fetch `directory.json` and `roots.json`
from https://ainra.org/net/, `cp kits/witness/witness.config.json witness.config.json`, edit it, then
`witnessd 0.0.0.0:4991 witness.config.json`.

## Witness, and keep the evidence

```sh
node kits/witness/submit.mjs --registrar <registrar-url> --witness http://127.0.0.1:4991 \
     --out evidence/cosignatures/<your-id>.json
```

It asks your witness where it left the log, asks the registrar for its signed checkpoint and the consistency proof from
there, and writes your cosignature only if your witness gave one. Run it on a schedule. Submit the file as
`evidence/cosignatures/<your-id>.json`; `make genesis-status` counts distinct keys over one checkpoint the log really
signed, and never a key the project runs (`witnesses/project-keys.json`). To be on the network's roster too, open a
pull request adding the candidacy file `be-a-witness.sh` prints as `evidence/witness/<your-id>.json`; CI checks its
shape and probes your endpoint (`evidence/README.md`).

## Prove it works

```sh
make witness-feed-drill     # three witnesses against a real registrar; restart, replay, key swap and forgery all refused
make drill-networked        # N independent witnessd processes; an injected fork is refused by the quorum
```

Honest state: the directory is published (a dated copy of the STAGING network, TEST-ROOT), but its registrars run on a
pinned clock and bind `127.0.0.1`, so there is no public, wall-clock registrar feed for an outside witness to poll
until the network is hosted (PLAN-M52). Everything above runs today; the public feed is the missing piece, and it is
ours to provide.
