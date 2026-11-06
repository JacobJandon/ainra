<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# AINRA Witness Kit — a witness quorum you can actually deploy

A single witness catching a fork is trust-in-one-operator. AINRA's fork defence is a **quorum of independently-operated
witnesses** (D-021): a log checkpoint is *certified* only when at least **k** distinct witnesses cosign it, and because
each honest witness refuses to cosign a checkpoint that forks the head it already cosigned, an equivocating fork can't
reach quorum unless **k or more** witnesses are adversarial. M6 proved this in-process; this kit runs it **between
separate processes over HTTP**, so you can put each witness on its own machine.

## Prove it locally
```sh
make drill-networked            # 5 witnessd processes on separate ports, k=3
# → honest head certified (5 cosigns fetched over HTTP); INJECTED FORK refused 5/5 → not certified
make drill-networked N=7 K=4    # any N >= 3, any 1 <= k <= N
```

## Run your own witness (v3 — one binary, one file, one folder)
```sh
bash kits/witness/be-a-witness.sh --operator "Your Institution" --region EU
                                                    # key + memory + the published directory in ~/.ainra-witness
# or by hand:
cargo build --release -p ainra-services --bin witnessd
curl -O https://ainra.org/net/directory.json -O https://ainra.org/net/roots.json   # the root-signed directory
cp kits/witness/witness.config.json my-witness.json     # edit operator/region/contact/note
./target/release/witnessd 0.0.0.0:4991 my-witness.json   # makes witness.key (0600) on first start
node kits/witness/submit.mjs --registrar <registrar-url> --witness http://127.0.0.1:4991 \
     --out evidence/cosignatures/<you>.json             # your cosignature, as the genesis board counts it
make witness-check                                        # smoke + a TIMED <10-min onboarding rehearsal
make witness-feed-drill                                   # the whole path against a real registrar, and its failures
```
What a witness a stranger runs needs, and what the daemon now does about each:
- **A key nobody else can compute.** `key_file` is made at random on first start (0600) and kept; a file that exists
  but cannot be read stops the daemon instead of being replaced. An address-derived or `seed`-phrase key is
  computable, so off loopback the daemon refuses to start without `key_file`.
- **A memory.** `state_file` keeps the last head cosigned per log and the key each log is held to, saved and fsynced
  before a cosignature is returned. A witness that forgets trusts the next checkpoint on first sight, a fork included.
- **Log keys from the directory.** `directory` + `roots` (published at https://ainra.org/net/) give every log's key
  and the revoked delegates; nothing a caller sends changes them. Required off loopback; a loopback drill without
  them keeps a caller's key only if it verified the checkpoint it came with.
- **Its own clock.** A checkpoint's delegate cert is judged at the witness's time, never the caller's.
- **A feed.** The registrar serves `GET /witness-feed?from=N`: its current signed checkpoint and the consistency proof
  from where your witness left off, so your witness can cosign every append, not only first sight.
- **`witnessd <addr> [config.json]`** — one witness daemon, one binary, no runtime deps.
  - `GET /key` (alias **`/root`**) → its Ed25519 public key.
  - `GET /info` → the operator's **self-declared** card `{ self_declared: true, ed25519, operator, region, contact, note }`.
    **Verified by no one** — the key is the only cryptographic fact; the site and verifier render the rest as an
    unverified operator claim. Witnessing needs **no accreditation**.
  - `POST /consider` → it evaluates a submitted checkpoint (validly log-signed? append-only vs the head it last
    cosigned?) and returns its **outcome** and, when it accepts, a **cosignature**.
  - `GET /seen` → the last head it cosigned per log (what `submit.mjs` asks the feed to prove consistency from).
    - Key: `key_file` (random, kept) — required off loopback, with `directory` + `roots`. On loopback a `seed` pins a
    phrase-derived key, and with neither the key is derived from the address, so a local drill quorum has
    **distinct** keys.
- **`witness-quorum-drill <k> <addr>...`** — a **relying party**: it fetches each witness's key (its roster), submits
  the log's checkpoints, collects the cosignatures over the wire, assembles a `QuorumCertificate`, and checks
  `certified(checkpoint, roster, k)`.

## Witness the root's own history too: the epoch log (D-097)

A registrar's log is not the only thing that can be shown differently to different people. The root's one act is a
directory epoch, and a host could serve one epoch 3 to some observers and another to the rest. The epoch log puts
every archived epoch into an RFC 6962 tree (origin `ainra-directory`); your cosignature on its head says "this is
the one history I was shown". It needs no daemon and no operator key: each leaf is a directory signed by both roots,
and the witness checks every one itself.

```bash
ainra directory witness --net https://ainra.org/net --roots pinned-roots.json \
      --key ~/.ainra-witness/epoch.key --state ~/.ainra-witness/epoch-state.json --out epoch-cosig.json
```

- The first run makes a random key (0600) in `--key`. Keep it: it is your identity.
- `--state` remembers each epoch's digest and the last head. It is saved before you sign.
- You refuse by name:
  - a different digest for an epoch you have seen (a split view);
  - a log that shrank;
  - an epoch that does not verify under both pinned roots.
- Send `epoch-cosig.json` to the steward. The steward adds it with
  `ainra directory log --write <net> --add-cosig epoch-cosig.json`, which refuses one that does not verify.
- `ainra ctl status` verifies every served cosignature and counts the ones you pin with `--epoch-witness <key>`.
- Run it on a schedule, for example daily from cron. Each run either extends what you have signed or refuses.

`make epoch-log-drill` shows each refusal and each alarm. It also shows that a witness whose memory is deleted
signs two different histories under one key, which is evidence anyone can check against it.

## Choosing your quorum k (worked examples)
`k` is **your** risk tolerance, not the network's. With `N` witnesses on the roster, a checkpoint is certified once
`k` distinct ones cosign. Two failure modes pull `k` in opposite directions — **safety** (can a fork be certified?)
needs `k` *high*; **liveness** (can honest witnesses still certify?) needs `k` *low*:

| Your roster | k | A fork needs… | You still certify if… | Fits |
|---|---|---|---|---|
| N=3 | **2** | 2 of 3 witnesses collude | any 2 are honest + reachable | a small deployment, low stakes |
| N=5 | **3** | 3 of 5 collude | any 3 of 5 up | the default staging shape (`make drill-networked`) |
| N=7 | **5** | 5 of 7 collude | any 5 of 7 up | payments-grade: tolerates 2 down AND resists 4 malicious |
| N=5 | 1 | **one** rogue witness equivocates | any 1 up | ✗ too low — one bad witness certifies a fork |
| N=5 | 5 | all 5 collude | **all 5** up | ✗ too high — one witness offline halts you |

Rule of thumb: pick the largest `k` whose "you still certify" column you can operationally sustain. A fork is then
uncertifiable unless **k** witnesses are simultaneously adversarial — you buy safety up to your liveness budget. `k`
travels with the *verifier's* config, never with a credential or a certificate (below).

## The one rule that must never bend: **k is the relying party's**
The threshold **k is an argument the relying party supplies** — it is *never* read from anything fetched. The
certificate carries **no threshold field** at all, so an equivocating log that assembles a certificate for its fork
cannot set `k = 0` and "self-certify"; `certified()` also refuses a nonsensical `k = 0`. (This is the M6 review's HIGH
fix — see D-021 — preserved across the network transport. The regression lives in
`services/ainra-services/tests/fork_drill.rs`.)

## Deploying real witnesses
- Run one `witnessd` per operator, each on its own host, behind a reverse proxy terminating **TLS** (the daemon speaks
  plain HTTP by design — transport security + auth are the deployment's job, matching the local-by-default posture).
- Publish each witness's public key so relying parties can build a roster they trust (out of band, or via the log's
  accreditation). Relying parties pick their own **k** from that roster — a payments-grade verifier might demand a
  higher k than a low-stakes one.
- Fill in `/info` (operator, region, contact) so relying parties and the explorer can see **witness diversity** — how
  many independent operators, in how many regions, stand behind a checkpoint. It is self-declared and rendered as
  such; diversity is a *social* fact the metadata surfaces, never a cryptographic claim the protocol enforces.
- This is deliberately **boring**: fetch + verify, no gossip protocol, no consensus engine (Certificate Transparency's
  gossip never shipped; witness cosigning is the deployed fix — MTS §5). The security is in the signatures, not the
  transport.

## What this closes (and what stays out of scope)
- **Closed:** the witness quorum runs between separate processes over a network; the §29 "injected fork caught by
  witnesses (not us)" is demonstrable with independently-operated witnesses, not just in-process keys. v2 makes the
  daemon a **one-file-config single binary** with a self-declared `/info` card, and `make witness-check` times the
  full clone→running-witness path (well under the 10-minute onboarding bar the kit promises).
- **Out of scope (deployment):** TLS/auth/rate-limiting on the transport, witness discovery, and hardware witnesses —
  standard operational concerns layered on top; the security-relevant logic is all in `ainra-services::witness`.
