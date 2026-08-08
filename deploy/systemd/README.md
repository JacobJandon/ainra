<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The staging network as a standing service

Until M27 the staging network was four processes started by hand. They died with the terminal that started
them — so the demo's spine worked only while an operator happened to be sitting at the machine.

```sh
make stage-install     # install + start + seed once; survives logout and reboot
make stage-health      # probe the public read contract and the units; non-zero when degraded
make stage-uninstall   # remove the units (state under stage/ is left alone)
```

## The honest availability claim

> **The network runs whenever this machine is powered on. No more than that.**

That sentence is the whole claim, and it is deliberately smaller than "always on":

* **It is not always on.** The machine sleeps, reboots, loses power, travels. `Restart=always` and linger mean
  the network comes back by itself; they do not mean it never went away.
* **It is not reachable by a stranger.** Every daemon binds `127.0.0.1`. The public site at `ainra.vercel.app`
  **cannot** reach it and never could — so making it stand does not turn the live site's minting flow on for
  visitors. It makes the network survive logout, reboot and a crashed daemon, on this machine.

Anywhere the site or docs describe availability, that is the wording to use. "Always-on" would require something
actually always on; see `docs/PLAN-M27.md` § *the always-on question* for the parked options and their costs.

## What is installed

| Unit | What it is | Recovery |
|---|---|---|
| `ainra-registrar@registrar-07.service` | registrar door, `127.0.0.1:4907` | `Restart=always`, 3 s |
| `ainra-registrar@registrar-11.service` | registrar door, `127.0.0.1:4911` | `Restart=always`, 3 s |
| `ainra-witnessd.service` | witness cosigning checkpoints, `127.0.0.1:4991` | `Restart=always`, 3 s |
| `ainra-artifacts.service` | the public read contract, `127.0.0.1:8091` | `Restart=always`, 3 s |
| `ainra-stage-watchdog.timer` | probes the contract every minute | restarts whatever fails to answer |
| `ainra-stage.target` | one handle for all of the above | — |

**Two layers of recovery, because they catch different failures.** `Restart=always` catches a process that
*exited*. The watchdog catches one that is *alive and useless* — wedged, still holding its port, answering
nothing — by probing the same contract a consumer reads. Both were proven rather than assumed:

```
SIGKILL the artifact server → unit=active, new PID, contract answers HTTP 200 again
stop registrar-07 outright  → watchdog: "registrar-07 door not answering (HTTP 000) — restarting"
                            → active, door answers HTTP 200
```

`StartLimitIntervalSec=0` is set on purpose: a machine that wakes with a briefly-unavailable dependency must
converge on running, not land in a permanently `failed` state that only a human notices days later.

**Logging** goes to the journal, which is already rotated and size-capped — no logrotate config to install and
forget. `journalctl --user -u ainra-artifacts -f` to follow one.

**Secrets:** `deploy/systemd/env/` holds the per-instance addresses and the staging write token. It is
gitignored and `chmod 600`; only the unit files themselves are committed.

## Seeding

The daemons *serve* state, they do not invent it. `stage-install` seeds the network once — issue, delegate,
revoke, renew, accredit, publish — and is idempotent: if the contract already lists registrars it leaves the
existing network alone rather than double-issuing.
