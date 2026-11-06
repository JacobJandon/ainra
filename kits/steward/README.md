<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The steward's desk

One local screen for everything the directory steward watches, with the emergency playbooks drafted in one action
(PLAN-M53 step 2, D-099).

```bash
make desk                                   # site/net and its roots, desk folder ~/.ainra-desk
NET=https://ainra.org/net ROOTS=pinned-roots.json make desk
```

It opens on `http://127.0.0.1:4979/`. It binds only that address and answers only requests addressed to it.

**What it shows:**
- the control room (`ainra ctl status`, with the desk's own memory);
- the epoch log and its cosignatures;
- the incident log, each open entry against its deadline;
- the compliance ladders in `~/.ainra-desk/ladders`;
- the change requests in `~/.ainra-desk/requests`, each checked now and aged against the 90-day target;
- the latest monthly report.

**The playbooks:**

| Playbook | What it drafts |
|---|---|
| A registrar's log forked | The D-098 fork proof from two checkpoints, the emergency DISTRUST_FROM_LEAF request, the checker's verdict on it, and a HIGH incident entry. |
| A registrar delegate compromised | The registrar's REVOKE_DELEGATE command and the checklist. |
| A root share lost | The share-refresh checklist and an incident entry. |
| The site defaced | The out-of-band checks and an incident entry. |

**It holds no key and publishes nothing.** AINRA has no admin button that changes the network, and must not have one
(D-034). A playbook writes into `~/.ainra-desk/drafts/` and runs read-only checks. Its last step is always a command
that the registrar or the custodians run with their own keys. This is the emergency stop as it exists:
- a gate refuses locally;
- a registrar revokes;
- the root publishes an emergency epoch, which skips the notice wait but never the publication.

`make desk-drill` runs the desk against a TEST-ROOT world from the epoch rehearsal. The fork playbook's request is
accepted by the real checker, and the desk leaves the contract it reads untouched.
