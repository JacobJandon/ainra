<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# K1 — both branches, neither taken

K1 is the demand-evidence gate: **8 completed 25-minute interviews with people who run agents that act.** The
count comes from the local tracker, never from a claim.

Everything that could be built for it is built. What is not done is the part no tool can do: a person deciding to
send. This file holds both branches so that decision is a choice between two written things rather than a drift.

**Neither branch has been executed.** Nothing here has been run.

---

## Branch A — the send week

Hour-level, D-1 through D-6. Times are local and deliberately clustered in one part of the day: outreach that
leaks across every hour becomes the only thing you do that week.

### D-1 — the day before anything leaves

| | |
|---|---|
| **09:00–10:30** | Open every proposed candidate's evidence URL and approve or drop. `campaign.mjs approve <id>` prints the URL so approving *is* looking. Anything you cannot confirm in ten seconds: `drop`. A shorter approved list is the point. |
| **10:30–11:00** | `make campaign-status` — read the proposed/approved counts back. If approved interview candidates < 12, stop and go back to research; a send week that starts short ends short. |
| **11:00–12:00** | `campaign.mjs star <id>` the day-one batch. Draft each: `campaign.mjs draft <id>`. Read every draft **out loud**. Any sentence you would not say to their face gets cut. |
| **13:00–13:30** | Verify the packet links resolve **on production**, not locally: `make stranger`. A dead link in an outreach mail is the whole first impression. |
| **13:30–14:00** | Decide the reply address and make sure you can actually see replies. Set nothing else up. |

### D0 — send day one

| | |
|---|---|
| **09:00–11:00** | Send the first **8** interview asks by hand, one at a time. Record each: `campaign.mjs send <id>`. Personalise the two evidence sentences per person — the draft is a starting point, never a mail-merge. |
| **11:00–11:15** | Stop. Eight is the batch. The temptation to do all thirty today is the thing that makes them all sound the same. |
| **16:00–16:30** | Read replies. Answer only what needs answering. Book any interview offered, in their timezone. |

### D1–D2 — the rest out

| | |
|---|---|
| **09:00–11:00** | Next batch of 8. Same discipline, same recording. |
| **11:00–11:30** | Any reply asking "what is this?" gets the one-pager link, not a new essay. |
| **16:00–17:00** | Run interviews that landed. 25 minutes, hard stop. The question list is in `campaign.mjs interview <id>` — ask it, do not improvise a pitch. |

### D3 — the only nudge

| | |
|---|---|
| **09:00–10:00** | `campaign.mjs nudge <id>` for D0 sends with no reply. **One sentence. One nudge. Then stop, forever.** The tool records that they have had theirs. |
| **10:00–12:00** | Final batch of asks, if any remain. |
| **16:00–17:00** | Interviews. |

### D4–D5 — interviews only

| | |
|---|---|
| **All day** | No new sends. Run and write up interviews within the hour they happen — notes written the next day are notes about your memory, not about what they said. `campaign.mjs interview <id>` records completion, which is what K1 counts. |

### D6 — read the gate in the open

| | |
|---|---|
| **09:00–09:30** | `make campaign-status`. Count the completed interviews. |
| **09:30–10:00** | Record the reading whatever it says — `met`, `missed`, or `continuing` — with a written reason. A gate read only when it is flattering is not a gate. |

### The three ways this week fails

1. **Batching by tooling instead of by hand.** Thirty identical mails get thirty non-replies and burn the list.
2. **Nudging twice.** The tracker permits one and remembers. A second nudge converts a non-reply into a no.
3. **Not recording the reading.** An unread gate quietly becomes a gate that never closes.

---

## Branch B — record the gate honestly, without sending

If the sends do not happen, the gate still gets read. This is the paste.

**Note on the verb.** This was specified as `campaign.mjs redate K1`. There is no such command and there should
not be: `campaign/gates.json` says in its own header that *"There are no dates here on purpose — a gate is a BAR,
not a deadline, and a published date is a promise about a calendar that nothing in this repository can verify."*
K1 carries a threshold (8), not a date, so there is nothing to move. The honest equivalent — record a reading, in
the open, with a written reason — already exists as `record`, and `continuing` leaves the gate open.

```sh
node tools/campaign.mjs record K1 continuing --reason \
  'Machinery ready, sends not made. The tooling side of K1 is complete: candidates researched from public sources, every one carrying a citation the tool refuses to store without, an approval gate that blocks drafting and sending until a human has opened that citation, drafts generated, and packet links verified against production. What has not happened is the human act — no message has been sent to anyone. Recording this as continuing rather than missed because the bar was never approached, not approached and failed; and recording it now rather than at a convenient moment, because a gate read only when the reading flatters is not a gate.'
```

**Not pasted.** Running it writes to `campaign/gates.json`, regenerates `campaign/GATES.md`, and that file is
public — so the reading becomes a public statement. That is the intent, and it is the maintainer's to make.

---

## What is true right now

- Every candidate in the tracker is `proposed`. Nothing can be drafted, starred or sent for any of them until
  approved one at a time.
- No message has been sent to anyone, by any channel.
- K1 stands `open` with an empty history — it has never been read.
