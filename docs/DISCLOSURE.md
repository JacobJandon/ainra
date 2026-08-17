<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Disclosure — mechanical, deadlined, and with no severity threshold

**This is a proposed accreditation term. It is not yet binding on anyone, because there is no legal entity to bind
them and no accredited registrar besides the staging pair.** It is written now because the deadline is the control,
and a deadline invented during an incident is not one.

## The arrow

Two landmark removals from browser root programs were driven by **conduct, not by the technical fault.**

On the 2011 compromise, the removing vendor listed its reasons in order, and the first was not the breach:

> *"1) Failure to notify. DigiNotar detected and revoked some of the fraudulent certificates 6 weeks ago without
> notifying Mozilla."*

The same post contrasted it with a comparable incident at another CA months earlier, which was *"detected,
contained, and reported to us immediately"* and survived. And it produced the doctrine sentence:

> **"The integrity of the SSL system cannot be maintained in secrecy."**

On the 2016 removal, the deciding factor was again conduct:

> *"The levels of deception demonstrated by representatives of the combined company have led to Mozilla's decision
> to distrust future certificates."*

That CA had also **owned another CA for eleven months without disclosing it**, and denied both that and the
backdating until proven wrong.

Fifteen years later the doctrine is mechanical: a **72-hour** public report, filed *"regardless of perceived
impact"*, intermediate CAs disclosed within **7 days of creation and before issuing anything**, and notification
**before** ownership or control changes.

## Why a deadline, and not a judgement

Every removal above involved someone deciding, in the moment, that a thing did not need reporting yet. A deadline
with a severity threshold recreates that decision; a deadline without one removes it. The point is not that 72
hours is magic — it is that **there is no conversation to have.**

## Proposed terms

An accredited registrar **shall**:

1. **Publish an initial incident report within 72 hours** of becoming aware of any of the following, **regardless of
   perceived impact, and without waiting to establish scope**: mis-issuance of any passport; any unauthorised access
   to issuance or signing infrastructure; any loss of, or loss of confidence in, key material; any inability to
   enumerate what it has issued.

   *No severity threshold.* "We assessed it as low impact" is not a reason to delay, and the assessment is exactly
   what an incident report exists to expose to review.

2. **Report an inability to enumerate its own issuance as the most serious class of incident.** The 2011 CA could
   not produce a complete list, *"so the only remedy was to remove the root certificate."* Under AINRA the log makes
   this recoverable — issuance is logged before valid, so the record does not depend on the registrar's own database
   — but a registrar whose internal state has diverged from the log must say so, because the divergence is itself
   the incident.

3. **Disclose a change of ownership or operational control BEFORE it takes effect**, not after. Eleven months of
   undisclosed ownership was, in the 2016 case, treated as more disqualifying than the technical failures beside it.

4. **Answer questions on an open incident within one week, and post an update at least weekly** until closed.

5. **Accept that a pattern is judged, not only an event.** Two 2024–25 removals cited *"a pattern of compliance
   failures, unmet improvement commitments, and the absence of tangible, measurable progress"* rather than any
   single incident. Continued accreditation is a claim that must keep being re-earned, and **the metric is response
   to incidents, not absence of incidents.**

## What makes these enforceable here, and what does not

**Does:** [D-044](DECISIONS.md) graduated distrust. Before it, the only response to a registrar was total removal,
which is why removal gets deferred until it is unavoidable. Now a cutoff can be published at a log position, with
everything earlier still verifying — so a proportionate response exists, which is what makes a disclosure term
credible rather than decorative.

**Does not, yet:** there is no legal entity to hold the agreement, no appeals body, and no accredited registrar
beyond the staging pair. So this is a draft term, and it says so at the top. The charter already promises that
revocation is *public and appealable*; this is what the disclosure half of that promise looks like written down.

## The one we have to apply to ourselves first

The root operates the log and the directory. Everything above is meaningless if the operator exempts itself, and
the record is unambiguous that root programs judge the operator hardest.

So the same 72-hour, no-threshold, no-scope-required rule binds the root, and the first place it applies is the
thing this project keeps finding: **a check that was reporting health it could not observe.** Three shipped this
session — a soak consumer that could not read the instrument, a drift gate that asked the wrong service, a daemon
that never reloaded its own state. Each was disclosed in the commit that fixed it, in the open, before anyone asked.
That is the standard; writing it down only makes it a rule instead of a habit.
