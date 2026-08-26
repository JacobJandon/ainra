// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The staleness horizon (M32 / D-058). A published record ages; the page must say so ON ITS OWN.
//
// The failure this exists to prevent is not the site going down. It is the site STAYING UP and slowly becoming a
// lie: artifacts stop being refreshed, and every page goes on implying a present tense that stopped being true
// months ago. A stale page that looks current is an active falsehood told to someone deciding whether to trust an
// identity system.
//
// So the horizon is stated, not implied, and the wording is derived from the DATA rather than written by hand —
// which is the property that survives the operator. Nobody has to remember to edit anything.
//
// Deliberately a PURE function of (stamp, now): no clock of its own, no I/O, no DOM. That is what makes it
// drillable — `make staleness-drill` calls it with a shifted clock and checks the sentence changes, which is
// impossible to do honestly with a function that reads `Date.now()` internally.

/** Days after which a published record stops being described as current. See docs/STALENESS.md for the reasoning. */
export const HORIZON_DAYS = 45;

/** Days after which the record is described as unmaintained rather than merely old. */
export const UNMAINTAINED_DAYS = 180;

/**
 * What a surface should say about a published record of a given age.
 *
 * Returns `{ state, text, days }`. `state` is one of `current` · `aging` · `stale` · `unmaintained`, and is the
 * thing a caller should branch styling on; `text` is the sentence to show.
 */
export function staleness(publishedAtIso, nowMs = Date.now()) {
  const t = Date.parse(publishedAtIso);
  if (!Number.isFinite(t)) return { state: "unknown", text: "published record — no date recorded", days: null };
  const days = Math.max(0, Math.round((nowMs - t) / 86400000));
  const on = publishedAtIso.slice(0, 10);

  if (days >= UNMAINTAINED_DAYS)
    // The strongest statement, and the one nobody would write by hand about their own project. That is exactly why
    // it has to come from the data.
    return { state: "unmaintained", days, text: `UNMAINTAINED SINCE ${on} — this record is ${days} days old and is no longer being refreshed. Treat everything on this page as historical.` };
  if (days >= HORIZON_DAYS)
    return { state: "stale", days, text: `STALE — published ${on}, ${days} days ago, past the ${HORIZON_DAYS}-day horizon. Verify against the repository before relying on it.` };
  if (days > 0)
    return { state: days > HORIZON_DAYS / 2 ? "aging" : "current", days, text: `published ${on} (${days} day${days === 1 ? "" : "s"} ago)` };
  return { state: "current", days, text: `published ${on} (today)` };
}
