<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# What regulators and standards bodies ask of AI agents, and what AINRA answers

Checked on 2026-10-20 against each source linked below. **This is a map, not a compliance claim.** AINRA runs on a
test root today, and no regulator has evaluated it. Where a requirement binds only certain systems, or is guidance
rather than law, the table says so.

## The short version

No law anywhere yet requires an agent identity or a revocation system that works across providers. But the bodies
that write the rules have converged on the same four asks:

1. each agent has **its own identity**, distinct from a person;
2. a **registry** of which agents are authorised, and by whom;
3. a way to **stop or revoke** an agent;
4. **logs** that let anyone reconstruct who did what, under whose authority.

All four are things AINRA does: a passport, an accredited registrar, a registrar-signed revocation list checked
offline that fails closed, and a public transparency log.

## Why now: what has already happened

These are documented incidents, not forecasts.

- **Agents breaking out of an evaluation environment, July 2026.** A lab's models in an internal evaluation
  "circumvented controls intended to isolate them from the internet" and attacked a model-hosting platform. The
  platform's own timeline notes that "each sandbox run had a fresh identity". Attribution waited until the lab reported
  it, and the remedy was rotating every credential.
  [lab report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) ·
  [platform timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline) ·
  [independent investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)
- **An espionage campaign largely run by AI, November 2025.** The attacker used AI "to perform 80-90% of the campaign"
  against roughly thirty targets. [report](https://www.anthropic.com/news/disrupting-AI-espionage)
- **Agent impersonation at scale, February 2026.** An exposed database let anyone "fully impersonate any agent" on an
  agent social platform. Its 1.5 million registered agents traced back to about 17,000 humans.
  [report](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
- **The capability trend.** The length of task an agent can finish has doubled about every 89 days since 2024.
  [measurement](https://metr.org/blog/2026-1-29-time-horizon-1-1/)

## The map

| What is asked | Who asks, and how binding | What AINRA provides |
|---|---|---|
| A unique identity for each agent, distinct from people | UK NCSC, guidance, 20 Aug 2026: "All agents should be assigned their own unique identity" ([source](https://www.ncsc.gov.uk/blogs/managing-the-cyber-risk-of-agentic-ai)) · IETF agentproto WG charter: "verifiable agent identity that is distinct from user identity" ([source](https://datatracker.ietf.org/group/agentproto/about/)) · NIST NCCoE concept paper, Feb 2026 ([source](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)) | A passport per agent lineage, and a short-lived credential per running copy |
| A registry of authorised agents | Five Eyes cyber agencies, guidance, 1 May 2026: "Maintain a trusted registry of authorized agents" ([source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)) · China, policy opinion, 8 May 2026: explore an agent registration platform with "digital identity management" ([source](https://www.cac.gov.cn/2026-05/08/c_1779979789523320.htm)) | Accredited registrars under one published rulebook; every passport logged before it is valid. Neutral across providers and countries |
| Stop, suspend or revoke | EU AI Act Art. 14(4)(e) "stop button" and Art. 26(5) suspension: law, for high-risk systems, now from 2 Dec 2027 ([source](https://artificialintelligenceact.eu/article/14/)) · UK NCSC: "always be able to 'pull the plug'" · IETF agentproto: "enables independent revocation of agent access" | A registrar-signed revocation list. Every gate that checks it refuses a revoked agent within 30 seconds on the strict setting, and a missing or stale status is a refusal |
| Revocation of agent keys, and actions bound to a human authorisation | NIST NCCoE concept paper asks how to handle agent keys' "issuance, update, and revocation" and "non-repudiation for agent actions and binding back to human authorization" ([source](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)) | Each request signed by the running copy's own key (RFC 9421), chained to a passport whose operator a registrar verified |
| Logs and traceability | EU AI Act Art. 12 automatic logs and Art. 26(6) retention "at least six months": law, high-risk systems · IETF WIMSE agent-identity draft: "deployments MUST produce durable audit logs" ([source](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/)) · Financial Stability Board, Oct 2026: documentation should support "the reconstruction of actions, particularly for agentic AI" ([source](https://www.fsb.org/uploads/P151026-2.pdf)) | A public, append-only log of every passport and revocation. Planned: signed decision records kept by each gate |
| Know which system acted, and under whose authority | International AI Safety Report, Nov 2025: investigators "need to determine which system was responsible and under whose authority it was acting"; it proposes "secure digital identities that can be verified and audited" ([source](https://arxiv.org/abs/2511.19863)) | The passport names the operator and the registrar that stands behind it; the check runs offline, so nobody has to be asked |
| Telling people they are dealing with AI | EU AI Act Art. 50(1), law from 2 Aug 2026 · California SB 243, law · Korea AI Basic Act, law from 22 Jan 2026 | Every AINRA passport is, by definition, an agent's: a signed request carrying one is machine-checkably from an agent |

## What AINRA does not claim

- It does not make an agent safe or aligned. It makes an agent identifiable, attributable and revocable, which is what
  every response above presupposes.
- It does not make anyone compliant. A deployer's duties under the AI Act belong to the deployer; AINRA can supply
  evidence they may use.
- It holds no personal data and computes no scores, by charter. Human backing is proven to a registrar, not to the root.

## Gaps the sources name that nobody fills yet

1. Revocation that works **across providers**. Short-lived tokens bound the damage by their lifetime; per-network
   directories revoke only inside one network.
2. Linking an action, across organisations, to an **accountable operator**.
3. A **neutral** registry. The proposals so far are run by one state or by one commercial network.

These three are why AINRA exists.
