# Efficient AI-to-AI communication: slice one, the plan

Status: plan, 2026-10-25. **No code.** ROADMAP row 41. Design: `DESIGN_AI_TO_AI_COMMUNICATION.md` (approved by
CireSnave 2026-09-18; the PM judged the start condition met on 2026-10-25). Why now, in the PM's words: CireSnave's
standing concern is tokens spent on lane traffic, and this is the design for cutting it.

## 1. What is solid and what is not

**Solid (read from `origin/main` or the portfolio files, not from the papers).** Sender authentication, receiver
acknowledgement, sealing, replay suppression and agent certificates are on `main`, so a negotiation can be refused
from anyone but a `Verified` sender (design section 11.1). `MESSAGE-FORMATS` v1 exists and lanes use it. The design's
section 7.3 decoder (a program that parses and renders v1) does not exist yet.

**Not evidence yet: OverMind's summary file** (`research/ai-to-ai-communication-papers.md`, 304 lines). A non-Claude
model summarised the papers and a script checked its figures. Of 54 reported gains, 43 are marked checked and 4 have
a quote with no figure (together the 47 this plan treats as unflagged) and 7 failed the check. **A check mark means
the number appears in a quote that appears in the paper; the file itself says it does not show the quote supports the
claim.** So all 54 are **UNVERIFIED** here, the 47 as much as the 7. Also: paper #3 was summarised from its arXiv
preprint because the journal fetch returned 403 (the journal version is **unchecked**); #4 is struck and #8 dropped by
CireSnave; #14 is a survey reporting other papers' numbers; #1's "100-agent" detail lies outside its quote.
**Rule for this plan: no figure from the file drives a decision until someone has read it in the paper itself
(step V below), and our own measurement outranks any paper.**

## 2. The plan, in order

| # | Item | Leans on | Verified by | Stop if |
|---|---|---|---|---|
| P0 | **Measure the traffic.** Tokens per message by type and the total, for real lane traffic, with the tokenizers of the models that read it (design 7.4 says to). A small harness plus a sample of messages. | nothing | the measurement is the evidence | routine traffic is a small share of the spend: then say so and stop |
| P1 | **The L1 decoder for `MESSAGE-FORMATS` v1** (design 7.2, 7.3): parse, reject unknown type, version, missing key or `\|`, render to prose by fixed rules; tested on a corpus of real messages. | nothing (no saving claimed) | the corpus run; sabotage of each rejection rule | P0 shows prose notes, not headers, are the cost: then P1's value is audit only |
| P2 | **A `mode` on the wire, a capability block, selection with acknowledgement** (design 5, 8). Wire change, so a Breaking entry. | Agora (#1), as the design relays it in 4.3: negotiating costs about two natural-language queries and pays back after about three uses | read Agora's cost table in the paper; redo the arithmetic with our own message sizes from P0 | the payback needs more messages per pair than lanes exchange |
| P3 | **A spec registry** (design 12 is a proposal; CireSnave has no preferred design). | Agora's duplicate-protocol finding | a short note to the PM with two options | CireSnave has a preference |
| P4 | **Token-saving L1 schemas beyond v1**, designed not emergent. | AutoForm (#17, up to 72.7%), CLSR (#9, 3 to 6 times), GlossoGen (#5, emergent shorthand did not form on open-weight models) | read each paper's setup; then an A/B of the candidate schema on real lane messages with the P0 harness | the A/B shows no saving on our traffic |
| P5 | **Latent (L2).** Fuel does the training; Synapse carries, versions and verifies (design 11.4). | #7, #10, #14, #15, #16 | not planned until Fuel exists | nothing to do before then |

P0 and P1 do not depend on any paper, so they go first and may be the whole story.

**Update after P0 (2026-10-25, with the PM).** `AI_TO_AI_P0_MEASUREMENT_2026-10-25.md` measured the lane traffic. Headers are only about a third of the tokens after the compact formats and the `note:` lines most of the rest, so P1 (the decoder) is **low value next to shorter note lines**; the PM is tightening the note-line guidance in `MESSAGE-FORMATS` herself. P1 is kept for its audit value only and is no longer next. P2 can save at most that third. The channel wrapper is about a third of an average message: it is **measure-only**. The untrusted-data warning line stays in every message until a design shows an equal-strength protection (for example a fixed marker the harness already explains); anything that weakens it goes to CireSnave. The measured levers that leave the line alone are small (`sender_cwd`, the message id: 20 to 34 tokens of 71 to 96).

## 3. Step V: how a paper figure becomes usable

1. Fetch the paper itself, never the summary (arXiv text or PDF); if the fetch fails, the figure is excluded, not guessed.
2. Read the sentence in context: model, benchmark, metric and baseline must match the claim as the plan states it.
3. Write the finding in a table `docs/AI_TO_AI_EVIDENCE.md`: paper, locator, what was checked, result (confirmed,
   narrower than claimed, or not supported).
4. Only a confirmed figure may sit in a plan item's "Leans on" cell as a reason; it still does not replace P0's measurement.

## 4. Asks of the PM

1. **P0 data:** which archive may I sample for real lane messages (the PM's `[READY]` and `[STATUS]` traffic, the
   Synapse mailbox, or `claude-peers` logs)? Content stays out of the repo; only counts and token numbers are kept.
2. **Tokenizers:** which models read lane traffic, so P0 counts with theirs?
3. Whether P0 and P1 may be one PR each, in that order, before any wire change.
