# P0: what lane traffic costs in tokens

Measured 2026-10-25 for ROADMAP row 41, slice P0 of `AI_TO_AI_COMMUNICATION_PLAN_2026-10-25.md`, with
`.github/ai2ai_p0_tokens.py`. **Numbers only: no message text, sender, recipient or timestamp is in this file or in
the repository.** Every number names its tokenizer.

## What was measured

- **Source** (PM-approved 2026-10-25): a copy of the claude-peers database, 27,842 message rows. One row is one
  delivery to one recipient, so a broadcast counts once per recipient.
- **Counted:** 23,223 rows (40,587,572 characters). **Skipped before counting:** 4,619 rows
  (12,841,204 characters, 24.0% of all characters) that looked secret-adjacent or quoted CireSnave (PM ruling).
  **That slice is large and unmeasured, so every total below is a lower bound.** The skipped rows average 2,780 characters against 1,747 for the counted ones.
  The Synapse mailbox was not sampled: it holds acknowledged-history ids, not bodies, and a handful of queued messages.
- **Tokenizers** (no paid API): `cl100k_base` (tiktoken 0.14.0, a generic BPE); Qwen3-0.6B and TinyLlama-1.1B (the
  `tokenizer.json` files in the local Hugging Face cache, `tokenizers` 0.23.3). No Phi tokenizer exists locally.
- **Periods:** `before` = sent before 2026-09-16, when `MESSAGE-FORMATS` v1 was introduced; `after` = from then on.
- **Types:** the bracketed header type of the first line (`[READY]`, `[STATUS]`, ...), else `prose` (no header).
  A headered message's first line is its header, the rest its `note:` lines.

## Result 1: per message, the compact formats cost about a third

| tokenizer | period | days | messages | tokens | mean tokens/message | prose (no header) | header lines |
|---|---|---|---|---|---|---|---|
| Qwen3-0.6B | before | 25 | 10,228 | 7,888,014 | 771.22 | 100.0% | 0.0% |
| Qwen3-0.6B | after | 35 | 12,995 | 2,873,551 | 221.13 | 9.6% | 33.9% |
| cl100k_base | before | 25 | 10,228 | 7,672,416 | 750.14 | 100.0% | 0.0% |
| cl100k_base | after | 35 | 12,995 | 2,711,056 | 208.62 | 9.8% | 33.2% |
| TinyLlama-1.1B | before | 25 | 10,228 | 9,263,490 | 905.7 | 100.0% | 0.0% |
| TinyLlama-1.1B | after | 35 | 12,995 | 3,352,283 | 257.97 | 9.6% | 34.3% |

- Qwen3-0.6B: 771.22 -> 221.13 tokens per message, 3.5 times fewer.
- cl100k_base: 750.14 -> 208.62 tokens per message, 3.6 times fewer.
- TinyLlama-1.1B: 905.7 -> 257.97 tokens per message, 3.5 times fewer.

**Not a controlled experiment.** The two periods differ in lanes, work and message mix; the formats arrived the
same week as the budget outage that prompted them. It shows the ground truth of what traffic cost before and after,
not that the format alone caused the drop.

## Result 2: after the formats, most of the cost is the note lines

Messages sent from 2026-09-16 on, with the types that carry most of the tokens. `header` is the first line;
`notes` is everything after it. Shares are of that period's tokens.

**Qwen3-0.6B** (headers 33.9%, headerless prose 9.6%, note lines of headered messages 56.5% of the period's tokens)

| type | messages | share of tokens | mean tokens | p50 | p90 | header tokens | note tokens |
|---|---|---|---|---|---|---|---|
| READY | 3,098 | 25.5% | 236.11 | 194 | 416 | 216,545 | 514,939 |
| FINDING | 956 | 13.8% | 413.9 | 330 | 787 | 72,842 | 322,842 |
| STATUS | 1,599 | 11.4% | 204.83 | 153 | 392 | 84,305 | 243,211 |
| prose | 534 | 9.6% | 517.09 | 402 | 1075 | 0 | 276,126 |
| MERGED | 2,016 | 7.5% | 106.94 | 84 | 170 | 156,844 | 58,740 |
| FIX | 930 | 7.4% | 227.86 | 172 | 453 | 70,250 | 141,658 |
| TASK | 780 | 6.6% | 243.44 | 177 | 471 | 105,665 | 84,218 |
| NOTICE | 1,337 | 5.7% | 122.06 | 100 | 197 | 108,282 | 54,912 |
| ASK | 584 | 5.4% | 265.8 | 202 | 529 | 33,349 | 121,881 |

**cl100k_base** (headers 33.2%, headerless prose 9.8%, note lines of headered messages 57.0% of the period's tokens)

| type | messages | share of tokens | mean tokens | p50 | p90 | header tokens | note tokens |
|---|---|---|---|---|---|---|---|
| READY | 3,098 | 25.1% | 220.1 | 179 | 391 | 195,568 | 486,307 |
| FINDING | 956 | 13.8% | 391.67 | 309 | 750 | 67,119 | 307,318 |
| STATUS | 1,599 | 11.4% | 192.75 | 142 | 368 | 77,426 | 230,776 |
| prose | 534 | 9.8% | 495.39 | 382 | 1046 | 0 | 264,540 |
| FIX | 930 | 7.4% | 217.08 | 159 | 438 | 65,301 | 136,582 |
| MERGED | 2,016 | 7.3% | 98.46 | 77 | 160 | 142,053 | 56,433 |
| TASK | 780 | 6.7% | 233.71 | 168 | 453 | 100,614 | 81,682 |
| NOTICE | 1,337 | 5.7% | 115.3 | 95 | 189 | 101,750 | 52,403 |
| ASK | 584 | 5.5% | 255.83 | 194 | 514 | 32,077 | 117,329 |

**TinyLlama-1.1B** (headers 34.3%, headerless prose 9.6%, note lines of headered messages 56.1% of the period's tokens)

| type | messages | share of tokens | mean tokens | p50 | p90 | header tokens | note tokens |
|---|---|---|---|---|---|---|---|
| READY | 3,098 | 25.5% | 276.06 | 225 | 490 | 260,563 | 594,658 |
| FINDING | 956 | 13.9% | 485.69 | 387 | 922 | 88,088 | 376,232 |
| STATUS | 1,599 | 11.5% | 240.26 | 177 | 460 | 101,799 | 282,383 |
| prose | 534 | 9.6% | 602.37 | 469 | 1252 | 0 | 321,663 |
| MERGED | 2,016 | 7.4% | 123.07 | 97 | 195 | 181,270 | 66,849 |
| FIX | 930 | 7.4% | 265.35 | 195 | 537 | 82,747 | 164,031 |
| TASK | 780 | 6.6% | 284.16 | 206 | 538 | 124,507 | 97,139 |
| NOTICE | 1,337 | 5.6% | 141.18 | 117 | 227 | 125,763 | 62,999 |
| ASK | 584 | 5.4% | 311.94 | 236 | 631 | 41,133 | 141,039 |

## Result 3: the fixed wrapper

A channel push wraps every body in a tag with identifying attributes and a warning line. A **synthetic** wrapper of
the same shape (made-up ids, no real text) costs, per message: Qwen3-0.6B 86, cl100k_base 71, TinyLlama-1.1B 96 tokens.
Against the post-format mean per message that is Qwen3-0.6B 39%, cl100k_base 34%, TinyLlama-1.1B 37% of an average message, extra, on every push. A better body format does not shrink it.

## What this says about the plan

1. **P1 (the decoder) saves no tokens by itself**, as the plan said; this confirms the headers are about a third of the
   post-format cost, so even a perfect header encoding (P2) could remove at most that third.
2. **About 57% of the post-format tokens are note lines**, which are free prose. Cutting those is a question about what
   lanes write, not about the wire format; P4 (designed schemas) is the only plan item aimed at it, and its candidate
   gains (AutoForm, CLSR) are still UNVERIFIED.
3. **The fixed wrapper is about a third of an average message** and is Synapse's own to look at, with no negotiation:
   shorter attribute names, dropping `sender_cwd`, a shorter warning line. The warning line is a safety measure, so what may go
   is a review question, not decided here. A first candidate for a measured follow-up, ahead of anything wire-level.
4. **P0's stop condition cannot be judged from this file.** It asks whether routine traffic is a small share of the
   spend; the spend is not in the data. What this gives is the lane traffic's own size: see the first table.

## Limits

- Receive side only (a row is a message as read). Send-side output tokens and tool-call overhead are not measured.
- The skipped slice (above) is excluded, and the claude-peers history is not the Synapse mailbox.
- The wrapper is a synthetic reconstruction of the Synapse channel tag as Claude Code shows it (source, message_id, sender, sender_cwd, the warning line); real attribute lengths vary a little.
- Token counts differ by tokenizer by up to about 25% (TinyLlama above cl100k); conclusions are read off ratios, which agree across the three.
- Reproduce on a copy of the database: `python .github/ai2ai_p0_tokens.py --peers-db COPY.db --tokenizer name=tokenizer.json --tiktoken cl100k_base [--only-period after-compact-formats]`.
