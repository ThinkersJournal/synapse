#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""P0 of docs/AI_TO_AI_COMMUNICATION_PLAN_2026-10-25.md: what does lane traffic cost in tokens?

    python .github/ai2ai_p0_tokens.py --self-test
    python .github/ai2ai_p0_tokens.py --peers-db COPY.db \
        --tokenizer qwen3=path/to/tokenizer.json --tiktoken cl100k_base --out numbers.json

Reads the messages table of a COPY of the claude-peers database (never the live file), counts tokens
in memory with each tokenizer it is given, and writes NUMBERS ONLY: counts, lengths, token totals and
percentiles per message type. No message text, sender, recipient or timestamp leaves the process, so
the output may be committed. Skipped before counting (PM ruling 2026-10-25): anything that looks like a
secret, and anything that quotes CireSnave. Every number names its tokenizer.

Needs, for the real run only: `pip install tokenizers tiktoken` (local analysis; the repo has no
Python dependency). The self-test needs neither.
"""
import argparse
import json
import re
import sqlite3
import sys

HEADER = re.compile(r"^\[([A-Z][A-Z-]*)(?: v(\d+))?\]")
SECRETISH = re.compile(
    r"-----BEGIN|ghp_[A-Za-z0-9]|github_pat_|\bBearer\s+[A-Za-z0-9._-]{16,}|\b[0-9a-f]{64}\b|"
    r"\b(api[_-]?key|secret|password|token)\s*[:=]\s*\S{12,}",
    re.IGNORECASE,
)


def classify(text):
    """The message type: the bracketed header type of the first line, else 'prose'."""
    m = HEADER.match(text)
    return m.group(1) if m else "prose"


def skipped(text):
    """True for a message that must not be counted: secret-adjacent, or a CireSnave quote."""
    if SECRETISH.search(text):
        return True
    return "CireSnave" in text and ('"' in text or "“" in text)


def split_header(text):
    """(header line, the rest). For a compact message the header is the whole machine-readable part."""
    head, _, rest = text.partition("\n")
    return head, rest


def percentile(sorted_values, p):
    if not sorted_values:
        return 0
    i = min(len(sorted_values) - 1, max(0, round(p / 100 * (len(sorted_values) - 1))))
    return sorted_values[i]


def measure(messages, counters):
    """messages: iterable of (text, meta); meta = {"period": str, "day": str} (labels only).
    counters: {name: callable(text) -> token count}. Returns numbers only, per tokenizer and per type,
    plus, per period (before or after the compact formats), the prose and header shares of the tokens."""
    out = {"counted": 0, "skipped": 0, "skipped_chars": 0, "counted_chars": 0, "tokenizers": {}}
    per = {name: {} for name in counters}
    groups = {name: {"period": {}} for name in counters}
    for text, meta in messages:
        if skipped(text):
            out["skipped"] += 1
            out["skipped_chars"] += len(text)
            continue
        out["counted_chars"] += len(text)
        out["counted"] += 1
        kind = classify(text)
        # A message with no bracketed header is all prose: none of it counts as header.
        head = "" if kind == "prose" else split_header(text)[0]
        for name, count in counters.items():
            row = per[name].setdefault(
                kind, {"n": 0, "chars": 0, "tokens": 0, "header_tokens": 0, "note_tokens": 0, "each": []}
            )
            total = count(text)
            h = count(head) if head else 0
            row["n"] += 1
            row["chars"] += len(text)
            row["tokens"] += total
            row["header_tokens"] += h
            row["note_tokens"] += max(0, total - h)
            row["each"].append(total)
            for axis in ("period",):
                g = groups[name][axis].setdefault(
                    meta[axis], {"n": 0, "tokens": 0, "prose_tokens": 0, "header_tokens": 0, "days": set()}
                )
                g["n"] += 1
                g["tokens"] += total
                g["prose_tokens"] += total if kind == "prose" else 0
                g["header_tokens"] += h
                g["days"].add(meta.get("day", ""))
    for name, kinds in per.items():
        grand = sum(r["tokens"] for r in kinds.values()) or 1
        table = {}
        for kind, r in sorted(kinds.items()):
            each = sorted(r.pop("each"))
            r["share_of_tokens"] = round(r["tokens"] / grand, 4)
            r["mean_tokens"] = round(r["tokens"] / r["n"], 2)
            r["p50_tokens"] = percentile(each, 50)
            r["p90_tokens"] = percentile(each, 90)
            r["max_tokens"] = each[-1]
            table[kind] = r
        for axis in groups[name].values():
            for g in axis.values():
                g["prose_share"] = round(g["prose_tokens"] / g["tokens"], 4) if g["tokens"] else 0
                g["header_share"] = round(g["header_tokens"] / g["tokens"], 4) if g["tokens"] else 0
                g["mean_tokens"] = round(g["tokens"] / g["n"], 2) if g["n"] else 0
                g["days"] = len(g["days"] - {""})
        out["tokenizers"][name] = {
            "total_tokens": sum(r["tokens"] for r in kinds.values()),
            "by_type": table,
            "by_period": dict(sorted(groups[name]["period"].items())),
        }
    return out


def build_counters(args):
    counters = {}
    for spec in args.tokenizer or []:
        name, _, path = spec.partition("=")
        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(path)
        counters[name] = lambda text, tok=tok: len(tok.encode(text).ids)
    for enc_name in args.tiktoken or []:
        import tiktoken

        enc = tiktoken.get_encoding(enc_name)
        counters[f"tiktoken:{enc_name}"] = lambda text, enc=enc: len(enc.encode(text, disallowed_special=()))
    return counters


COMPACT_ADOPTED = "2026-09-16"  # MESSAGE-FORMATS v1 was introduced after the 2026-09-16 budget outage


def peers_messages(path):
    # A copy of the database, opened read-only. The text never leaves this generator's consumer; the
    # meta carries two labels only: before or after the compact formats, and the day.
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    for text, sent_at in con.execute("select text, sent_at from messages order by id"):
        period = "before-compact-formats" if (sent_at or "")[:10] < COMPACT_ADOPTED else "after-compact-formats"
        yield text, {"period": period, "day": (sent_at or "")[:10]}


def self_test():
    assert classify("[READY] synapse#1 head=abc") == "READY"
    assert classify("[READY v2] x") == "READY"
    assert classify("just prose") == "prose"
    assert classify("") == "prose"
    assert skipped("here is -----BEGIN PRIVATE KEY-----")
    assert skipped("token=abcdefghijklmnop")
    assert skipped('CireSnave said "go"')
    assert not skipped("[STATUS] lane=synapse")
    assert not skipped("CireSnave asked nothing quoted")
    assert split_header("a\nb\nc") == ("a", "b\nc")
    words = lambda text: len(text.split())
    lane, pm = {"period": "after"}, {"period": "before"}
    msgs = [
        ("[READY] a b", dict(lane, day="d1")),
        ("[READY] c d\nnote: x y z", lane),
        ("plain words here", pm),
        ('CireSnave "q"', lane),
        ("[STATUS] one", lane),
    ]
    got = measure(msgs, {"words": words})
    assert got["counted"] == 4 and got["skipped"] == 1, got
    rows = got["tokenizers"]["words"]["by_type"]
    assert rows["READY"]["n"] == 2 and rows["READY"]["tokens"] == 3 + 7, rows
    assert rows["READY"]["header_tokens"] == 3 + 3 and rows["READY"]["note_tokens"] == 4, rows
    assert rows["prose"]["n"] == 1 and rows["prose"]["header_tokens"] == 0 and rows["prose"]["note_tokens"] == 3 and abs(sum(r["share_of_tokens"] for r in rows.values()) - 1) < 0.01
    assert "text" not in json.dumps(got), "numbers only"
    groups = got["tokenizers"]["words"]
    assert groups["by_period"]["before"]["prose_share"] == 1 and groups["by_period"]["after"]["prose_share"] == 0
    assert groups["by_period"]["after"]["days"] == 1 and groups["by_period"]["before"]["days"] == 0
    assert groups["by_period"]["before"]["n"] == 1 and got["skipped_chars"] == len('CireSnave "q"')
    print("self-test ok")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--peers-db")
    ap.add_argument("--tokenizer", action="append", help="NAME=path/to/tokenizer.json (HF tokenizers)")
    ap.add_argument("--tiktoken", action="append", help="encoding name, e.g. cl100k_base")
    ap.add_argument(
        "--only-period",
        choices=["before-compact-formats", "after-compact-formats"],
        help="count only messages sent in this period (the by-type table then describes that period)",
    )
    ap.add_argument("--out", help="write the numbers here (default: stdout)")
    args = ap.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.peers_db:
        ap.error("--peers-db is required (a COPY of the database)")
    counters = build_counters(args)
    if not counters:
        ap.error("give at least one --tokenizer or --tiktoken")
    messages = peers_messages(args.peers_db)
    if args.only_period:
        messages = (m for m in messages if m[1]["period"] == args.only_period)
    result = measure(messages, counters)
    result["only_period"] = args.only_period
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
