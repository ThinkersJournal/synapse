# SPDX-License-Identifier: MIT OR Apache-2.0
"""ROADMAP row 41, offline: what would a header encoding or a wrapper trim save on recorded lane traffic?

    python .github/ai2ai_header_encodings.py COPY.db QWEN3_tokenizer.json TINYLLAMA_tokenizer.json

NUMBERS ONLY (the rule of ai2ai_p0_tokens.py, which this imports). Needs tiktoken and tokenizers (local analysis).
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ai2ai_p0_tokens as p0
import tiktoken
from tokenizers import Tokenizer

SCHEMA = {  # MESSAGE-FORMATS v1 (C:/Projects/CLAUDE.md section 10): (bare first field?, keys in order)
    "STATUS": (False, ["lane","at","board","doing","next","waiting","id-from"]),
    "READY": (True, ["head","merge","checks","red","threads","codacy","sourcery","files"]),
    "MERGED": (True, ["main","branch","checked","next"]),
    "HOLD": (True, ["head","why","need"]),
    "ASK": (True, ["to","options","recommend","blocks"]),
    "TASK": (True, ["do","scope","deliver","stop","from"]),
    "NOTICE": (True, ["affects","when","action"]),
    "FINDING": (True, ["ref","by","status","basis"]),
    "FIX": (True, ["was","now","reached","fixed-in"]),
}
CODE = {"STATUS":"S","READY":"R","MERGED":"M","HOLD":"H","ASK":"A","TASK":"T","NOTICE":"N","FINDING":"F","FIX":"X"}
HDR = re.compile(r"^\[([A-Z][A-Z-]*)\]\s*(.*)$")

def parse(head):
    m = HDR.match(head)
    if not m or m.group(1) not in SCHEMA: return None
    kind, rest = m.group(1), m.group(2).split()
    bare_first, keys = SCHEMA[kind]
    bare, kv = None, []
    for i, tok in enumerate(rest):
        if "=" in tok and not tok.startswith("http"):
            k, _, v = tok.partition("="); kv.append((k, v))
        elif i == 0 and bare_first: bare = tok
        else: return None            # stray word: not a v1 header, leave it alone
    if bare_first and bare is None: return None
    return kind, bare, kv

def encodings(kind, bare, kv):
    """-> dict name -> rendered header, or None if this header is not covered by the encoding."""
    _, keys = SCHEMA[kind]
    got = [k for k, _ in kv]
    vals = dict(kv)
    if len(vals) != len(kv) or any(k not in keys for k in got): return {}
    order = [k for k in keys if k in vals]
    if got != order: return {}       # out of canonical order: leave alone
    exact = got == keys
    out = {}
    fields = ([bare] if bare is not None else [])
    full = fields + [vals.get(k, "-") for k in keys]
    if exact:
        out["E1 values only, space"] = f"[{kind}] " + " ".join(fields + [vals[k] for k in keys])
        out["E2 values only, pipe"] = f"[{kind}] " + "|".join(fields + [vals[k] for k in keys])
        out["E3 type letter + pipe"] = f"{CODE[kind]} " + "|".join(fields + [vals[k] for k in keys])
    # relaxed: absent keys filled with "-" (net cost counted, so it may be negative)
    out["E3r type letter + pipe, absent keys as -"] = f"{CODE[kind]} " + "|".join(full)
    out["E1r values only, space, absent as -"] = f"[{kind}] " + " ".join(full)
    return out

def main():
    db = sys.argv[1]
    counters = {}
    for name, path in [("qwen3-0.6B", sys.argv[2]), ("tinyllama-1.1B", sys.argv[3])]:
        t = Tokenizer.from_file(path); counters[name] = lambda s, t=t: len(t.encode(s).ids)
    e = tiktoken.get_encoding("cl100k_base"); counters["cl100k_base"] = lambda s: len(e.encode(s, disallowed_special=()))
    res = {}
    for name, count in counters.items():
        n = tot = hdr_tok = headered = parsed = 0
        sav = {}; cover = {}
        bytes_tot = bytes_hdr = 0; bsav = {}
        for text, meta in p0.peers_messages(db):
            if meta["period"] != "after-compact-formats" or p0.skipped(text): continue
            n += 1; tot += count(text); bytes_tot += len(text.encode())
            kind = p0.classify(text)
            if kind == "prose": continue
            head = p0.split_header(text)[0]
            headered += 1; h = count(head); hdr_tok += h; bytes_hdr += len(head.encode())
            p = parse(head)
            if not p: continue
            parsed += 1
            for enc, r in encodings(*p).items():
                sav[enc] = sav.get(enc, 0) + h - count(r)
                bsav[enc] = bsav.get(enc, 0) + len(head.encode()) - len(r.encode())
                cover[enc] = cover.get(enc, 0) + 1
        res[name] = {"messages": n, "total_tokens": tot, "headered": headered, "header_tokens": hdr_tok,
                     "parsed_v1_headers": parsed, "total_bytes": bytes_tot, "header_bytes": bytes_hdr,
                     "encodings": {k: {"covered_headers": cover[k], "tokens_saved": sav[k], "bytes_saved": bsav[k],
                                       "pct_of_header_tokens": round(100*sav[k]/hdr_tok, 2),
                                       "pct_of_all_tokens": round(100*sav[k]/tot, 2)} for k in sav}}
    # wrapper trim: per-message tokens from docs/AI_TO_AI_P0_MEASUREMENT (synthetic reconstruction)
    W = {"qwen3-0.6B": (86, 78, 54), "cl100k_base": (71, 63, 51), "tinyllama-1.1B": (96, 87, 62)}
    for name, (v0, v1, v2) in W.items():
        r = res[name]; n = r["messages"]
        r["wrapper"] = {"V0_per_msg": v0, "V1_saves_per_msg": v0 - v1, "V2_saves_per_msg": v0 - v2,
                        "V1_tokens_saved": n*(v0-v1), "V2_tokens_saved": n*(v0-v2),
                        "V2_pct_of_message_tokens": round(100*n*(v0-v2)/r["total_tokens"], 2),
                        "V2_pct_of_message_plus_wrapper": round(100*n*(v0-v2)/(r["total_tokens"]+n*v0), 2),
                        "wrapper_total_V0_tokens": n*v0}
    print(json.dumps(res, indent=1, sort_keys=True))

if __name__ == "__main__":
    main()
