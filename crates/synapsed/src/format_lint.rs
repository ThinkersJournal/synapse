// SPDX-License-Identifier: MIT OR Apache-2.0
//! A soft lint for `MESSAGE-FORMATS` v1 headers (ROADMAP row 41, PM 2026-10-31).
//!
//! Measured on the claude-peers history since the formats began: 76% of header lines did not parse,
//! mostly because free words or values with spaces sat on the header line, which is about 28% of all
//! message tokens. [`problem`] names the first reason a message's first line is not a v1 header, as a
//! fixed phrase that never echoes the message. The daemon only reports it (a `warning` on the send
//! reply, a per-role counter); it never rejects, so no wire format changes.

/// The v1 types: (name, whether the first field is a bare word, the keys).
const TYPES: [(&str, bool, &[&str]); 9] = [
    (
        "STATUS",
        false,
        &["lane", "at", "board", "doing", "next", "waiting", "id-from"],
    ),
    (
        "READY",
        true,
        &[
            "head", "merge", "checks", "red", "threads", "codacy", "sourcery", "files",
        ],
    ),
    ("MERGED", true, &["main", "branch", "checked", "next"]),
    ("HOLD", true, &["head", "why", "need"]),
    ("ASK", true, &["to", "options", "recommend", "blocks"]),
    ("TASK", true, &["do", "scope", "deliver", "stop", "from"]),
    ("NOTICE", true, &["affects", "when", "action"]),
    ("FINDING", true, &["ref", "by", "status", "basis"]),
    ("FIX", true, &["was", "now", "reached", "fixed-in"]),
];

/// Why `body`'s first line is not a v1 header, or `None` when it is one (or the body is not text,
/// which is not a lane message and is left alone).
#[must_use]
pub fn problem(body: &[u8]) -> Option<&'static str> {
    let text = std::str::from_utf8(body).ok()?;
    let line = text.lines().next().unwrap_or("");
    let Some(rest) = line.strip_prefix('[') else {
        return Some("no [TYPE] at the start");
    };
    let Some((tag, rest)) = rest.split_once(']') else {
        return Some("no [TYPE] at the start");
    };
    // `[READY v2]`: an optional version after the type.
    let name = tag.split_once(' ').map_or(tag, |(name, _)| name);
    let Some(&(_, bare_first, keys)) = TYPES.iter().find(|(t, _, _)| *t == name) else {
        return Some("unknown type");
    };
    let mut words = rest.split_whitespace();
    if bare_first {
        match words.next() {
            Some(first) if !first.contains('=') => {}
            _ => return Some("missing first field"),
        }
    }
    for word in words {
        let Some((key, value)) = word.split_once('=') else {
            return Some("a word without key=");
        };
        if !keys.contains(&key) {
            return Some("unknown key");
        }
        if value.is_empty() {
            return Some("empty value");
        }
    }
    None
}

/// The sentence a send reply carries for a [`problem`].
#[must_use]
pub fn warning(body: &[u8]) -> Option<String> {
    problem(body).map(|why| {
        format!(
            "first line is not a MESSAGE-FORMATS v1 header ({why}); keep values free of spaces and put free text on note: lines"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_headers_pass() {
        for line in [
            "[STATUS] lane=synapse at=main board=- doing=x next=y waiting=- id-from=pm",
            "[READY] synapse#307 head=0fdce3a merge=CLEAN checks=green red=0 threads=0 codacy=- sourcery=- files=16",
            "[MERGED] synapse#307 main=48268fa branch=deleted checked=- next=-",
            "[HOLD] synapse#307 head=abc why=red need=rerun",
            "[ASK] topic to=pm options=A|B recommend=A blocks=-",
            "[TASK] synapse do=x scope=y deliver=z stop=w from=pm",
            "[NOTICE] topic affects=all when=now action=none",
            "[FINDING] topic ref=r by=me status=s basis=b\nnote: free text on later lines is fine",
            "[FIX] topic was=a now=b reached=c fixed-in=d",
            "[READY v2] x head=1",
            "[READY] synapse#1",
        ] {
            assert_eq!(problem(line.as_bytes()), None, "{line}");
        }
    }

    #[test]
    fn each_way_to_fail_names_its_reason() {
        for (line, why) in [
            ("just prose", "no [TYPE] at the start"),
            ("", "no [TYPE] at the start"),
            ("[READY synapse#1", "no [TYPE] at the start"),
            ("[REPORT] x", "unknown type"),
            ("[READY] head=1", "missing first field"),
            ("[READY]", "missing first field"),
            ("[READY] synapse#1 head=1 all green", "a word without key="),
            ("[READY] synapse#1 colour=red", "unknown key"),
            ("[READY] synapse#1 head=", "empty value"),
            ("[STATUS] lane=x doing=two words", "a word without key="),
        ] {
            assert_eq!(problem(line.as_bytes()), Some(why), "{line:?}");
        }
    }

    #[test]
    fn a_binary_body_is_not_linted_and_the_warning_never_echoes_the_message() {
        assert_eq!(problem(&[0xff, 0xfe, 0x00]), None);
        let w = warning(b"[READY] synapse#1 secret-token-abc").unwrap();
        assert!(!w.contains("secret-token-abc"), "{w}");
        assert!(w.contains("a word without key="), "{w}");
    }
}
