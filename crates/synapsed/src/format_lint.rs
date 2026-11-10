// SPDX-License-Identifier: MIT OR Apache-2.0
//! A soft lint for `MESSAGE-FORMATS` v1 headers (ROADMAP row 41, PM 2026-10-31; slice P1 moved the
//! parsing to the L1 decoder, `synapse::message_format`).
//!
//! Measured on the claude-peers history since the formats began: 76% of header lines did not parse,
//! mostly because free words or values with spaces sat on the header line, which is about 28% of all
//! message tokens. [`warning`] names the first rule a message's first line breaks and shows the shape
//! its type wants, as fixed phrases that never echo the message. The daemon only reports it (a
//! `warning` on the send reply, a per-role counter); it never rejects, so no wire format changes.
//!
//! Soft means: only the first line, and only what the sender can fix at once. It does not report a
//! missing key, a version it does not read, or a bad later line (the decoder's `decode` does); it
//! does report a key outside the type's own, though the format allows extras after the listed ones,
//! because a typo in a key is the likeliest cause (PM 2026-10-31).

use synapse::message_format::{keys_of, parse_header};

/// Why `body`'s first line is not a v1 header, as a sentence, or `None` when it is one (or the body
/// is not text, which is not a lane message and is left alone).
#[must_use]
pub fn problem(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let line = text.lines().next().unwrap_or("");
    match parse_header(line) {
        Err(e) => Some(e.to_string()),
        Ok(header) => {
            if header.extra_keys().is_empty() {
                None
            } else {
                let keys = keys_of(header.kind).unwrap_or(&[]).join(", ");
                Some(format!(
                    "a key is not one of [{}]'s ({keys}); a typo? (extra keys are allowed after the listed ones)",
                    header.kind
                ))
            }
        }
    }
}

/// The sentence a send reply carries for a [`problem`].
#[must_use]
pub fn warning(body: &[u8]) -> Option<String> {
    problem(body).map(|why| format!("first line is not a MESSAGE-FORMATS v1 header: {why}"))
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
            "[ASK] topic to=pm options=A,B recommend=A blocks=-",
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
    fn each_way_to_fail_says_which_rule_and_shows_the_shape() {
        for (line, needle) in [
            ("just prose", "must start with [TYPE]"),
            ("", "must start with [TYPE]"),
            ("[READY synapse#1", "must start with [TYPE]"),
            ("[REPORT] x", "not a v1 type"),
            ("[READY vx] a", "v<digits>"),
            (
                "[ASK] topic=x to=a options=b recommend=- blocks=-",
                "needs a bare subject word right after the tag",
            ),
            ("[READY] head=1", "[READY] <subject> head= merge="),
            ("[READY]", "needs a bare subject word"),
            ("[READY] synapse#1 head=1 all green", "has no key="),
            ("[STATUS] lane=x doing=two words", "has no key="),
            ("[STATUS] lane=x doing=two words", "no spaces in the value"),
            ("[STATUS] oops lane=x", "[STATUS] has no subject"),
            (
                "[READY] synapse#1 colour=red",
                "a key is not one of [READY]'s",
            ),
            ("[READY] synapse#1 head=", "empty value"),
            (
                "[ASK] t to=a options=b|c recommend=- blocks=-",
                "contains |",
            ),
        ] {
            let w = warning(line.as_bytes()).unwrap_or_else(|| panic!("{line:?} passed"));
            assert!(w.contains(needle), "{line:?} -> {w}");
            assert!(
                w.starts_with("first line is not a MESSAGE-FORMATS v1 header: "),
                "{w}"
            );
        }
    }

    #[test]
    fn a_binary_body_is_not_linted_and_the_warning_never_echoes_the_message() {
        assert_eq!(problem(&[0xff, 0xfe, 0x00]), None);
        let w = warning(b"[READY] synapse#1 secret-token-abc").unwrap();
        assert!(!w.contains("secret-token-abc"), "{w}");
        assert!(w.contains("has no key="), "{w}");
        let w = warning(b"[READY] synapse#1 secret-key=1").unwrap();
        assert!(!w.contains("secret-key"), "{w}");
    }
}
