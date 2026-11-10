// SPDX-License-Identifier: MIT OR Apache-2.0
//! The L1 decoder (`synapse::message_format`, ROADMAP row 41 slice P1) on a corpus of real lane
//! messages: what the decoder accepts, which rule each refusal names, that a refusal never echoes
//! the message, and that rendering is a fixed function of the header.

use synapse::message_format::{decode, parse_header, render};

fn corpus() -> Vec<(String, String)> {
    include_str!("data/message_corpus.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (expect, msg) = l.split_once('\t').expect("expected TAB message");
            (expect.to_string(), msg.replace("\\n", "\n"))
        })
        .collect()
}

#[test]
fn every_corpus_message_is_decoded_or_refused_as_recorded() {
    let rows = corpus();
    assert!(rows.len() >= 25, "the corpus shrank to {}", rows.len());
    let mut ok = 0;
    let mut refused = 0;
    for (expect, msg) in &rows {
        match (expect.as_str(), decode(msg)) {
            ("ok", Ok(_)) => ok += 1,
            (e, Err(err)) if e == format!("err:{}", err.code()) => refused += 1,
            (e, got) => panic!("{msg:?}: expected {e}, got {got:?}"),
        }
    }
    // Both sides are populated, so a decoder that accepts or refuses everything fails here.
    assert!(ok >= 10 && refused >= 10, "ok={ok} refused={refused}");
}

#[test]
fn every_rule_the_decoder_has_is_exercised_by_a_corpus_row() {
    let seen: Vec<String> = corpus()
        .into_iter()
        .filter_map(|(e, _)| e.strip_prefix("err:").map(str::to_string))
        .collect();
    for code in [
        "no-type",
        "unknown-type",
        "bad-version",
        "unknown-version",
        "missing-subject",
        "unexpected-subject",
        "word-without-key",
        "empty-value",
        "pipe-in-value",
        "missing-key",
        "not-a-note",
    ] {
        assert!(seen.iter().any(|s| s == code), "no corpus row for {code}");
    }
}

#[test]
fn a_refusal_never_repeats_a_value_from_the_message() {
    for (expect, msg) in corpus() {
        if expect == "ok" {
            continue;
        }
        let text = decode(&msg).unwrap_err().to_string();
        assert!(!text.is_empty());
        for word in msg.split_whitespace() {
            if let Some((_, value)) = word.split_once('=')
                && value.len() >= 6
            {
                assert!(!text.contains(value), "{msg:?}: {text:?} repeats {value:?}");
            }
        }
    }
}

#[test]
fn rendering_is_the_same_text_every_time_and_keeps_every_value() {
    for (expect, msg) in corpus() {
        if expect != "ok" {
            continue;
        }
        let h = decode(&msg).unwrap();
        let first = render(&h);
        assert_eq!(first, render(&decode(&msg).unwrap()), "{msg:?}");
        assert!(first.starts_with(h.kind), "{first}");
        for (_, v) in &h.pairs {
            if v == "-" {
                assert!(first.contains("none"), "{first}");
            } else if !v.contains(',') && !v.contains('/') {
                assert!(first.contains(v.as_str()), "{first:?} lost {v:?}");
            }
        }
        for note in &h.notes {
            assert!(first.contains(note.as_str()), "{first:?} lost its note");
        }
    }
}

#[test]
fn the_soft_entry_point_checks_structure_only() {
    // `parse_header` is what the daemon lint uses: structure, not every key.
    assert!(parse_header("[HOLD] synapse#348 head=01b6db76 why=audit-red").is_ok());
    assert!(decode("[HOLD] synapse#348 head=01b6db76 why=audit-red").is_err());
    assert!(parse_header("[ASK] topic=x to=a options=b recommend=- blocks=-").is_err());
}
