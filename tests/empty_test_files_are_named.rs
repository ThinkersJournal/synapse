// SPDX-License-Identifier: MIT OR Apache-2.0
//! **The empty-test-file list in `TEST_VALIDATION_AUDIT_REPORT.md` must match the tree.**
//!
//! That report names three files as EMPTY. Measured at `7b80ca4`, two of the
//! three genuinely were — **so it described that tree correctly.** It was
//! committed at `f0f570c` eleven months later, and **that same commit refilled
//! two of them and emptied a third.**
//!
//! ⚠️ **The report was ACCURATE WHEN WRITTEN AND FALSIFIED BY ITS OWN
//! PUBLICATION.** Neither standard remedy fits: a supersession banner implies it
//! was current and drifted (it never was current here, not for one commit), and
//! a correction implies it was wrong on arrival (it was not). **What it lacked
//! was its REF** — *"several files are empty"* where it should have said *"at
//! `7b80ca4`, these files were empty."*
//!
//! # ⚠️ EMPTINESS IS MEASURED BY CONTENT, NOT BY BYTE COUNT, AND THAT IS NOT A DETAIL
//!
//! These files hold a single newline. **In git's LF blobs that is 1 byte; in a
//! Windows working tree with CRLF it is 2.** A guard written as `len <= 1`
//! answers differently depending on where it reads from, and would have reported
//! **zero** empty files on the tree where four are empty. **This one strips
//! whitespace and asks whether anything remains**, which cannot drift with line
//! endings.
//!
//! # What is pinned, and why it is not the report's sentence
//!
//! The original claim is deliberately KEPT — it is the record of what was
//! measured and when. **So "the report says X is empty" cannot be the failure
//! condition**, or correcting the document would redden this guard forever.
//! **The correction states the CURRENT empty set, and this test holds that
//! statement to the tree.** Empty a file or fill one, and it reddens until the
//! document is updated.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Test files whose content is entirely whitespace.
fn empty_by_content(tests_dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = fs::read_dir(tests_dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "rs")
            && let Ok(text) = fs::read_to_string(&p)
            && text.trim().is_empty()
            && let Some(stem) = p.file_stem().and_then(|s| s.to_str())
        {
            out.insert(stem.to_string());
        }
    }
    out
}

/// The set the correction states as current, from its "the current empty set is
/// exactly:" line. Anchored on prose rather than a line number.
fn documented_empty_set(doc: &str) -> Option<BTreeSet<String>> {
    let marker = "the current empty set is exactly:";
    let idx = doc.find(marker)?;
    // The list may wrap; read to the blank-ish terminator.
    let tail = &doc[idx + marker.len()..];
    // "none" is a statement of the empty set, not an absence of one.
    if tail.trim_start().starts_with("none") {
        return Some(BTreeSet::new());
    }
    let end = tail
        .find("(4 of")
        .or_else(|| tail.find('\n').map(|_| tail.len()))?;
    let names: BTreeSet<String> = tail[..end]
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|s| s.contains('_') && s.len() > 4)
        .map(|s| s.to_string())
        .collect();
    if names.is_empty() { None } else { Some(names) }
}

#[test]
fn the_report_names_exactly_the_empty_test_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests_dir = root.join("tests");

    // Non-vacuity: if the directory read fails, both sets are empty and this
    // passes having examined nothing.
    let all = fs::read_dir(&tests_dir)
        .expect("control: tests/ is unreadable")
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
        .count();
    assert!(
        all > 10,
        "only {all} .rs files found under tests/ — the reader is broken, not the tree"
    );

    let actual = empty_by_content(&tests_dir);

    let doc = fs::read_to_string(root.join("docs/archive/TEST_VALIDATION_AUDIT_REPORT.md"))
        .expect("control: TEST_VALIDATION_AUDIT_REPORT.md is missing — repoint, do not delete");

    let stated = documented_empty_set(&doc).unwrap_or_else(|| {
        panic!(
            "TEST_VALIDATION_AUDIT_REPORT.md no longer states the current empty set.\n\
             Measured now: {actual:?}\n\n\
             The report's own three-file list is kept deliberately as the record of what was \
             measured at 7b80ca4, so this test cannot key on it. Restore a statement of the \
             CURRENT set, with the ref it was taken at."
        )
    });

    assert_eq!(
        stated, actual,
        "THE REPORT'S EMPTY-FILE LIST AND THE TREE DISAGREE.\n\n  \
         document states : {stated:?}\n  \
         tree has        : {actual:?}\n\n\
         Update the correction block, with the ref you measured at.\n\n\
         ⚠️ This guard exists because that report was ACCURATE WHEN WRITTEN and falsified by \
         the commit that published it — a measurement with no ref becomes a claim about the \
         present the moment it is repeated.\n\n\
         ⚠️ Emptiness here is whitespace-stripped content, NOT byte count: these files hold one \
         newline, which is 1 byte in git and 2 in a CRLF working tree, and a size threshold \
         reports zero empty files on a tree where four are."
    );
}
