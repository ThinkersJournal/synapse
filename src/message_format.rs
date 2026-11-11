// SPDX-License-Identifier: MIT OR Apache-2.0
//! The L1 decoder for `MESSAGE-FORMATS` v1 (ROADMAP row 41, slice P1; design
//! `docs/DESIGN_AI_TO_AI_COMMUNICATION.md` sections 7.2 and 7.3).
//!
//! A program that reads a lane message the way the format says, so it cannot share an author's
//! misreading: [`decode`] parses the header, **rejects** a message with an unknown type, an unknown
//! version, a missing required key, a word without `key=`, an empty value, a `|` in a value, or a
//! later line that is not a `note:` line, and [`render`] turns an accepted header into prose by fixed
//! rules (the same input always gives the same text). Extra keys after the listed ones are allowed,
//! as the format says; [`Header::extra_keys`] names them.
//!
//! Every refusal is a [`FormatError`] whose text names the rule that was broken and shows the shape
//! the type wants. The text never echoes the message: it carries only fixed phrases, the type name
//! and the key names from the format's own table.
//!
//! No size saving is claimed (design 7.4); this is the auditor, not a codec.
//!
//! Not enforced: key order (the format says "in the order shown" but readers cope), and visible-ASCII
//! tokens (design 7.2's `token`); a non-ASCII value is accepted.

use std::fmt;

/// The version this decoder reads. An untagged header is v1.
pub const KNOWN_VERSION: u32 = 1;

/// One v1 type: its name, whether it takes a bare subject word first, and its required keys in
/// template order. This is `MESSAGE-FORMATS.md`'s table, nothing more.
struct Type {
    name: &'static str,
    subject: bool,
    keys: &'static [&'static str],
}

const TYPES: [Type; 9] = [
    Type {
        name: "STATUS",
        subject: false,
        keys: &["lane", "at", "board", "doing", "next", "waiting", "id-from"],
    },
    Type {
        name: "READY",
        subject: true,
        keys: &[
            "head", "merge", "checks", "red", "threads", "codacy", "sourcery", "files",
        ],
    },
    Type {
        name: "MERGED",
        subject: true,
        keys: &["main", "branch", "checked", "next"],
    },
    Type {
        name: "HOLD",
        subject: true,
        keys: &["head", "why", "need"],
    },
    Type {
        name: "ASK",
        subject: true,
        keys: &["to", "options", "recommend", "blocks"],
    },
    Type {
        name: "TASK",
        subject: true,
        keys: &["do", "scope", "deliver", "stop", "from"],
    },
    Type {
        name: "NOTICE",
        subject: true,
        keys: &["affects", "when", "action"],
    },
    Type {
        name: "FINDING",
        subject: true,
        keys: &["ref", "by", "status", "basis"],
    },
    Type {
        name: "FIX",
        subject: true,
        keys: &["was", "now", "reached", "fixed-in"],
    },
];

/// Keys whose value is a `,`-separated list (design 7.2, the sub-structure table).
const LIST_KEYS: [&str; 5] = ["board", "red", "files", "options", "why"];

/// The required keys of a type in template order, or `None` for a name that is not a v1 type.
#[must_use]
pub fn keys_of(kind: &str) -> Option<&'static [&'static str]> {
    lookup(kind).map(|t| t.keys)
}

fn lookup(name: &str) -> Option<&'static Type> {
    TYPES.iter().find(|t| t.name == name)
}

fn type_names() -> String {
    TYPES.iter().map(|t| t.name).collect::<Vec<_>>().join(", ")
}

/// The shape of one type: `[ASK] <subject> to= options= recommend= blocks=`.
fn template(t: &Type) -> String {
    let mut out = format!("[{}]", t.name);
    if t.subject {
        out.push_str(" <subject>");
    }
    for k in t.keys {
        out.push(' ');
        out.push_str(k);
        out.push('=');
    }
    out
}

/// Why a message is not a v1 message. The `Display` text names the rule and shows the shape; it never
/// repeats anything from the message itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// The first line does not start with `[TYPE]`.
    NoType,
    /// `[TYPE]` is not one of the v1 types.
    UnknownType,
    /// Text after the type that is not `v<digits>`.
    BadVersion,
    /// A well-formed version this decoder does not read.
    UnknownVersion(u32),
    /// A type that takes a subject has none (the first word is `key=value`, or there is no word).
    MissingSubject(&'static str),
    /// `[STATUS]` has no subject, and a bare word stands where a pair belongs.
    UnexpectedSubject(&'static str),
    /// A word after the subject with no `=`.
    WordWithoutKey(&'static str),
    /// `key=` with nothing after it.
    EmptyValue,
    /// A `|` inside a value.
    PipeInValue,
    /// A required key of the type is absent.
    MissingKey(&'static str, &'static str),
    /// A line after the header (1-based, counting from the header as line 1) that is not `note: ...`.
    NotANote(usize),
}

impl FormatError {
    /// A short stable name, for counters and for tests (`missing-subject`, `pipe-in-value`, ...).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            FormatError::NoType => "no-type",
            FormatError::UnknownType => "unknown-type",
            FormatError::BadVersion => "bad-version",
            FormatError::UnknownVersion(_) => "unknown-version",
            FormatError::MissingSubject(_) => "missing-subject",
            FormatError::UnexpectedSubject(_) => "unexpected-subject",
            FormatError::WordWithoutKey(_) => "word-without-key",
            FormatError::EmptyValue => "empty-value",
            FormatError::PipeInValue => "pipe-in-value",
            FormatError::MissingKey(..) => "missing-key",
            FormatError::NotANote(_) => "not-a-note",
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shape = |kind: &str| lookup(kind).map(template).unwrap_or_default();
        match self {
            FormatError::NoType => write!(
                f,
                "the first line must start with [TYPE], one of {}",
                type_names()
            ),
            FormatError::UnknownType => {
                write!(f, "[TYPE] is not a v1 type; the types are {}", type_names())
            }
            FormatError::BadVersion => write!(
                f,
                "a version after the type is v<digits>, like [READY v2]; none means v1"
            ),
            FormatError::UnknownVersion(n) => {
                write!(f, "version v{n} is not known; this reads v{KNOWN_VERSION}")
            }
            FormatError::MissingSubject(k) => write!(
                f,
                "[{k}] needs a bare subject word right after the tag, before the key=value pairs: {}",
                shape(k)
            ),
            FormatError::UnexpectedSubject(k) => write!(
                f,
                "[{k}] has no subject: every word after the tag is key=value: {}",
                shape(k)
            ),
            FormatError::WordWithoutKey(k) => write!(
                f,
                "a word after the subject has no key=; every pair is key=value with no spaces in the value (- for none, , between list items, free text on note: lines): {}",
                shape(k)
            ),
            FormatError::EmptyValue => write!(f, "a key has an empty value; write - for none"),
            FormatError::PipeInValue => {
                write!(f, "a value contains |; separate list items with ,")
            }
            FormatError::MissingKey(k, key) => {
                write!(f, "[{k}] is missing the key {key}: {}", shape(k))
            }
            FormatError::NotANote(n) => write!(
                f,
                "line {n} after the header must start with `note: ` (free text goes on note: lines)"
            ),
        }
    }
}

impl std::error::Error for FormatError {}

/// A parsed v1 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The type name, one of the v1 types.
    pub kind: &'static str,
    /// The version (1 when untagged).
    pub version: u32,
    /// The bare subject word, for types that take one.
    pub subject: Option<String>,
    /// The `key=value` pairs, in the order written.
    pub pairs: Vec<(String, String)>,
    /// The `note:` lines after the header, without the `note: ` prefix.
    pub notes: Vec<String>,
}

impl Header {
    /// The keys written that are not among the type's own (the format allows extras after the
    /// listed ones; a linter may still want to name them).
    #[must_use]
    pub fn extra_keys(&self) -> Vec<&str> {
        let own = lookup(self.kind).map_or(&[][..], |t| t.keys);
        self.pairs
            .iter()
            .map(|(k, _)| k.as_str())
            .filter(|k| !own.contains(k))
            .collect()
    }

    /// The value of `key`, if written.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse a first line by the grammar and refuse what breaks it. This checks the line's own structure
/// (type, version syntax, subject, pairs) and does **not** require every key of the type nor a
/// version this decoder reads; [`decode`] adds those. A soft linter uses this entry point.
///
/// # Errors
/// The first rule the line breaks, as a [`FormatError`].
pub fn parse_header(line: &str) -> Result<Header, FormatError> {
    let rest = line.strip_prefix('[').ok_or(FormatError::NoType)?;
    let (tag, rest) = rest.split_once(']').ok_or(FormatError::NoType)?;
    let (name, version) = match tag.split_once(' ') {
        None => (tag, KNOWN_VERSION),
        Some((name, v)) => {
            let digits = v.strip_prefix('v').ok_or(FormatError::BadVersion)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(FormatError::BadVersion);
            }
            // Too many digits is not a version anyone wrote.
            (
                name,
                digits.parse::<u32>().map_err(|_| FormatError::BadVersion)?,
            )
        }
    };
    let t = lookup(name).ok_or(FormatError::UnknownType)?;
    let mut words = rest.split_whitespace().peekable();
    let mut subject = None;
    if t.subject {
        match words.peek() {
            Some(first) if !first.contains('=') => subject = words.next().map(str::to_string),
            _ => return Err(FormatError::MissingSubject(t.name)),
        }
    }
    let mut pairs = Vec::new();
    for word in words {
        // A bare first word on a type with no subject is a subject nobody asked for; any other
        // bare word is a value that broke at a space.
        let (key, value) = word
            .split_once('=')
            .ok_or(if t.subject || !pairs.is_empty() {
                FormatError::WordWithoutKey(t.name)
            } else {
                FormatError::UnexpectedSubject(t.name)
            })?;
        if value.is_empty() {
            return Err(FormatError::EmptyValue);
        }
        if value.contains('|') {
            return Err(FormatError::PipeInValue);
        }
        pairs.push((key.to_string(), value.to_string()));
    }
    Ok(Header {
        kind: t.name,
        version,
        subject,
        pairs,
        notes: Vec::new(),
    })
}

/// Decode a whole message: the header by [`parse_header`], then a version this decoder reads, every
/// required key of the type, and only `note:` lines after the header.
///
/// # Errors
/// The first rule the message breaks, as a [`FormatError`].
pub fn decode(message: &str) -> Result<Header, FormatError> {
    let mut lines = message.lines();
    let mut header = parse_header(lines.next().unwrap_or(""))?;
    if header.version != KNOWN_VERSION {
        return Err(FormatError::UnknownVersion(header.version));
    }
    let t = lookup(header.kind).expect("parse_header returns a known type");
    for key in t.keys {
        if header.get(key).is_none() {
            return Err(FormatError::MissingKey(t.name, key));
        }
    }
    for (i, line) in lines.enumerate() {
        let note = line
            .strip_prefix("note: ")
            .ok_or(FormatError::NotANote(i + 2))?;
        header.notes.push(note.to_string());
    }
    Ok(header)
}

fn render_value(key: &str, value: &str) -> String {
    if value == "-" {
        return "none".to_string();
    }
    if LIST_KEYS.contains(&key) {
        return value.replace(',', ", ");
    }
    if key == "checks"
        && let Some((pass, total)) = value.split_once('/')
        && !pass.is_empty()
        && !total.is_empty()
        && pass.bytes().all(|b| b.is_ascii_digit())
        && total.bytes().all(|b| b.is_ascii_digit())
    {
        return format!("{pass} of {total}");
    }
    value.to_string()
}

/// Render an accepted header to prose, by fixed rules: one sentence, `TYPE subject: key value; key
/// value`, the type's keys in template order then any extra keys in the order written, `-` as
/// "none", list keys with `, `, `checks=p/t` as "p of t", everything else verbatim; each note on its
/// own following line, unchanged. The same header always gives the same text.
#[must_use]
pub fn render(header: &Header) -> String {
    let t = lookup(header.kind).expect("a Header holds a known type");
    let mut parts: Vec<String> = Vec::new();
    for key in t.keys {
        if let Some(v) = header.get(key) {
            parts.push(format!("{key} {}", render_value(key, v)));
        }
    }
    for (k, v) in &header.pairs {
        if !t.keys.contains(&k.as_str()) {
            parts.push(format!("{k} {}", render_value(k, v)));
        }
    }
    let mut out = header.kind.to_string();
    if let Some(s) = &header.subject {
        out.push(' ');
        out.push_str(s);
    }
    if !parts.is_empty() {
        out.push_str(": ");
        out.push_str(&parts.join("; "));
    }
    out.push('.');
    for note in &header.notes {
        out.push('\n');
        out.push_str(note);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_documented_header_decodes_and_renders_by_fixed_rules() {
        let m = "[READY] fuel#211 head=31ec300d merge=CLEAN checks=14/14 red=- threads=0 codacy=ok sourcery=skipped files=docs/gaps.md,scripts/x.py\nnote: nothing new";
        let h = decode(m).unwrap();
        assert_eq!(h.kind, "READY");
        assert_eq!(h.subject.as_deref(), Some("fuel#211"));
        assert_eq!(
            render(&h),
            "READY fuel#211: head 31ec300d; merge CLEAN; checks 14 of 14; red none; threads 0; codacy ok; sourcery skipped; files docs/gaps.md, scripts/x.py.\nnothing new"
        );
        assert_eq!(render(&h), render(&decode(m).unwrap()));
    }

    #[test]
    fn extra_keys_may_follow_the_listed_ones_and_render_after_them() {
        // MESSAGE-FORMATS: "Extra keys may follow the listed ones" (the OverMind runner keys are such).
        let h = decode("[HOLD] x colour=red head=1 why=a,b need=who:what").unwrap();
        assert_eq!(h.extra_keys(), vec!["colour"]);
        assert_eq!(
            render(&h),
            "HOLD x: head 1; why a, b; need who:what; colour red."
        );
        assert!(
            decode("[HOLD] x head=1 why=a need=b")
                .unwrap()
                .extra_keys()
                .is_empty()
        );
    }

    #[test]
    fn each_rule_names_itself() {
        for (m, code) in [
            ("prose", "no-type"),
            ("[READY synapse#1", "no-type"),
            ("[REPORT] x", "unknown-type"),
            ("[READY vx] a", "bad-version"),
            ("[READY v] a", "bad-version"),
            ("[READY 2] a", "bad-version"),
            ("[READY v2] a head=1", "unknown-version"),
            (
                "[ASK] topic=x to=a options=b recommend=- blocks=-",
                "missing-subject",
            ),
            ("[ASK]", "missing-subject"),
            ("[STATUS] lane=x stray", "word-without-key"),
            ("[STATUS] oops lane=x", "unexpected-subject"),
            ("[HOLD] x head=1 all red", "word-without-key"),
            ("[HOLD] x head=", "empty-value"),
            (
                "[ASK] t to=a options=b|c recommend=- blocks=-",
                "pipe-in-value",
            ),
            ("[HOLD] x head=1 why=a", "missing-key"),
            ("[HOLD] x head=1 why=a need=b\nfree text", "not-a-note"),
        ] {
            let got = decode(m).map(|_| ()).unwrap_err();
            assert_eq!(got.code(), code, "{m:?} -> {got}");
        }
    }

    #[test]
    fn the_first_missing_key_in_template_order_is_named() {
        let e = decode("[ASK] t to=a blocks=-").unwrap_err();
        assert_eq!(e, FormatError::MissingKey("ASK", "options"));
        assert!(e.to_string().contains("options"), "{e}");
    }

    #[test]
    fn a_refusal_shows_the_shape_and_never_echoes_the_message() {
        let e = decode("[ASK] topic=hunter2 to=a options=b recommend=- blocks=-").unwrap_err();
        let text = e.to_string();
        assert!(
            text.contains("[ASK] <subject> to= options= recommend= blocks="),
            "{text}"
        );
        assert!(!text.contains("hunter2"), "{text}");
        let e = parse_header("[HOLD] x head=1 hunter2").unwrap_err();
        assert!(!e.to_string().contains("hunter2"));
        let e = parse_header("[HOLD] x hunter2").unwrap_err();
        assert!(!e.to_string().contains("hunter2"));
    }

    #[test]
    fn a_pair_splits_on_the_first_equals_only() {
        let h = decode("[NOTICE] t affects=a when=b=c action=-").unwrap();
        assert_eq!(h.get("when"), Some("b=c"));
        assert_eq!(render(&h), "NOTICE t: affects a; when b=c; action none.");
    }

    #[test]
    fn the_version_tag_is_read_and_v1_is_the_default() {
        assert_eq!(parse_header("[READY] x").unwrap().version, 1);
        assert_eq!(parse_header("[READY v7] x").unwrap().version, 7);
        assert_eq!(
            parse_header("[READY v99999999999] x"),
            Err(FormatError::BadVersion)
        );
    }

    #[test]
    fn status_has_no_subject_and_renders_without_one() {
        let h = decode(
            "[STATUS] lane=synapse at=9:00Z board=0 doing=idle next=- waiting=pm:merge id-from=wt",
        )
        .unwrap();
        assert_eq!(h.subject, None);
        assert_eq!(
            render(&h),
            "STATUS: lane synapse; at 9:00Z; board 0; doing idle; next none; waiting pm:merge; id-from wt."
        );
    }

    #[test]
    fn parse_header_does_not_require_every_key() {
        assert!(parse_header("[READY] synapse#1").is_ok());
        assert!(decode("[READY] synapse#1").is_err());
    }
}
