// SPDX-License-Identifier: MIT OR Apache-2.0
//! The board export (design section 9, slice S6): every record the caller may read, as one
//! Markdown table or as JSON. Pure rendering over `(Record, Derived)` pairs the store already
//! filtered by access, so an export can never show more than `list` does.
//!
//! Deterministic: rows sorted by id (numerically), and the only wall-clock value in the body is
//! `generated_at` in the header. Every free-text field is data and is escaped for Markdown.
//! Nothing typed is rendered as a fact without the checker's observation beside it.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::{Blocker, Condition, ConditionView, Derived, Record};

/// One record with what is derived about it.
pub type View = (Record, Derived);

fn id_number(id: &str) -> u64 {
    id.strip_prefix("T-")
        .and_then(|n| n.parse().ok())
        .unwrap_or(u64::MAX)
}

fn sorted(views: &[View]) -> Vec<&View> {
    let mut rows: Vec<&View> = views.iter().collect();
    rows.sort_by(|a, b| {
        id_number(&a.0.id)
            .cmp(&id_number(&b.0.id))
            .then_with(|| a.0.id.cmp(&b.0.id))
    });
    rows
}

fn name<T: serde::Serialize>(value: &T) -> String {
    json!(value).as_str().unwrap_or_default().to_string()
}

/// Escape text for one Markdown table cell: nothing in it may start markup, break the row, or
/// carry a control or bidi-override character.
#[must_use]
pub fn escape_cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '|' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '<' | '>' | '&' | '!' | '#'
            | '~' => {
                out.push('\\');
                out.push(c);
            }
            // Controls (newlines included) and the bidi formatting characters.
            c if c.is_control()
                || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
            {
                out.push(' ');
            }
            c => out.push(c),
        }
    }
    out
}

fn age(from: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let minutes = (now - from).num_minutes().max(0);
    match minutes {
        0..=59 => format!("{minutes}m"),
        60..=2879 => format!("{}h", minutes / 60),
        _ => format!("{}d", minutes / 1440),
    }
}

fn condition_text(
    condition: &Condition,
    view: Option<&ConditionView>,
    now: DateTime<Utc>,
) -> String {
    let op = name(&condition.op);
    let mut text = format!("{} {op}", condition.fact.as_str());
    if !condition.value.is_empty() {
        text.push(' ');
        text.push_str(&condition.value);
    }
    match view {
        None => text.push_str(" => not observed"),
        Some(v) => {
            match (&v.observed, v.observed_at) {
                (_, None) => text.push_str(" => not observed"),
                (Some(seen), Some(at)) => {
                    text.push_str(&format!(" => {seen} ({} ago)", age(at, now)));
                }
                (None, Some(at)) => text.push_str(&format!(" => absent ({} ago)", age(at, now))),
            }
            match v.satisfied {
                Some(true) => text.push_str(", satisfied"),
                Some(false) => text.push_str(", not satisfied"),
                None => text.push_str(", unknown"),
            }
            if let Some(error) = &v.error {
                text.push_str(&format!(", last lookup failed: {error}"));
            }
        }
    }
    text
}

fn blocked_on(record: &Record, derived: &Derived, now: DateTime<Utc>) -> String {
    let parts: Vec<String> = record
        .blocked_on
        .iter()
        .enumerate()
        .map(|(i, blocker)| match blocker {
            Blocker::Record(id) => id.clone(),
            Blocker::Condition(c) => condition_text(
                c,
                derived.blocked_on.get(i).and_then(|b| b.condition.as_ref()),
                now,
            ),
        })
        .collect();
    let mut text = if parts.is_empty() {
        String::from("-")
    } else {
        escape_cell(&parts.join("; "))
    };
    if derived.unblocked {
        text.push_str(" **UNBLOCKED**");
    }
    text
}

fn verify(record: &Record, derived: &Derived, now: DateTime<Utc>) -> String {
    if record.verify.is_empty() {
        return String::from("-");
    }
    let parts: Vec<String> = record
        .verify
        .iter()
        .enumerate()
        .map(|(i, c)| condition_text(c, derived.verify.get(i), now))
        .collect();
    escape_cell(&parts.join("; "))
}

fn last_verified(record: &Record, derived: &Derived, now: DateTime<Utc>) -> String {
    let mut text = match (derived.last_verified, &derived.last_verified_by) {
        (Some(at), Some(by)) => format!("{} ago by {}", age(at, now), escape_cell(by)),
        (Some(at), None) => format!("{} ago", age(at, now)),
        (None, _) => String::new(),
    };
    if record.verify.is_empty() && record.blocked_on.is_empty() {
        text = String::from("nothing to verify");
    } else if derived.last_verified.is_none() {
        text = String::from("**NEVER VERIFIED**");
    }
    if derived.stale {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str("**STALE**");
    }
    text
}

/// The Markdown board. `generated_at` is the only wall-clock value in the body besides the ages,
/// which are relative to it, so the same inputs and `generated_at` give the same bytes.
#[must_use]
pub fn render_markdown(views: &[View], generated_at: DateTime<Utc>) -> String {
    let mut out = format!(
        "# Shared state\n\ngenerated_at: {}\n\n",
        generated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    out.push_str("| id | title | owner | state | blocked on | verify | last verified |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for (record, derived) in sorted(views) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            escape_cell(&record.id),
            escape_cell(&record.title),
            escape_cell(&record.owner),
            name(&record.state),
            blocked_on(record, derived, generated_at),
            verify(record, derived, generated_at),
            last_verified(record, derived, generated_at),
        ));
    }
    out
}

/// The same data as JSON, for board tooling: `{generated_at, records: [record + derived]}`.
#[must_use]
pub fn render_json(views: &[View], generated_at: DateTime<Utc>) -> serde_json::Value {
    let records: Vec<serde_json::Value> = sorted(views)
        .into_iter()
        .map(|(record, derived)| {
            let mut value = json!(record);
            value["derived"] = json!(derived);
            value
        })
        .collect();
    json!({
        "generated_at": generated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "records": records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Caller, MemoryState, NewRecord, State, StateStore};
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap()
    }

    #[test]
    fn escape_neutralises_markup_rows_and_bidi() {
        let e = escape_cell("a|b\n[x](http://e)<b>\u{202e}`c`");
        assert!(!e.contains('\n') && !e.contains('\u{202e}'));
        assert!(e.contains("\\|") && e.contains("\\[") && e.contains("\\<") && e.contains("\\`"));
    }

    #[test]
    fn ids_sort_numerically() {
        assert!(id_number("T-2") < id_number("T-10"));
        assert_eq!(id_number("weird"), u64::MAX);
    }

    fn view_with(verify: Vec<Condition>, state: State) -> View {
        let store = MemoryState::in_memory();
        let who = Caller {
            role: "a".into(),
            write: true,
            admin: false,
            read_all: false,
            derive: false,
        };
        let new: NewRecord = serde_json::from_value(json!({
            "title": "Ship | it now",
            "parties": ["a"], "owner": "a",
            "state": state, "verify": verify,
        }))
        .unwrap();
        store.create(&who, new, now()).unwrap();
        store.get_view(&who, "T-1", now()).unwrap().unwrap()
    }

    #[test]
    fn unverified_and_stale_rows_are_marked_and_text_is_escaped() {
        let c: Condition = serde_json::from_value(
            json!({"fact": "pr_state:o/r#1", "op": "eq", "value": "merged"}),
        )
        .unwrap();
        let md = render_markdown(&[view_with(vec![c], State::Open)], now());
        assert!(md.contains("**NEVER VERIFIED**"), "{md}");
        assert!(md.contains("**STALE**"), "{md}");
        assert!(md.contains("not observed"), "{md}");
        assert!(md.contains("Ship \\| it now"), "{md}");
    }

    #[test]
    fn a_record_with_nothing_to_verify_is_not_called_unverified() {
        let md = render_markdown(&[view_with(vec![], State::Open)], now());
        assert!(
            md.contains("nothing to verify") && !md.contains("NEVER"),
            "{md}"
        );
    }

    #[test]
    fn output_is_deterministic_and_json_matches() {
        let v = [view_with(vec![], State::Open)];
        assert_eq!(render_markdown(&v, now()), render_markdown(&v, now()));
        let j = render_json(&v, now());
        assert_eq!(j["records"][0]["id"], "T-1");
        assert_eq!(j["generated_at"], "2026-11-13T12:00:00Z");
    }
}
