// SPDX-License-Identifier: MIT OR Apache-2.0
//! Outcome of a room post that needs acks (messaging step 2, slice c; docs/MESSAGING_SEMANTICS_DESIGN.md
//! section 4). A post sent `room_any` needs one member's ack; `room_all` needs every member's. The members
//! are fixed when the post is sent (the copies that were queued), so a lane that dies or leaves later cannot
//! wedge an all-of. The sender gets exactly one `[ROOM-OUTCOME]` mail per post.
//!
//! An any-of never recalls the other copies once someone acked: they stay queued and are acked or run out
//! like any other mail (a guard from the patent reading, CireSnave 2026-11-21).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

/// How many acks the sender needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    Any,
    All,
}

impl Need {
    fn word(self) -> &'static str {
        match self {
            Need::Any => "any",
            Need::All => "all",
        }
    }
}

/// One post being waited on.
pub(crate) struct Post {
    pub need: Need,
    /// The sender (a global id), who is told.
    pub sender: String,
    /// The sender's own id for the post, without the room suffix.
    pub id: String,
    pub room: String,
    /// The members that were handed a copy, fixed at send time.
    pub members: BTreeSet<String>,
    pub deadline: DateTime<Utc>,
    acked: BTreeSet<String>,
    declined: BTreeSet<String>,
    dead: BTreeSet<String>,
}

impl Post {
    pub fn new(
        need: Need,
        sender: String,
        id: String,
        room: String,
        members: BTreeSet<String>,
        deadline: DateTime<Utc>,
    ) -> Post {
        Post {
            need,
            sender,
            id,
            room,
            members,
            deadline,
            acked: BTreeSet::new(),
            declined: BTreeSet::new(),
            dead: BTreeSet::new(),
        }
    }

    fn pending(&self) -> Vec<&String> {
        self.members
            .iter()
            .filter(|m| {
                !self.acked.contains(*m) && !self.declined.contains(*m) && !self.dead.contains(*m)
            })
            .collect()
    }

    /// The result, once there is one.
    fn result(&self, now: DateTime<Utc>) -> Option<&'static str> {
        let none_pending = self.pending().is_empty();
        let timed_out = now >= self.deadline;
        match self.need {
            Need::Any if !self.acked.is_empty() => Some("acked"),
            Need::Any if none_pending => Some("failed"),
            Need::All if self.acked.len() == self.members.len() => Some("complete"),
            Need::All if none_pending => Some("incomplete"),
            _ if timed_out => Some("timeout"),
            _ => None,
        }
    }
}

/// What the sender is told.
pub(crate) struct Outcome {
    pub sender: String,
    /// The `[ROOM-OUTCOME]` line.
    pub body: String,
}

fn names(set: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    let list: Vec<String> = set
        .into_iter()
        .map(|g| {
            let g = g.as_ref();
            g.split_once('@').map_or(g, |(role, _)| role).to_string()
        })
        .collect();
    if list.is_empty() {
        "-".to_string()
    } else {
        list.join(",")
    }
}

fn outcome(post: &Post, result: &str) -> Outcome {
    Outcome {
        sender: post.sender.clone(),
        body: format!(
            "[ROOM-OUTCOME] room={} id={} mode={} result={result} acked={} declined={} unreachable={} pending={}",
            post.room
                .split_once('@')
                .map_or(post.room.as_str(), |(r, _)| r),
            post.id,
            post.need.word(),
            names(&post.acked),
            names(&post.declined),
            names(&post.dead),
            names(post.pending()),
        ),
    }
}

/// The posts being waited on, keyed by a copy's id (`<sender>/<id>#<room>`, the same for every member).
#[derive(Default)]
pub(crate) struct Tracker {
    posts: BTreeMap<String, Post>,
}

impl Tracker {
    pub fn register(&mut self, copy_id: String, post: Post) {
        self.posts.insert(copy_id, post);
    }

    pub fn tracked(&self, copy_id: &str) -> bool {
        self.posts.contains_key(copy_id)
    }

    fn update(
        &mut self,
        copy_id: &str,
        who: &str,
        now: DateTime<Utc>,
        record: impl FnOnce(&mut Post, &str),
    ) -> Option<Outcome> {
        let post = self.posts.get_mut(copy_id)?;
        if !post.members.contains(who) {
            return None;
        }
        record(post, who);
        let result = post.result(now)?;
        let told = outcome(post, result);
        self.posts.remove(copy_id);
        Some(told)
    }

    pub fn acked(&mut self, copy_id: &str, who: &str, now: DateTime<Utc>) -> Option<Outcome> {
        self.update(copy_id, who, now, |p, w| {
            p.acked.insert(w.to_string());
        })
    }

    pub fn declined(&mut self, copy_id: &str, who: &str, now: DateTime<Utc>) -> Option<Outcome> {
        self.update(copy_id, who, now, |p, w| {
            p.declined.insert(w.to_string());
        })
    }

    /// A copy ran out of deliveries unacked.
    pub fn dead(&mut self, copy_id: &str, who: &str, now: DateTime<Utc>) -> Option<Outcome> {
        self.update(copy_id, who, now, |p, w| {
            p.dead.insert(w.to_string());
        })
    }

    /// Posts whose deadline has passed.
    pub fn expire(&mut self, now: DateTime<Utc>) -> Vec<Outcome> {
        let due: Vec<String> = self
            .posts
            .iter()
            .filter(|(_, p)| p.result(now).is_some())
            .map(|(k, _)| k.clone())
            .collect();
        due.into_iter()
            .filter_map(|k| {
                let post = self.posts.remove(&k)?;
                let result = post.result(now)?;
                Some(outcome(&post, result))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(need: Need, members: &[&str]) -> (Tracker, DateTime<Utc>) {
        let now = Utc::now();
        let mut t = Tracker::default();
        t.register(
            "a@acct/p1#lounge@acct".into(),
            Post::new(
                need,
                "a@acct".into(),
                "p1".into(),
                "lounge@acct".into(),
                members.iter().map(|m| (*m).to_string()).collect(),
                now + chrono::Duration::minutes(5),
            ),
        );
        (t, now)
    }

    const ID: &str = "a@acct/p1#lounge@acct";

    #[test]
    fn any_is_done_at_the_first_ack_and_later_acks_say_nothing() {
        let (mut t, now) = post(Need::Any, &["b@acct", "c@acct"]);
        let told = t.acked(ID, "b@acct", now).expect("first ack ends it");
        assert!(
            told.body.contains("mode=any result=acked acked=b "),
            "{}",
            told.body
        );
        assert!(told.body.ends_with("pending=c"), "{}", told.body);
        assert!(t.acked(ID, "c@acct", now).is_none(), "one outcome per post");
    }

    #[test]
    fn all_waits_for_every_member_and_a_decline_ends_it_incomplete() {
        let (mut t, now) = post(Need::All, &["b@acct", "c@acct"]);
        assert!(t.acked(ID, "b@acct", now).is_none());
        let told = t
            .declined(ID, "c@acct", now)
            .expect("nobody left to wait for");
        assert!(told.body.contains("result=incomplete"), "{}", told.body);
        let (mut t, now) = post(Need::All, &["b@acct", "c@acct"]);
        t.acked(ID, "b@acct", now);
        let told = t.acked(ID, "c@acct", now).unwrap();
        assert!(
            told.body.contains("result=complete acked=b,c "),
            "{}",
            told.body
        );
    }

    #[test]
    fn a_post_nobody_answers_times_out_once_and_a_stranger_changes_nothing() {
        let (mut t, now) = post(Need::All, &["b@acct"]);
        assert!(
            t.acked(ID, "z@acct", now).is_none(),
            "not a member of this post"
        );
        assert!(t.expire(now).is_empty());
        let late = now + chrono::Duration::minutes(6);
        let told = t.expire(late);
        assert_eq!(told.len(), 1);
        assert!(told[0].body.contains("result=timeout"), "{}", told[0].body);
        assert!(told[0].body.ends_with("pending=b"), "{}", told[0].body);
        assert!(t.expire(late).is_empty());
    }

    #[test]
    fn an_all_of_with_a_dead_copy_ends_when_the_rest_answer() {
        let (mut t, now) = post(Need::All, &["b@acct", "c@acct"]);
        assert!(t.dead(ID, "c@acct", now).is_none());
        let told = t.acked(ID, "b@acct", now).unwrap();
        assert!(told.body.contains("result=incomplete"), "{}", told.body);
        assert!(told.body.contains("unreachable=c"), "{}", told.body);
    }
}
