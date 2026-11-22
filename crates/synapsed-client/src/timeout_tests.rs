// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rules of `docs/CLIENT_TIMEOUTS_DESIGN.md` against a fake daemon. These test `locate` and `call`
//! directly and never `connect`, so a broken rule cannot start a real `synapsed`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::*;

struct Fake {
    addr: String,
    instance_id: String,
    health_delay_ms: Arc<AtomicU64>,
    health_hits: Arc<AtomicU32>,
    /// How many of the next `/v1/send` connections to drop without a reply.
    drop_sends: Arc<AtomicU32>,
    sends: Arc<AtomicU32>,
    clears: Arc<AtomicU32>,
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            while buf.len() < end + 4 + len {
                let n = stream.read(&mut chunk).ok()?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let first = head.lines().next()?.to_string();
            return Some((first, head));
        }
    }
}

fn reply(stream: &mut TcpStream, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn fake() -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let instance_id = hex(&[7u8; 16]);
    let f = Fake {
        addr: addr.clone(),
        instance_id: instance_id.clone(),
        health_delay_ms: Arc::new(AtomicU64::new(0)),
        health_hits: Arc::new(AtomicU32::new(0)),
        drop_sends: Arc::new(AtomicU32::new(0)),
        sends: Arc::new(AtomicU32::new(0)),
        clears: Arc::new(AtomicU32::new(0)),
    };
    let (delay, hits, drops, sends, clears) = (
        f.health_delay_ms.clone(),
        f.health_hits.clone(),
        f.drop_sends.clone(),
        f.sends.clone(),
        f.clears.clone(),
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (addr, instance_id) = (addr.clone(), instance_id.clone());
            let (delay, hits, drops, sends, clears) = (
                delay.clone(),
                hits.clone(),
                drops.clone(),
                sends.clone(),
                clears.clone(),
            );
            std::thread::spawn(move || {
                let Some((first, _)) = read_request(&mut stream) else {
                    return;
                };
                if first.contains("/v1/health") {
                    hits.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(delay.load(Ordering::SeqCst)));
                    let challenge = first
                        .split("challenge=")
                        .nth(1)
                        .and_then(|c| c.split(' ').next())
                        .and_then(unhex::<16>)
                        .unwrap();
                    let key = ring::hmac::Key::new(
                        ring::hmac::HMAC_SHA256,
                        &unhex::<16>(&instance_id).unwrap(),
                    );
                    let mut msg = format!("synapsed-health-v1\n{addr}\n").into_bytes();
                    msg.extend_from_slice(&challenge);
                    let proof = hex(ring::hmac::sign(&key, &msg).as_ref());
                    let started = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
                    reply(
                        &mut stream,
                        &format!(r#"{{"ok":true,"proof":"{proof}","started_at":"{started}"}}"#),
                    );
                } else if first.contains("/v1/send") {
                    sends.fetch_add(1, Ordering::SeqCst);
                    let left = drops.load(Ordering::SeqCst);
                    if left > 0 {
                        drops.store(left - 1, Ordering::SeqCst);
                        return; // closed without a reply
                    }
                    reply(&mut stream, r#"{"outcome":"queued"}"#);
                } else if first.contains("/v1/launch-clear") {
                    clears.fetch_add(1, Ordering::SeqCst);
                    // closed without a reply
                } else {
                    reply(&mut stream, "{}");
                }
            });
        }
    });
    f
}

fn announce_for(f: &Fake, pid: u32) -> Announce {
    Announce {
        addr: f.addr.clone(),
        instance_id: f.instance_id.clone(),
        pid,
    }
}

fn write_announce(home: &Path, f: &Fake, pid: u32) {
    let path = home.join(ANNOUNCE_FILE);
    std::fs::write(
        &path,
        format!(
            r#"{{"addr":"{}","instance_id":"{}","pid":{pid}}}"#,
            f.addr, f.instance_id
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// A connection to the fake with a cached session for `alice`, so `call` needs no claim.
fn connected(f: &Fake, home: &Path) -> Daemon {
    let cached = Cached {
        instance_id: f.instance_id.clone(),
        token: "t".into(),
        global_id: "alice@acct".into(),
        epoch: 1,
    };
    save_session(home, "alice", &cached).unwrap();
    Daemon::new(
        Daemon::http_client().unwrap(),
        home,
        (announce_for(f, std::process::id()), Utc::now()),
        Mutex::new(Estimator::new()),
    )
}

#[test]
fn a_slow_health_answer_from_a_live_pid_is_waited_for_and_not_read_as_down() {
    let f = fake();
    f.health_delay_ms.store(2_600, Ordering::SeqCst);
    let home = tempfile::tempdir().unwrap();
    write_announce(home.path(), &f, std::process::id());
    let http = Daemon::http_client().unwrap();
    let est = Mutex::new(Estimator::new());
    let mut squat = Squat::default();
    let found = locate(&http, home.path(), &mut squat, &est).unwrap();
    assert!(
        matches!(found, Located::Found(_)),
        "the first 2 s probe timed out, the daemon was alive, and the longer second probe got its answer"
    );
    assert!(
        f.health_hits.load(Ordering::SeqCst) >= 2,
        "it probed again instead of giving up"
    );
    assert!(
        lock_estimator(&est).allowance() > FLOOR_FOR_TEST,
        "the allowance grew after the slow answer"
    );
}

const FLOOR_FOR_TEST: Duration = crate::timeout::FLOOR;

#[test]
fn a_dead_pid_in_the_announce_file_is_nothing_at_once_not_a_wait() {
    let f = fake();
    let home = tempfile::tempdir().unwrap();
    // A pid that is not running: the announce file is stale.
    write_announce(home.path(), &f, 0x7fff_fff0);
    let http = Daemon::http_client().unwrap();
    let est = Mutex::new(Estimator::new());
    let started = Instant::now();
    let found = locate(&http, home.path(), &mut Squat::default(), &est).unwrap();
    assert!(matches!(found, Located::Nothing));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "no wait for a dead daemon"
    );
    assert_eq!(
        f.health_hits.load(Ordering::SeqCst),
        0,
        "a dead pid is not even probed"
    );
}

#[test]
fn a_send_that_is_dropped_twice_is_repeated_and_lands() {
    let f = fake();
    f.drop_sends.store(2, Ordering::SeqCst);
    let home = tempfile::tempdir().unwrap();
    let daemon = connected(&f, home.path());
    let body = json!({"to": "bob@acct", "message_id": "m1", "body_b64": B64.encode(b"x")});
    let got = daemon.call("alice", "/v1/send", Some(&body)).unwrap();
    assert_eq!(got["outcome"], "queued");
    assert_eq!(
        f.sends.load(Ordering::SeqCst),
        3,
        "two drops, then the third try"
    );
}

#[test]
fn a_call_that_must_not_repeat_is_tried_once_and_the_failure_names_the_timeout() {
    let f = fake();
    let home = tempfile::tempdir().unwrap();
    let daemon = connected(&f, home.path());
    let err = daemon
        .call("alice", "/v1/launch-clear", Some(&json!({"role": "bob"})))
        .unwrap_err();
    assert_eq!(
        f.clears.load(Ordering::SeqCst),
        1,
        "a launch call is never repeated"
    );
    let text = err.to_string();
    assert!(
        text.contains("phase=call")
            && text.contains("kind=")
            && text.contains("timeout_ms=30000")
            && text.contains("attempt=1/1"),
        "{text}"
    );
}

#[test]
fn a_send_that_keeps_failing_gives_up_after_the_tries_and_says_which() {
    let f = fake();
    f.drop_sends.store(100, Ordering::SeqCst);
    let home = tempfile::tempdir().unwrap();
    let daemon = connected(&f, home.path());
    let body = json!({"to": "bob@acct", "message_id": "m2", "body_b64": B64.encode(b"x")});
    let err = daemon.call("alice", "/v1/send", Some(&body)).unwrap_err();
    assert_eq!(
        f.sends.load(Ordering::SeqCst),
        4,
        "one try and three repeats"
    );
    assert!(err.to_string().contains("attempt=4/4"), "{err}");
}

#[test]
fn a_call_teaches_the_average_and_a_long_poll_does_not() {
    let f = fake();
    let home = tempfile::tempdir().unwrap();
    let daemon = connected(&f, home.path());
    assert!(lock_estimator(&daemon.estimator).smoothed().is_none());
    let body = json!({"to": "bob@acct", "message_id": "m3", "body_b64": B64.encode(b"x")});
    daemon.call("alice", "/v1/send", Some(&body)).unwrap();
    assert!(
        lock_estimator(&daemon.estimator).smoothed().is_some(),
        "a finished call is a sample"
    );
    let fresh = connected(&f, home.path());
    daemon.call("alice", "/v1/waiting?wait=1", None).unwrap();
    fresh.call("alice", "/v1/waiting?wait=1", None).unwrap();
    assert!(
        lock_estimator(&fresh.estimator).smoothed().is_none(),
        "a poll that waits by design says nothing about load"
    );
}

#[test]
fn a_fresh_latency_file_raises_the_first_probe_and_a_stale_or_bad_one_is_the_floor() {
    let home = tempfile::tempdir().unwrap();
    let file = home.path().join(LATENCY_FILE);
    let write = |at: DateTime<Utc>, smoothed: u64| {
        std::fs::write(
            &file,
            format!(
                r#"{{"smoothed_ms":{smoothed},"deviation_ms":500,"at":"{}"}}"#,
                at.to_rfc3339()
            ),
        )
        .unwrap();
    };
    assert_eq!(
        seed_estimator(home.path()).allowance(),
        crate::timeout::FLOOR,
        "no file"
    );
    write(Utc::now(), 4_000);
    assert!(
        seed_estimator(home.path()).allowance() > crate::timeout::FLOOR,
        "a daemon that is taking 4 s earns a longer first probe"
    );
    write(Utc::now() - chrono::Duration::minutes(5), 4_000);
    assert_eq!(
        seed_estimator(home.path()).allowance(),
        crate::timeout::FLOOR,
        "stale"
    );
    write(Utc::now(), 10_000_000);
    assert_eq!(
        seed_estimator(home.path()).allowance(),
        crate::timeout::CEILING,
        "capped, not trusted"
    );
    std::fs::write(&file, "not json").unwrap();
    assert_eq!(
        seed_estimator(home.path()).allowance(),
        crate::timeout::FLOOR,
        "garbage"
    );
}
