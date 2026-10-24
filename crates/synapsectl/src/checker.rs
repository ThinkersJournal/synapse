// SPDX-License-Identifier: MIT OR Apache-2.0
//! The shared-state checker (design: docs/superpowers/specs/2026-10-23-shared-state-design.md,
//! section 7, slice S4b): the one process that answers forge facts for the state store. It asks the
//! daemon which facts the open records name (`GET /v1/state/wanted`), looks each up from the forge,
//! and reports what it saw (`POST /v1/state/facts`). It needs the `state-derive` grant, which no
//! lane holds; a lane can say "I am waiting on PR 238" but cannot say "PR 238 is merged".
//!
//! The forge credential comes from a [`TokenSource`], asked for a token on every request: today an
//! environment variable, later whatever mints a read-only GitHub App installation token (those
//! expire hourly, which is why the token is never cached here). A token is sent only over HTTPS or
//! to loopback, and only to the GitHub base URL, never to crates.io.

use std::time::Duration;

use serde_json::Value;
use synapse::state::{FactSpec, Look};
use synapsed_client::{Daemon, MailError};

/// Where the forge token comes from. Asked once per request.
pub trait TokenSource {
    fn token(&self) -> Option<String>;
}

/// A token in an environment variable (empty or unset: none, so GitHub's unauthenticated limits apply).
pub struct EnvToken(pub String);

impl TokenSource for EnvToken {
    fn token(&self) -> Option<String> {
        std::env::var(&self.0).ok().filter(|t| !t.trim().is_empty())
    }
}

/// The forge, as the checker sees it.
pub struct Forge {
    http: reqwest::blocking::Client,
    crates_url: String,
    github_url: String,
    token: Box<dyn TokenSource>,
}

/// A bearer token goes over HTTPS, or to loopback (a test stub), and nowhere else.
fn may_send_token(url: &str) -> bool {
    url.starts_with("https://")
        || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|h| url.starts_with(h))
}

impl Forge {
    pub fn new(
        crates_url: &str,
        github_url: &str,
        token: Box<dyn TokenSource>,
    ) -> Result<Forge, MailError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("synapse-state-checker/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| MailError::Usage(format!("cannot build an HTTP client: {e}")))?;
        Ok(Forge {
            http,
            crates_url: crates_url.trim_end_matches('/').to_string(),
            github_url: github_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    /// GET `url`; the status and the JSON body (`Null` if it is not JSON). A transport failure is
    /// an error with no URL in it.
    fn get(&self, url: &str, github: bool) -> Result<(u16, Value), String> {
        let mut req = self.http.get(url);
        if github {
            req = req
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            if may_send_token(url)
                && let Some(token) = self.token.token()
            {
                req = req.bearer_auth(token);
            }
        }
        let resp = req.send().map_err(|e| e.without_url().to_string())?;
        let status = resp.status().as_u16();
        let body = resp.json::<Value>().unwrap_or(Value::Null);
        Ok((status, body))
    }

    /// Look one fact up.
    pub fn look(&self, fact: &FactSpec) -> Look {
        let text = fact.as_str();
        let Some((kind, rest)) = text.split_once(':') else {
            return Look::Failed("not a fact".into());
        };
        let (url, github, interpret): (String, bool, fn(u16, &Value) -> Look) = match kind {
            "crate_version" => (
                format!("{}/api/v1/crates/{rest}", self.crates_url),
                false,
                crate_look,
            ),
            "pr_state" => {
                let Some((repo, n)) = rest.split_once('#') else {
                    return Look::Failed("not a fact".into());
                };
                (
                    format!("{}/repos/{repo}/pulls/{n}", self.github_url),
                    true,
                    pr_look,
                )
            }
            "ref_sha" => {
                let Some((repo, branch)) = rest.split_once('@') else {
                    return Look::Failed("not a fact".into());
                };
                (
                    format!("{}/repos/{repo}/commits/{branch}", self.github_url),
                    true,
                    ref_look,
                )
            }
            "check_state" => {
                let Some((repo, sha)) = rest.split_once('@') else {
                    return Look::Failed("not a fact".into());
                };
                (
                    format!(
                        "{}/repos/{repo}/commits/{sha}/check-runs?per_page=100",
                        self.github_url
                    ),
                    true,
                    checks_look,
                )
            }
            "file_at_ref" => {
                let Some((repo, tail)) = rest.split_once('@') else {
                    return Look::Failed("not a fact".into());
                };
                let Some((git_ref, path)) = tail.split_once(':') else {
                    return Look::Failed("not a fact".into());
                };
                (
                    format!(
                        "{}/repos/{repo}/contents/{path}?ref={git_ref}",
                        self.github_url
                    ),
                    true,
                    file_look,
                )
            }
            _ => return Look::Failed("unknown fact kind".into()),
        };
        match self.get(&url, github) {
            Ok((status, body)) => interpret(status, &body),
            Err(e) => Look::Failed(format!("request failed: {e}")),
        }
    }
}

fn failed(status: u16) -> Look {
    match status {
        403 | 429 => Look::Failed(format!("HTTP {status} (rate limited or not permitted)")),
        _ => Look::Failed(format!("HTTP {status}")),
    }
}

/// `GET /api/v1/crates/<crate>`: the highest non-yanked version. 404: no such crate.
pub fn crate_look(status: u16, body: &Value) -> Look {
    match status {
        200 => body["crate"]["max_version"].as_str().map_or_else(
            || Look::Failed("no max_version in the reply".into()),
            |v| Look::Found(v.into()),
        ),
        404 => Look::Absent,
        s => failed(s),
    }
}

/// `GET /repos/<repo>/pulls/<n>`: `merged`, else the PR's own state (`open` or `closed`).
pub fn pr_look(status: u16, body: &Value) -> Look {
    match status {
        200 if !body["merged_at"].is_null() => Look::Found("merged".into()),
        200 => body["state"].as_str().map_or_else(
            || Look::Failed("no state in the reply".into()),
            |s| Look::Found(s.into()),
        ),
        404 => Look::Absent,
        s => failed(s),
    }
}

/// `GET /repos/<repo>/commits/<branch>`: the head SHA. 404 or 422: no such ref.
pub fn ref_look(status: u16, body: &Value) -> Look {
    match status {
        200 => body["sha"].as_str().map_or_else(
            || Look::Failed("no sha in the reply".into()),
            |s| Look::Found(s.into()),
        ),
        404 | 422 => Look::Absent,
        s => failed(s),
    }
}

/// `GET /repos/<repo>/commits/<sha>/check-runs`: `failure` if any run failed, else `pending` if any
/// is unfinished or there are none, else `success`. All check runs count, not only the required
/// ones: the required set is branch protection, a different API.
pub fn checks_look(status: u16, body: &Value) -> Look {
    match status {
        200 => {
            let runs = body["check_runs"].as_array().cloned().unwrap_or_default();
            let bad = |r: &Value| {
                matches!(
                    r["conclusion"].as_str(),
                    Some("failure" | "timed_out" | "cancelled" | "action_required" | "stale")
                )
            };
            let unfinished = |r: &Value| r["status"].as_str() != Some("completed");
            let state = if runs.iter().any(bad) {
                "failure"
            } else if runs.is_empty() || runs.iter().any(unfinished) {
                "pending"
            } else {
                "success"
            };
            Look::Found(state.into())
        }
        404 | 422 => Look::Absent,
        s => failed(s),
    }
}

/// `GET /repos/<repo>/contents/<path>?ref=<ref>`: the blob SHA of a file (`directory` for a
/// directory, which has no single blob). 404: absent at that ref.
pub fn file_look(status: u16, body: &Value) -> Look {
    match status {
        200 if body.is_array() => Look::Found("directory".into()),
        200 => body["sha"].as_str().map_or_else(
            || Look::Failed("no sha in the reply".into()),
            |s| Look::Found(s.into()),
        ),
        404 => Look::Absent,
        s => failed(s),
    }
}

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub found: usize,
    pub absent: usize,
    pub failed: usize,
}

/// Facts per report request.
const BATCH: usize = 100;

/// One pass: ask the daemon what is wanted, look each fact up, report. The daemon decides what a
/// report means (`satisfied`, `stale`); the checker only says what it saw.
pub fn check_once(daemon: &Daemon, role: &str, forge: &Forge) -> Result<Pass, MailError> {
    let wanted = daemon.call(role, "/v1/state/wanted", None)?;
    let mut pass = Pass::default();
    let mut reports = Vec::new();
    for text in wanted["facts"].as_array().into_iter().flatten() {
        let Some(fact) = text.as_str().and_then(|t| FactSpec::parse(t).ok()) else {
            continue;
        };
        let look = forge.look(&fact);
        match look {
            Look::Found(_) => pass.found += 1,
            Look::Absent => pass.absent += 1,
            Look::Failed(_) => pass.failed += 1,
        }
        reports.push(serde_json::json!({ "fact": fact.as_str(), "look": look }));
    }
    for chunk in reports.chunks(BATCH) {
        daemon.call(
            role,
            "/v1/state/facts",
            Some(&serde_json::json!({ "reports": chunk })),
        )?;
    }
    Ok(pass)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_crate_is_its_highest_non_yanked_version_or_absent() {
        let body = json!({"crate": {"max_version": "6.0.0-rc.146", "max_stable_version": "1.1.0"}});
        assert_eq!(crate_look(200, &body), Look::Found("6.0.0-rc.146".into()));
        assert_eq!(crate_look(404, &Value::Null), Look::Absent);
        assert!(matches!(crate_look(200, &json!({})), Look::Failed(_)));
        assert!(matches!(crate_look(503, &Value::Null), Look::Failed(t) if t == "HTTP 503"));
    }

    #[test]
    fn a_pr_is_merged_open_or_closed() {
        let merged = json!({"state": "closed", "merged_at": "2026-10-24T01:00:00Z"});
        let closed = json!({"state": "closed", "merged_at": null});
        let open = json!({"state": "open", "merged_at": null});
        assert_eq!(pr_look(200, &merged), Look::Found("merged".into()));
        assert_eq!(pr_look(200, &closed), Look::Found("closed".into()));
        assert_eq!(pr_look(200, &open), Look::Found("open".into()));
        assert_eq!(pr_look(404, &Value::Null), Look::Absent);
    }

    #[test]
    fn a_rate_limit_is_a_failure_never_an_absence() {
        for status in [403, 429, 500, 502] {
            for look in [
                crate_look(status, &Value::Null),
                pr_look(status, &Value::Null),
                ref_look(status, &Value::Null),
                checks_look(status, &Value::Null),
                file_look(status, &Value::Null),
            ] {
                assert!(matches!(look, Look::Failed(_)), "{status}: {look:?}");
            }
        }
    }

    #[test]
    fn check_runs_fold_to_failure_pending_or_success() {
        let run =
            |status: &str, conclusion: Value| json!({"status": status, "conclusion": conclusion});
        let all = |runs: Vec<Value>| checks_look(200, &json!({ "check_runs": runs }));
        assert_eq!(
            all(vec![
                run("completed", json!("success")),
                run("completed", json!("skipped"))
            ]),
            Look::Found("success".into())
        );
        assert_eq!(
            all(vec![
                run("completed", json!("success")),
                run("in_progress", Value::Null)
            ]),
            Look::Found("pending".into())
        );
        assert_eq!(
            all(vec![
                run("completed", json!("failure")),
                run("in_progress", Value::Null)
            ]),
            Look::Found("failure".into()),
            "one failure is a failure even while others run"
        );
        assert_eq!(
            all(vec![]),
            Look::Found("pending".into()),
            "no runs yet is not success"
        );
    }

    #[test]
    fn refs_and_files_answer_with_their_sha_or_absence() {
        assert_eq!(
            ref_look(200, &json!({"sha": "abc"})),
            Look::Found("abc".into())
        );
        assert_eq!(ref_look(422, &Value::Null), Look::Absent);
        assert_eq!(
            file_look(200, &json!({"sha": "def"})),
            Look::Found("def".into())
        );
        assert_eq!(
            file_look(200, &json!([{"name": "a"}])),
            Look::Found("directory".into())
        );
        assert_eq!(file_look(404, &Value::Null), Look::Absent);
    }

    #[test]
    fn a_token_travels_only_over_https_or_to_loopback() {
        assert!(may_send_token("https://api.github.com/repos/o/r"));
        assert!(may_send_token("http://127.0.0.1:8080/repos"));
        assert!(may_send_token("http://localhost:8080/repos"));
        assert!(!may_send_token("http://api.github.com/repos"));
        assert!(!may_send_token("http://evil.example/127.0.0.1"));
        assert!(!may_send_token("ftp://127.0.0.1/"));
    }

    #[test]
    fn an_empty_token_variable_is_no_token() {
        // A name no other test or process sets.
        let name = "SYNAPSE_CHECKER_TEST_TOKEN_UNSET";
        assert_eq!(EnvToken(name.into()).token(), None);
    }
}
