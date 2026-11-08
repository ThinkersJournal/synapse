// SPDX-License-Identifier: MIT OR Apache-2.0
//! Who may see and message whom (docs/ACCESS_CONTROL_DESIGN.md, slice A1; board 384, 385, 388):
//! over real loopback HTTP, default deny for new roles, the one-time legacy grants, `see` and
//! `send` apart, the creator rule, and the daemon's own notices outside the rules.

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use synapse::certificate::{AgentCertificate, Permission, chain_to_pem};
use synapse::keystore::Keystore;
use synapse::roles::{claim_signing_input_v2, sign_claim_for};
use synapsed::{Daemon, DaemonConfig};

struct Running {
    addr: SocketAddr,
    home: tempfile::TempDir,
    started_at: DateTime<Utc>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Running {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Stop the daemon and hand back its home, for a restart on the same state.
    async fn stop(mut self) -> tempfile::TempDir {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.home
    }
}

fn new_home(grants: &[(&str, Permission)]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    Keystore::init_account(home.path(), "acct").expect("init account");
    let store = Keystore::open(home.path()).unwrap();
    for (role, permission) in grants {
        store.grant(role, permission).unwrap();
    }
    home
}

/// Write `<home>/access.json` before the daemon opens the home.
fn seed(home: &tempfile::TempDir, body: &Value) {
    std::fs::write(home.path().join("access.json"), body.to_string()).unwrap();
}

async fn start(home: tempfile::TempDir) -> Running {
    let cfg = DaemonConfig {
        home: home.path().to_path_buf(),
        addr: "127.0.0.1:0".parse().unwrap(),
        sweep_every: Duration::from_secs(3600),
    };
    let daemon = Daemon::open(&cfg)
        .expect("open daemon")
        .with_redelivery_gaps(vec![chrono::Duration::milliseconds(300); 3])
        .with_redelivery_check(Duration::from_millis(50));
    let started_at = daemon.started_at();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(daemon.serve(listener, async move {
        let _ = rx.await;
    }));
    let announce = home.path().join("synapsed.json");
    for _ in 0..200 {
        if announce.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Running {
        addr,
        home,
        started_at,
        stop: Some(tx),
        task: Some(task),
    }
}

fn instance_id(d: &Running) -> String {
    let text = std::fs::read_to_string(d.home.path().join("synapsed.json")).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    v["instance_id"].as_str().unwrap().to_string()
}

async fn post_claim(d: &Running, req: &synapse::roles::ClaimRequest) -> String {
    let body = json!({
        "audience": req.audience,
        "chain_pem": chain_to_pem(&req.chain),
        "nonce_hex": req.nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "signed_at": req.signed_at.to_rfc3339(),
        "signature_b64": B64.encode(&req.signature),
    });
    let reply = reqwest::Client::new()
        .post(d.url("/v1/claim"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = reply.status().as_u16();
    let reply: Value = reply.json().await.unwrap();
    assert_eq!(status, 200, "{reply}");
    reply["session"].as_str().unwrap().to_string()
}

/// Claim `role` the usual way: its certificate is one link, signed by the account key.
async fn claim(d: &Running, role: &str) -> String {
    let store = Keystore::open(d.home.path()).unwrap();
    let identity = store.role(role, Utc::now()).unwrap();
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let req = sign_claim_for(&identity, &instance_id(d), nonce, signed_at).unwrap();
    post_claim(d, &req).await
}

/// Claim `worker.pm@acct`, whose certificate was issued by `pm@acct` (two links, board 388): the
/// root is pm's certificate from the account key, the leaf is signed by pm's key.
async fn claim_sub_agent_of_pm(d: &Running) -> String {
    let pem =
        std::fs::read_to_string(d.home.path().join("account").join("account.key.pem")).unwrap();
    let account_key = {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(&pem).expect("account key")
    };
    let pm_key = SigningKey::from_bytes(
        uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let worker_key = SigningKey::from_bytes(
        uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let now = Utc::now();
    let key_id = |k: &SigningKey| synapse::sender_auth::key_id(&k.verifying_key().to_bytes());
    let cert = |issuer: &SigningKey, label: &str, id: &str, subject: &SigningKey, delegate: u8| {
        AgentCertificate::sign(
            AgentCertificate {
                version: 1,
                serial: *uuid::Uuid::new_v4().as_bytes(),
                issuer_key_id: key_id(issuer),
                subject_label: label.to_string(),
                subject_global_id: id.to_string(),
                subject_signing_key: subject.verifying_key().to_bytes(),
                subject_sealing_key: [7; 32],
                not_before: now - chrono::Duration::minutes(5),
                not_after: now + chrono::Duration::hours(1),
                permissions: vec![Permission::Send, Permission::Ack],
                may_delegate: delegate,
                signature: [0; 64],
            },
            issuer,
        )
    };
    let root = cert(&account_key, "pm", "pm@acct", &pm_key, 1);
    let leaf = cert(&pm_key, "worker", "worker.pm@acct", &worker_key, 0);
    let signed_at = (Utc::now().max(d.started_at + chrono::Duration::seconds(1))).trunc_subsecs(0);
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let text = claim_signing_input_v2("worker.pm@acct", &instance_id(d), &nonce, signed_at);
    let req = synapse::roles::ClaimRequest {
        chain: vec![leaf, root],
        nonce,
        signed_at,
        signature: worker_key.sign(text.as_bytes()).to_bytes().to_vec(),
        audience: Some(instance_id(d)),
    };
    post_claim(d, &req).await
}

async fn call(d: &Running, token: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let req = match &body {
        Some(b) => client.post(d.url(path)).json(b),
        None => client.get(d.url(path)),
    };
    let resp = req.bearer_auth(token).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn send(d: &Running, token: &str, to: &str, text: &str) -> (u16, Value) {
    call(
        d,
        token,
        "/v1/send",
        Some(json!({"to": to, "body_b64": B64.encode(text.as_bytes())})),
    )
    .await
}

async fn visible(d: &Running, token: &str) -> Vec<String> {
    let (status, reply) = call(d, token, "/v1/list?include_retired=true", None).await;
    assert_eq!(status, 200, "{reply}");
    let mut ids: Vec<String> = reply["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["global_id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

async fn fetch(d: &Running, token: &str) -> Vec<Value> {
    let (status, reply) = call(d, token, "/v1/fetch", Some(json!({"lease_secs": 5}))).await;
    assert_eq!(status, 200, "{reply}");
    reply["messages"].as_array().cloned().unwrap_or_default()
}

fn grant(principal: &str, actions: &[&str], objects: &[&str]) -> Value {
    json!({"principal": principal, "actions": actions, "objects": objects})
}

#[tokio::test]
async fn a_new_role_can_neither_see_nor_message_anyone() {
    let d = start(new_home(&[])).await;
    let a = claim(&d, "a").await;
    let _b = claim(&d, "b").await;
    assert_eq!(visible(&d, &a).await, ["a@acct"], "only itself");
    let (status, reply) = send(&d, &a, "b@acct", "hi").await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (404, Some("unknown_recipient"))
    );
}

#[tokio::test]
async fn an_upgraded_role_keeps_seeing_and_messaging_every_existing_role() {
    // A home from before access control: roles in the table, no access.json.
    let home = new_home(&[]);
    seed(
        &home,
        &json!({"grants": [grant("*", &["see", "send"], &["agent:*"])]}),
    );
    let d = start(home).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    let home = d.stop().await;
    std::fs::remove_file(home.path().join("access.json")).unwrap();

    let d = start(home).await; // the upgrade: legacy grants written for a and b
    let a = {
        let _ = &a;
        claim(&d, "a").await
    };
    let b = {
        let _ = &b;
        claim(&d, "b").await
    };
    assert_eq!(visible(&d, &a).await, ["a@acct", "b@acct"]);
    assert_eq!(send(&d, &a, "b@acct", "hi").await.0, 200);
    assert_eq!(fetch(&d, &b).await.len(), 1);

    // A lane first claimed after the upgrade is deny-all and unreachable for the old lanes.
    let c = claim(&d, "c").await;
    assert_eq!(visible(&d, &c).await, ["c@acct"]);
    assert_eq!(
        visible(&d, &a).await,
        ["a@acct", "b@acct"],
        "c is not reached by a legacy grant"
    );
    assert_eq!(
        send(&d, &a, "c@acct", "hi").await.1["error"],
        "unknown_recipient"
    );
    let text = std::fs::read_to_string(d.home.path().join("access.json")).unwrap();
    assert!(text.contains("\"legacy\": true"), "tagged legacy: {text}");
}

#[tokio::test]
async fn the_upgrade_migration_runs_once() {
    let home = new_home(&[]);
    seed(
        &home,
        &json!({"grants": [grant("*", &["see", "send"], &["agent:*"])]}),
    );
    let d = start(home).await;
    let _a = claim(&d, "a").await;
    let home = d.stop().await;
    std::fs::remove_file(home.path().join("access.json")).unwrap();

    let d = start(home).await; // writes legacy grants for a
    let _b = claim(&d, "b").await; // new after the upgrade
    let first = std::fs::read_to_string(d.home.path().join("access.json")).unwrap();
    let home = d.stop().await;
    let d = start(home).await; // a restart must not write them again, nor widen to b
    let second = std::fs::read_to_string(d.home.path().join("access.json")).unwrap();
    assert_eq!(first, second, "the file is the record that the upgrade ran");
    assert!(
        !second.contains("agent:b@acct"),
        "b never got a legacy grant: {second}"
    );
}

#[tokio::test]
async fn see_does_not_imply_send_and_send_does_not_imply_see() {
    let home = new_home(&[]);
    seed(
        &home,
        &json!({"grants": [
            grant("a@acct", &["see"], &["agent:b@acct"]),
            grant("c@acct", &["send"], &["agent:b@acct"]),
        ]}),
    );
    let d = start(home).await;
    let a = claim(&d, "a").await;
    let c = claim(&d, "c").await;
    let _b = claim(&d, "b").await;

    // a sees b but may not message it: a typed refusal that names the missing action.
    assert_eq!(visible(&d, &a).await, ["a@acct", "b@acct"]);
    let (status, reply) = send(&d, &a, "b@acct", "hi").await;
    assert_eq!((status, reply["error"].as_str()), (403, Some("forbidden")));
    assert!(
        reply["message"].as_str().unwrap().contains("synapse:send"),
        "{reply}"
    );

    // c may send to b but cannot see it, so the send reads as an unknown recipient.
    assert_eq!(visible(&d, &c).await, ["c@acct"]);
    let (status, reply) = send(&d, &c, "b@acct", "hi").await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (404, Some("unknown_recipient"))
    );
}

#[tokio::test]
async fn send_to_an_unseen_role_is_indistinguishable_from_absent() {
    let d = start(new_home(&[])).await;
    let a = claim(&d, "a").await;
    let _b = claim(&d, "b").await;
    let (real_status, real) = send(&d, &a, "b@acct", "hi").await;
    let (absent_status, absent) = send(&d, &a, "nobody@acct", "hi").await;
    assert_eq!(real_status, absent_status);
    assert_eq!(real["error"], absent["error"]);
    let shape = |v: &Value, name: &str| v["message"].as_str().unwrap().replace(name, "<role>");
    assert_eq!(shape(&real, "b@acct"), shape(&absent, "nobody@acct"));
}

#[tokio::test]
async fn list_hides_roles_the_caller_may_not_see() {
    let home = new_home(&[]);
    seed(
        &home,
        &json!({"grants": [grant("a@acct", &["see"], &["agent:b@acct"])]}),
    );
    let d = start(home).await;
    let a = claim(&d, "a").await;
    let _b = claim(&d, "b").await;
    let _c = claim(&d, "c").await;
    assert_eq!(visible(&d, &a).await, ["a@acct", "b@acct"]);
    let (_, stats) = call(&d, &a, "/v1/stats", None).await;
    let ids: Vec<&str> = stats["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["global_id"].as_str().unwrap())
        .collect();
    assert!(
        !ids.contains(&"c@acct"),
        "stats follow the same filter: {ids:?}"
    );
}

#[tokio::test]
async fn queued_mail_survives_a_revoke() {
    let home = new_home(&[]);
    seed(
        &home,
        &json!({"grants": [grant("a@acct", &["see", "send"], &["agent:b@acct"])]}),
    );
    let d = start(home).await;
    let a = claim(&d, "a").await;
    let _b = claim(&d, "b").await;
    assert_eq!(send(&d, &a, "b@acct", "before").await.0, 200);

    // Revoke: the rule is removed and the daemon restarted on the same state.
    let home = d.stop().await;
    let path = home.path().join("access.json");
    let mut state: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    state["grants"] = json!([]);
    std::fs::write(&path, state.to_string()).unwrap();
    let d = start(home).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    assert_eq!(
        send(&d, &a, "b@acct", "after").await.0,
        404,
        "new sends are refused"
    );
    let got = fetch(&d, &b).await;
    assert_eq!(got.len(), 1, "mail queued before the revoke is kept");
    assert_eq!(
        B64.decode(got[0]["body_b64"].as_str().unwrap()).unwrap(),
        b"before"
    );
}

#[tokio::test]
async fn daemon_notices_ignore_the_rules() {
    // a may message b and nothing else: no rule mentions the daemon's own sender.
    let home = new_home(&[]);
    seed(
        &home,
        &json!({"grants": [grant("a@acct", &["see", "send"], &["agent:b@acct"])]}),
    );
    let d = start(home).await;
    let a = claim(&d, "a").await;
    let b = claim(&d, "b").await;
    assert_eq!(
        send(&d, &a, "b@acct", "[STATUS] lane=a doing=x").await.0,
        200
    );
    for _ in 0..3 {
        assert_eq!(fetch(&d, &b).await.len(), 1);
        tokio::time::sleep(Duration::from_millis(350)).await;
    }
    let mut notice = Vec::new();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        notice = fetch(&d, &a).await;
        if !notice.is_empty() {
            break;
        }
    }
    assert_eq!(notice.len(), 1, "the [UNACKED] notice reaches a");
    assert_eq!(notice[0]["from"], "synapsed@acct");
}

#[tokio::test]
async fn a_new_sub_agent_is_invisible_to_a_third_agent_and_visible_to_its_creator_and_the_account_holder()
 {
    let home = new_home(&[("root", Permission::RoleAdmin)]);
    // c may see and message b only. pm is a plain lane with no rules at all.
    seed(
        &home,
        &json!({"grants": [grant("c@acct", &["see", "send"], &["agent:b@acct"])]}),
    );
    let d = start(home).await;
    let root = claim(&d, "root").await;
    let pm = claim(&d, "pm").await;
    let c = claim(&d, "c").await;
    let _b = claim(&d, "b").await;
    let worker = claim_sub_agent_of_pm(&d).await;

    // Its creator and the account holder see it, and a send from them is queued (A3: a dotted id
    // such as worker.pm@acct is a well-formed address, `keystore::valid_role_id`).
    assert!(
        visible(&d, &pm)
            .await
            .contains(&"worker.pm@acct".to_string())
    );
    assert!(
        visible(&d, &root)
            .await
            .contains(&"worker.pm@acct".to_string())
    );
    for token in [&pm, &root] {
        let (status, reply) = send(&d, token, "worker.pm@acct", "task").await;
        assert_eq!(status, 200, "the send is queued: {reply}");
    }
    let _ = &worker;

    // A third agent does not see it, and a send to it reads as an unknown recipient.
    assert!(
        !visible(&d, &c)
            .await
            .contains(&"worker.pm@acct".to_string())
    );
    let (status, reply) = send(&d, &c, "worker.pm@acct", "hi").await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (404, Some("unknown_recipient"))
    );
}

#[tokio::test]
async fn a_sub_agent_provisioned_directly_has_no_creator() {
    let d = start(new_home(&[("root", Permission::RoleAdmin)])).await;
    let _root = claim(&d, "root").await;
    let _direct = claim(&d, "direct").await;
    let state: Value =
        serde_json::from_str(&std::fs::read_to_string(d.home.path().join("access.json")).unwrap())
            .unwrap();
    assert_eq!(
        state["created_by"],
        json!({}),
        "a one-link chain records no creator"
    );
}

/// A3: the whole path with real keys and no hand-built certificate. pm holds `role-admin`, so its
/// own certificate carries a delegation budget; it issues a certificate for `worker` with
/// `Keystore::delegate`; the sub-agent claims `worker.pm@acct` with that chain; pm mails it and the
/// mail is queued (the dotted address is well formed); a third agent neither sees nor reaches it.
#[tokio::test]
async fn a_chain_issued_sub_agent_can_be_mailed_by_its_creator() {
    let d = start(new_home(&[("pm", Permission::RoleAdmin)])).await;
    let pm = claim(&d, "pm").await;
    let c = claim(&d, "c").await;

    let store = Keystore::open(d.home.path()).unwrap();
    let worker_key = SigningKey::from_bytes(
        uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let keys = synapse::keystore::RolePublicKeys {
        signing: worker_key.verifying_key().to_bytes(),
        sealing: [7; 32],
    };
    let pem = store
        .delegate(
            "pm",
            "worker",
            keys,
            &[Permission::Send, Permission::Ack],
            Utc::now(),
            chrono::Duration::hours(1),
        )
        .expect("pm holds role-admin, so it may delegate");
    let chain = synapse::certificate::chain_from_pem(&pem).unwrap();
    let signed_at = (Utc::now().max(d.started_at + chrono::Duration::seconds(1))).trunc_subsecs(0);
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let text = claim_signing_input_v2("worker.pm@acct", &instance_id(&d), &nonce, signed_at);
    let req = synapse::roles::ClaimRequest {
        chain,
        nonce,
        signed_at,
        signature: worker_key.sign(text.as_bytes()).to_bytes().to_vec(),
        audience: Some(instance_id(&d)),
    };
    let _worker = post_claim(&d, &req).await;

    let (status, reply) = send(&d, &pm, "worker.pm@acct", "task").await;
    assert_eq!(status, 200, "its creator mails it: {reply}");
    assert!(
        !visible(&d, &c)
            .await
            .contains(&"worker.pm@acct".to_string()),
        "a third agent does not see it"
    );
    let (status, reply) = send(&d, &c, "worker.pm@acct", "hi").await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (404, Some("unknown_recipient"))
    );
}

/// A3 (b): the sub-agent claims from a home of its own, which never held the account key: its keys
/// are made there, its creator's `delegate` chain is installed, `load_role` reads it, and the claim
/// it signs is accepted. Its creator's mail to `worker.pm@acct` reaches it.
#[tokio::test]
async fn a_sub_agent_claims_from_its_own_home_and_receives_its_creators_mail() {
    let d = start(new_home(&[("pm", Permission::RoleAdmin)])).await;
    let pm = claim(&d, "pm").await;

    let sub_home = tempfile::tempdir().unwrap();
    let keys = Keystore::init_role(sub_home.path(), "acct", "worker").unwrap();
    let store = Keystore::open(d.home.path()).unwrap();
    let pem = store
        .delegate(
            "pm",
            "worker",
            keys,
            &[Permission::Send, Permission::Ack],
            Utc::now(),
            chrono::Duration::hours(1),
        )
        .unwrap();
    Keystore::install_role_certificate(sub_home.path(), "worker", &pem).unwrap();

    let identity = synapse::keystore::load_role(sub_home.path(), "worker", Utc::now()).unwrap();
    assert_eq!(identity.global_id, "worker.pm@acct");
    let signed_at = Utc::now().max(d.started_at + chrono::Duration::seconds(1));
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let req = sign_claim_for(&identity, &instance_id(&d), nonce, signed_at).unwrap();
    let worker = post_claim(&d, &req).await;

    let (status, reply) = send(&d, &pm, "worker.pm@acct", "task").await;
    assert_eq!(status, 200, "{reply}");
    let got = fetch(&d, &worker).await;
    assert_eq!(got.len(), 1, "the sub-agent receives the mail");
    assert_eq!(got[0]["from"], "pm@acct");
}
