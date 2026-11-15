// SPDX-License-Identifier: MIT OR Apache-2.0
//! `/v1/state/*`: the shared-state store (design: docs/superpowers/specs/2026-10-23-shared-state-design.md,
//! slice S2b) behind the daemon's session auth. A thin binding: the caller is built from the
//! verified session, and access, compare-and-set and validation are the store's, not this file's.

use axum::extract::State;
use synapse::certificate::Permission;
use synapse::state::{
    Caller, Derived, FactReport, Filter, NewRecord, Patch, Record, SignedWrite, StateError,
    StateStore, WriteSig,
};

use super::{
    ApiError, Arc, Bytes, Deserialize, HeaderMap, IntoResponse, Response, SecurityEventKind,
    Session, Shared, StatusCode, Uri, Utc, authed, json, parse, query_param,
};

/// The caller as the session's certificate describes it: never a field of the request.
fn caller(session: &Session) -> Caller {
    let has = |p: Permission| session.permissions.contains(&p);
    Caller {
        role: session
            .global_id
            .split('@')
            .next()
            .unwrap_or_default()
            .to_string(),
        write: has(Permission::StateWrite),
        admin: has(Permission::StateAdmin),
        read_all: has(Permission::StateReadAll),
        derive: has(Permission::StateDerive),
    }
}

fn refuse(shared: &Shared, session: &Session, what: &str, e: StateError) -> ApiError {
    match e {
        StateError::Forbidden => {
            shared.security.emit(
                SecurityEventKind::StateDenied,
                "synapsed/state",
                &session.global_id,
                what,
            );
            ApiError::new(StatusCode::FORBIDDEN, "forbidden", "not allowed")
        }
        StateError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such record"),
        StateError::StaleRevision(current) => {
            let mut error = ApiError::new(
                StatusCode::CONFLICT,
                "stale_revision",
                format!("{} is at revision {}", current.id, current.revision),
            );
            error.body["current"] = json!(current.revision);
            error.body["record"] = json!(*current);
            error
        }
        StateError::Terminal => ApiError::new(StatusCode::CONFLICT, "terminal", e),
        StateError::UnknownBlocker(_) => {
            ApiError::new(StatusCode::BAD_REQUEST, "unknown_blocker", e)
        }
        StateError::Malformed(_) => ApiError::new(StatusCode::BAD_REQUEST, "malformed", e),
        StateError::Store(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "the state store failed",
        ),
    }
}

/// A record as JSON with what is derived about it beside it (`derived`), never stored as typed.
fn with_derived(record: &Record, derived: &Derived) -> serde_json::Value {
    let mut value = json!(record);
    value["derived"] = json!(derived);
    value
}

fn reply(value: serde_json::Value) -> Response {
    axum::Json(value).into_response()
}

/// What a client adds to sign a write (S7): the daemon supplies the rest of the signed text (the
/// signer from the session, its own instance id, the op, the target, the revision and the body it parsed).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigIn {
    nonce: String,
    signed_at: chrono::DateTime<Utc>,
    signature: String,
}

/// Split an optional `sig` off a request body, leaving what the typed request parses.
fn split_sig(mut value: serde_json::Value) -> Result<(serde_json::Value, Option<SigIn>), ApiError> {
    let sig = match value.as_object_mut().and_then(|o| o.remove("sig")) {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(serde_json::from_value::<SigIn>(v).map_err(|e| {
            ApiError::new(StatusCode::BAD_REQUEST, "malformed", format!("sig: {e}"))
        })?),
    };
    Ok((value, sig))
}

fn bad_signature(shared: &Shared, session: &Session, why: &str) -> ApiError {
    shared.security.emit(
        SecurityEventKind::StateDenied,
        "synapsed/state",
        &session.global_id,
        why,
    );
    ApiError::new(StatusCode::FORBIDDEN, "bad_signature", why.to_string())
}

/// Check a client's signature over this write against the session's own key, and that it is fresh
/// and unused. `None` (no `sig`) is an unsigned write, accepted and recorded as unsigned in phase 1.
fn checked_sig<T: serde::Serialize>(
    shared: &Shared,
    session: &Session,
    sig: Option<SigIn>,
    op: &str,
    target: &str,
    expected_revision: u64,
    body: &T,
) -> Result<Option<WriteSig>, ApiError> {
    let Some(sig) = sig else {
        return Ok(None);
    };
    let now = Utc::now();
    let nonce_ok = sig.nonce.len() == 32 && synapse::state::sig_unhex(&sig.nonce).is_some();
    let sig_ok = sig.signature.len() == 128 && synapse::state::sig_unhex(&sig.signature).is_some();
    if !nonce_ok || !sig_ok {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed",
            "sig: nonce is 32 hex characters and signature 128",
        ));
    }
    if !synapse::state::fresh(sig.signed_at, now) || sig.signed_at < shared.started_at {
        return Err(bad_signature(shared, session, "stale signature"));
    }
    let key = synapse::state::sig_hex(&session.signing_key);
    let body_hash = synapse::state::body_hash(body);
    let text = synapse::state::signing_text(&SignedWrite {
        signer: &session.global_id,
        audience: &shared.instance_id,
        op,
        target,
        expected_revision,
        body_hash: &body_hash,
        nonce: &sig.nonce,
        signed_at: sig.signed_at,
    });
    if !synapse::state::verify_text(&key, &text, &sig.signature) {
        return Err(bad_signature(shared, session, "signature does not verify"));
    }
    {
        let mut seen = shared.write_nonces.lock().map_err(|_| {
            ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", "lock")
        })?;
        let horizon = now - chrono::Duration::seconds(synapse::state::WRITE_WINDOW_SECS * 2);
        seen.retain(|_, at| *at > horizon);
        if seen.contains_key(&sig.nonce) {
            return Err(bad_signature(shared, session, "signature already used"));
        }
        seen.insert(sig.nonce.clone(), now);
    }
    Ok(Some(WriteSig {
        signer: session.global_id.clone(),
        audience: shared.instance_id.clone(),
        key,
        nonce: sig.nonce,
        signed_at: sig.signed_at,
        signature: sig.signature,
    }))
}

pub(crate) async fn create(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let (value, sig) = split_sig(parse(&headers, &body)?)?;
    let new: NewRecord = serde_json::from_value(value).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed",
            format!("invalid body: {e}"),
        )
    })?;
    let sig = checked_sig(&shared, &session, sig, "create", "-", 0, &new)?;
    let record = shared
        .state
        .create_signed(&caller(&session), new, sig, Utc::now())
        .map_err(|e| refuse(&shared, &session, "create", e))?;
    shared.state_nudge.notify_one();
    Ok(reply(json!({ "record": record })))
}

pub(crate) async fn get(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let id = query_param(&uri, "id")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "malformed", "id is required"))?;
    // A record the caller may not see is answered like one that does not exist.
    match shared
        .state
        .get_view(&caller(&session), &id, Utc::now())
        .map_err(|e| refuse(&shared, &session, "get", e))?
    {
        Some((record, derived)) => Ok(reply(json!({ "record": with_derived(&record, &derived) }))),
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such record",
        )),
    }
}

pub(crate) async fn list(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let mut filter = Filter::default();
    if let Some(states) = query_param(&uri, "state") {
        for name in states.split(',').filter(|s| !s.is_empty()) {
            let state = serde_json::from_value(json!(name)).map_err(|_| {
                ApiError::new(StatusCode::BAD_REQUEST, "malformed", "unknown state")
            })?;
            filter.states.push(state);
        }
    }
    filter.party = query_param(&uri, "party");
    let records: Vec<serde_json::Value> = shared
        .state
        .list_views(&caller(&session), &filter, Utc::now())
        .map_err(|e| refuse(&shared, &session, "list", e))?
        .iter()
        .map(|(record, derived)| with_derived(record, derived))
        .collect();
    Ok(reply(json!({ "records": records })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchBody {
    id: String,
    expected_revision: u64,
    patch: Patch,
}

pub(crate) async fn patch(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let (value, sig) = split_sig(parse(&headers, &body)?)?;
    let body: PatchBody = serde_json::from_value(value).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed",
            format!("invalid body: {e}"),
        )
    })?;
    let sig = checked_sig(
        &shared,
        &session,
        sig,
        "patch",
        &body.id,
        body.expected_revision,
        &body.patch,
    )?;
    let record = shared
        .state
        .patch_signed(
            &caller(&session),
            &body.id,
            body.expected_revision,
            body.patch,
            sig,
            Utc::now(),
        )
        .map_err(|e| refuse(&shared, &session, "patch", e))?;
    shared.state_nudge.notify_one();
    Ok(reply(json!({ "record": record })))
}

pub(crate) async fn history(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let id = query_param(&uri, "id")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "malformed", "id is required"))?;
    let entries = shared
        .state
        .history(&caller(&session), &id)
        .map_err(|e| refuse(&shared, &session, "history", e))?;
    Ok(reply(json!({ "entries": entries })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactsBody {
    reports: Vec<FactReport>,
}

/// The checker reports what it looked up. `state-derive` only; the reports are facts from the
/// closed registry (the body does not parse otherwise).
pub(crate) async fn facts(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let body: FactsBody = parse(&headers, &body)?;
    let count = body.reports.len();
    shared
        .state
        .report_facts(&caller(&session), body.reports, Utc::now())
        .map_err(|e| refuse(&shared, &session, "facts", e))?;
    // A report may flip a condition: tell the parties now rather than at the next minute.
    let _ = shared.state.refresh_derived(Utc::now());
    shared.state_nudge.notify_one();
    Ok(reply(json!({ "recorded": count })))
}

/// The facts the checker should look up now. `state-derive` only.
pub(crate) async fn wanted(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let facts: Vec<String> = shared
        .state
        .wanted_facts(&caller(&session))
        .map_err(|e| refuse(&shared, &session, "wanted", e))?
        .iter()
        .map(|f| f.as_str().to_string())
        .collect();
    Ok(reply(json!({ "facts": facts })))
}
