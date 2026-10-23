// SPDX-License-Identifier: MIT OR Apache-2.0
//! `/v1/state/*`: the shared-state store (design: docs/superpowers/specs/2026-10-23-shared-state-design.md,
//! slice S2b) behind the daemon's session auth. A thin binding: the caller is built from the
//! verified session, and access, compare-and-set and validation are the store's, not this file's.

use axum::extract::State;
use synapse::certificate::Permission;
use synapse::state::{Caller, Filter, NewRecord, Patch, StateError, StateStore};

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

fn reply(value: serde_json::Value) -> Response {
    axum::Json(value).into_response()
}

pub(crate) async fn create(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let new: NewRecord = parse(&headers, &body)?;
    let record = shared
        .state
        .create(&caller(&session), new, Utc::now())
        .map_err(|e| refuse(&shared, &session, "create", e))?;
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
        .get(&caller(&session), &id)
        .map_err(|e| refuse(&shared, &session, "get", e))?
    {
        Some(record) => Ok(reply(json!({ "record": record }))),
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
    let records = shared
        .state
        .list(&caller(&session), &filter)
        .map_err(|e| refuse(&shared, &session, "list", e))?;
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
    let body: PatchBody = parse(&headers, &body)?;
    let record = shared
        .state
        .patch(
            &caller(&session),
            &body.id,
            body.expected_revision,
            body.patch,
            Utc::now(),
        )
        .map_err(|e| refuse(&shared, &session, "patch", e))?;
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
