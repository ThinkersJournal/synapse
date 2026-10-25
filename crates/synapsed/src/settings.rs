// SPDX-License-Identifier: MIT OR Apache-2.0
//! The daemon's settings through ConfigurAnt: `SYNAPSE_ADDR`, `SYNAPSE_MAILBOX_STORE`,
//! `SYNAPSE_LAUNCHER_ROLES` and `SYNAPSE_ALERT_ROLES` as they always were, plus the same four in an
//! optional `<home>/synapsed.toml` ([`FILE_NAME`]). The environment wins over the file, the file over
//! the defaults. The schema is `synapsed.schema.toml`, compiled in. Pure: the environment and the
//! file's text come in as data, so every rule here is tested without a process.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use configurant::{Loader, Origin, Schema};

/// The file in the home that may set the same values.
pub const FILE_NAME: &str = "synapsed.toml";

const SCHEMA: &str = include_str!("../synapsed.schema.toml");

/// What `synapsed` reads at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to listen (default `127.0.0.1:7920`).
    pub addr: SocketAddr,
    /// A pinned mailbox store id (`redb`, `sqlite`), or `None` to follow the recorded choice.
    pub store_pin: Option<String>,
    /// Whether the pin came from `SYNAPSE_MAILBOX_STORE` (the deprecated route) and not the file.
    pub store_pin_from_env: bool,
    /// Roles that may read launch signals; empty means launch is off.
    pub launcher_roles: Vec<String>,
    /// Roles that receive security alerts as mail.
    pub alert_roles: Vec<String>,
    /// A role idle this many days is retired (file only; default 30).
    pub role_ttl_days: u32,
}

/// Resolve the settings from `env` (the whole process environment is fine) and the text of
/// `<home>/synapsed.toml`, if there is one.
///
/// # Errors
/// A message for the operator: a file that does not parse, a key it does not know, an address that
/// is not one, or a role that is not a valid name. An empty `SYNAPSE_MAILBOX_STORE` counts as unset,
/// as it always did.
pub fn load(env: &BTreeMap<String, String>, file: Option<&str>) -> Result<Settings, String> {
    let schema = Schema::parse(SCHEMA).map_err(|e| format!("the built-in schema: {e}"))?;
    let env: BTreeMap<String, String> = env
        .iter()
        .filter(|(name, value)| !(name.as_str() == "SYNAPSE_MAILBOX_STORE" && value.is_empty()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut loader = Loader::new(&schema).env(env);
    if let Some(text) = file {
        loader = loader.file(FILE_NAME, text);
    }
    let config = loader.build().map_err(|e| e.to_string())?;

    let raw: String = config.get("listen.addr").map_err(|e| e.to_string())?;
    let addr: SocketAddr = raw.parse().map_err(|_| {
        format!("listen.addr {raw:?} is not an address (set SYNAPSE_ADDR, or listen.addr in {FILE_NAME})")
    })?;
    let roles = |key: &str| -> Result<Vec<String>, String> {
        let list: Vec<String> = config.get(key).map_err(|e| e.to_string())?;
        let list: Vec<String> = list.into_iter().filter(|r| !r.is_empty()).collect();
        match list.iter().find(|r| !synapse::keystore::valid_name(r)) {
            Some(bad) => Err(format!("{key}: {bad:?} is not a role name")),
            None => Ok(list),
        }
    };
    let days: i64 = config
        .get("liveness.role_ttl_days")
        .map_err(|e| e.to_string())?;
    let role_ttl_days = u32::try_from(days)
        .ok()
        .filter(|d| *d >= 1)
        .ok_or_else(|| format!("liveness.role_ttl_days is {days}: it must be at least 1"))?;
    let store_pin: Option<String> = config.get("storage.id").ok();
    let store_pin_from_env = store_pin.is_some()
        && config.explain("storage.id").is_ok_and(|e| {
            e.chain
                .iter()
                .any(|line| line.wins && matches!(line.origin, Origin::Env(_)))
        });
    Ok(Settings {
        addr,
        store_pin,
        store_pin_from_env,
        launcher_roles: roles("launch.roles")?,
        alert_roles: roles("alert.roles")?,
        role_ttl_days,
    })
}
