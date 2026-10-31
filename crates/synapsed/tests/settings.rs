// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapsed`'s settings through ConfigurAnt (ROADMAP row 36): the environment variables it always
//! read still work, a `<home>/synapsed.toml` can set the same values, and the environment wins.

use std::collections::BTreeMap;

use synapsed::settings::{Settings, load};

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn settings(pairs: &[(&str, &str)], file: Option<&str>) -> Result<Settings, String> {
    load(&env(pairs), file)
}

#[test]
fn nothing_set_gives_the_defaults() {
    let s = settings(&[], None).unwrap();
    assert_eq!(s.addr.to_string(), "127.0.0.1:7920");
    assert_eq!(s.store_pin, None);
    assert!(s.launcher_roles.is_empty() && s.alert_roles.is_empty());
    assert_eq!(
        s.role_ttl_days, 30,
        "ROLE_TTL, the L1 constant, is the default"
    );
    assert_eq!(
        s.session_ttl_hours, 24,
        "a session idle for a day expires (PM 2026-10-25)"
    );
}

#[test]
fn the_session_ttl_is_set_in_the_file_and_must_be_at_least_an_hour() {
    let file = |value: &str| format!("[session]\nttl_hours = {value}\n");
    let s = settings(&[], Some(&file("2"))).unwrap();
    assert_eq!(s.session_ttl_hours, 2);
    for bad in ["0", "-1", "\"x\""] {
        let e = settings(&[], Some(&file(bad))).unwrap_err();
        assert!(e.contains("ttl_hours"), "{bad}: {e}");
    }
}

#[test]
fn the_role_ttl_is_set_in_the_file_and_must_be_at_least_a_day() {
    let s = settings(
        &[],
        Some(
            "[liveness]
role_ttl_days = 7
",
        ),
    )
    .unwrap();
    assert_eq!(s.role_ttl_days, 7);
    for bad in ["0", "-3", "\"x\""] {
        let e = settings(
            &[],
            Some(&format!(
                "[liveness]
role_ttl_days = {bad}
"
            )),
        )
        .unwrap_err();
        assert!(e.contains("role_ttl_days"), "{bad}: {e}");
    }
}

#[test]
fn the_environment_variables_synapsed_always_read_still_work() {
    let s = settings(
        &[
            ("SYNAPSE_ADDR", "127.0.0.1:0"),
            ("SYNAPSE_MAILBOX_STORE", "sqlite"),
            ("SYNAPSE_LAUNCHER_ROLES", "agentlife-launcher, other"),
            ("SYNAPSE_ALERT_ROLES", "pm"),
            ("PATH", "unrelated variables are ignored"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(s.addr.to_string(), "127.0.0.1:0");
    assert_eq!(s.store_pin.as_deref(), Some("sqlite"));
    assert!(s.store_pin_from_env);
    assert_eq!(s.launcher_roles, ["agentlife-launcher", "other"]);
    assert_eq!(s.alert_roles, ["pm"]);
}

#[test]
fn an_empty_store_variable_is_no_pin_as_it_always_was() {
    let s = settings(&[("SYNAPSE_MAILBOX_STORE", "")], None).unwrap();
    assert_eq!(s.store_pin, None);
    assert!(!s.store_pin_from_env);
}

#[test]
fn a_file_sets_the_same_values_and_the_environment_wins() {
    let file = r#"
[listen]
addr = "127.0.0.1:7931"
[launch]
roles = ["from-file"]
[alert]
roles = ["pm"]
[storage]
id = "redb"
"#;
    let s = settings(&[], Some(file)).unwrap();
    assert_eq!(s.addr.to_string(), "127.0.0.1:7931");
    assert_eq!(s.launcher_roles, ["from-file"]);
    assert_eq!(s.alert_roles, ["pm"]);
    assert_eq!(s.store_pin.as_deref(), Some("redb"));
    assert!(!s.store_pin_from_env, "the pin came from the file");

    let s = settings(
        &[
            ("SYNAPSE_ADDR", "127.0.0.1:1"),
            ("SYNAPSE_LAUNCHER_ROLES", "env-role"),
        ],
        Some(file),
    )
    .unwrap();
    assert_eq!(s.addr.to_string(), "127.0.0.1:1", "env over file");
    assert_eq!(s.launcher_roles, ["env-role"]);
}

#[test]
fn a_bad_value_is_refused_naming_where_to_fix_it() {
    let e = settings(&[("SYNAPSE_ADDR", "not-an-address")], None).unwrap_err();
    assert!(
        e.contains("listen.addr") && e.contains("SYNAPSE_ADDR"),
        "{e}"
    );
    let e = settings(&[("SYNAPSE_LAUNCHER_ROLES", "ok,bad name!")], None).unwrap_err();
    assert!(e.contains("launch.roles") && e.contains("bad name!"), "{e}");
    let e = settings(&[("SYNAPSE_ALERT_ROLES", "../x")], None).unwrap_err();
    assert!(e.contains("alert.roles") && e.contains("../x"), "{e}");
}

#[test]
fn a_file_that_does_not_parse_or_names_an_unknown_key_is_refused() {
    let e = settings(&[], Some("[listen\naddr = ")).unwrap_err();
    assert!(e.contains("synapsed.toml"), "{e}");
    let e = settings(&[], Some("[listen]\nadress = \"127.0.0.1:1\"\n")).unwrap_err();
    assert!(e.contains("adress"), "{e}");
}

#[test]
fn launch_senders_come_from_the_environment_or_the_file_and_default_to_none() {
    assert!(settings(&[], None).unwrap().launch_senders.is_empty());
    let s = settings(&[("SYNAPSE_LAUNCH_SENDERS", "agentlife,pm@acct")], None).unwrap();
    assert_eq!(s.launch_senders, ["agentlife", "pm@acct"]);
    let s = settings(&[], Some("[launch]\nsenders = [\"from-file\"]\n")).unwrap();
    assert_eq!(s.launch_senders, ["from-file"]);
    let e = settings(&[("SYNAPSE_LAUNCH_SENDERS", "bad name")], None).unwrap_err();
    assert!(e.contains("launch.senders"), "{e}");
}

#[test]
fn the_redelivery_back_off_defaults_to_two_four_eight_and_sixteen_minutes() {
    let s = settings(&[], None).unwrap();
    assert_eq!(
        s.redelivery_gaps_secs,
        [120, 240, 480, 960],
        "30 minutes in all (CireSnave 2026-10-31)"
    );
}

#[test]
fn the_back_off_is_set_by_the_environment_or_the_file_and_checked() {
    let s = settings(&[("SYNAPSE_REDELIVERY_GAPS", "60,300")], None).unwrap();
    assert_eq!(s.redelivery_gaps_secs, [60, 300]);
    let file = r#"[delivery]
gaps_secs = ["30", "90"]
"#;
    let s = settings(&[], Some(file)).unwrap();
    assert_eq!(s.redelivery_gaps_secs, [30, 90]);
    let off = r#"[delivery]
gaps_secs = []
"#;
    let s = settings(&[], Some(off)).unwrap();
    assert!(
        s.redelivery_gaps_secs.is_empty(),
        "an empty list turns it off"
    );
    for bad in ["0", "x", "-5", "86401"] {
        let e = settings(&[("SYNAPSE_REDELIVERY_GAPS", bad)], None).unwrap_err();
        assert!(e.contains("delivery.gaps_secs"), "{bad}: {e}");
    }
    let many = vec!["60"; 17].join(",");
    assert!(settings(&[("SYNAPSE_REDELIVERY_GAPS", &many)], None).is_err());
}
