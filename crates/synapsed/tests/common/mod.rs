// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared by the daemon tests.

/// Seed `<home>/access.json` with an allow-all rule before the daemon first opens the home, so a
/// test that sends between freshly claimed roles can. A test of the access rules itself does not
/// call this. It is a file the test writes, not a switch in the daemon: production has no bypass.
#[allow(dead_code)]
pub fn allow_all(home: &std::path::Path) {
    let rule = r#"{"grants":[{"principal":"*","actions":["see","send"],"objects":["agent:*"]}]}"#;
    let path = home.join("access.json");
    if path.exists() {
        return;
    }
    std::fs::write(path, rule).expect("seed access.json");
}
