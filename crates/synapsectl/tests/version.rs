// SPDX-License-Identifier: MIT OR Apache-2.0
//! `--version` and `-V` print the build and exit 0 without opening a home, a store or a port.

use std::process::Command;

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn version_flag_prints_the_build_and_creates_nothing() {
    for flag in ["--version", "-V"] {
        let dir = tempfile::tempdir().unwrap();
        let before = listing(dir.path());
        let out = Command::new(env!("CARGO_BIN_EXE_synapse"))
            .arg(flag)
            .current_dir(dir.path())
            .env_remove("SYNAPSE_HOME")
            .env_remove("SYNAPSE_ADDR")
            .env("HOME", dir.path())
            .env("USERPROFILE", dir.path())
            .env("LOCALAPPDATA", dir.path())
            .env("APPDATA", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .output()
            .expect("the binary runs");
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            concat!("synapse ", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
        assert_eq!(listing(dir.path()), before, "{flag} created something");
    }
}
