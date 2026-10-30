// SPDX-License-Identifier: MIT OR Apache-2.0
//! `--help`, `-h`, `--version` and `-V` answer on stdout and exit 0 without opening a home, a store or a port.

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
fn help_and_version_flags_answer_and_create_nothing() {
    for flag in ["--help", "-h", "--version", "-V"] {
        let dir = tempfile::tempdir().unwrap();
        let before = listing(dir.path());
        let out = Command::new(env!("CARGO_BIN_EXE_synapse-agent"))
            .arg(flag)
            .current_dir(dir.path())
            .env_remove("SYNAPSE_HOME")
            .env_remove("SYNAPSE_ROLE")
            .env_remove("SYNAPSE_ADDR")
            .env("HOME", dir.path())
            .env("USERPROFILE", dir.path())
            .env("LOCALAPPDATA", dir.path())
            .env("APPDATA", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .output()
            .expect("the binary runs");
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let wanted = if flag.starts_with("--v") || flag == "-V" {
            concat!("synapse-agent ", env!("CARGO_PKG_VERSION"))
        } else {
            "usage: synapse-agent"
        };
        assert!(stdout.trim_start().starts_with(wanted), "{flag}: {stdout:?}");
        assert_eq!(listing(dir.path()), before, "{flag} created something");
    }
}
