// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one place the mailbox store is chosen (`synapsed::select_store`, ROADMAP row 42 slice B).

use synapsed::{Selection, StoreKind, select_store};

#[test]
fn a_pin_of_redb_selects_redb_and_an_unknown_pin_is_refused() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(
        select_store(home.path(), Some("redb"), false).unwrap(),
        Selection::Kind(StoreKind::Redb)
    );
    let err = select_store(home.path(), Some("nosuch"), false).unwrap_err();
    assert!(
        err.contains("\"nosuch\"") && err.contains("not available"),
        "{err}"
    );
}

#[cfg(feature = "sqlite-store")]
mod sqlite {
    use super::*;
    use synapse_mailbox_persistant::needs::StoreChoice;

    #[test]
    fn a_pin_wins_over_a_recorded_choice_and_an_existing_file() {
        let home = tempfile::tempdir().unwrap();
        StoreChoice::new("some-provider", None)
            .unwrap()
            .write(home.path())
            .unwrap();
        std::fs::write(home.path().join("mailbox.redb"), b"x").unwrap();
        assert_eq!(
            select_store(home.path(), Some("sqlite"), false).unwrap(),
            Selection::Kind(StoreKind::Sqlite)
        );
    }

    #[test]
    fn a_recorded_choice_wins_over_the_file_already_in_the_home() {
        let home = tempfile::tempdir().unwrap();
        let choice = StoreChoice::new("some-provider", None).unwrap();
        choice.write(home.path()).unwrap();
        std::fs::write(home.path().join("mailbox.redb"), b"x").unwrap();
        assert_eq!(
            select_store(home.path(), None, false).unwrap(),
            Selection::Named(choice)
        );
    }

    #[test]
    fn a_home_with_a_mailbox_file_and_no_record_stays_on_redb_and_records_nothing() {
        for file in ["mailbox.redb", "mailbox.sqlite"] {
            let home = tempfile::tempdir().unwrap();
            std::fs::write(home.path().join(file), b"x").unwrap();
            assert_eq!(
                select_store(home.path(), None, false).unwrap(),
                Selection::Kind(StoreKind::Redb),
                "{file}"
            );
            assert!(!home.path().join("mailbox-store.json").exists(), "{file}");
        }
    }

    #[test]
    fn a_fresh_home_is_given_a_file_provider_which_is_recorded_for_the_next_start() {
        let home = tempfile::tempdir().unwrap();
        let first = select_store(home.path(), None, false).unwrap();
        assert!(matches!(first, Selection::Named(_)), "{first:?}");
        assert!(home.path().join("mailbox-store.json").exists());
        assert_eq!(select_store(home.path(), None, false).unwrap(), first);
    }
}

#[cfg(not(feature = "sqlite-store"))]
#[test]
fn a_build_without_the_sqlite_store_refuses_a_sqlite_pin() {
    let home = tempfile::tempdir().unwrap();
    let err = select_store(home.path(), Some("sqlite"), false).unwrap_err();
    assert!(
        err.contains("sqlite needs --features sqlite-store"),
        "{err}"
    );
}
