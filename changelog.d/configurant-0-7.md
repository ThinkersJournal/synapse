Changed: configurant 0.6 to 0.7.2 in synapsed

synapsed now depends on crates.io configurant 0.7 (resolves 0.7.2, which adds redactant 0.1.2). 0.7.0 is Breaking upstream (an unset table is absent); synapsed reads only scalar settings, and its settings tests and the full synapsed test suite pass unchanged. Cargo.lock changes only configurant and the new redactant entry.
