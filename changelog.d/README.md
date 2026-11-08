<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# changelog.d: CHANGELOG fragments

A pull request does **not** edit `docs/CHANGELOG.md`, the version in any `Cargo.toml`, or `Cargo.lock`. Those are
what parallel PRs collide on: every merge moves the version under every other open PR, and each collision is a
hand merge of nine manifests, the lock file and the CHANGELOG's top entry (a docs-only PR waiting in the gate
hit it twice in one evening). A PR adds **one fragment** instead, `changelog.d/<topic>.md`:

    Added: the thing, in a few words (ROADMAP row 1)

    One or more paragraphs in the CHANGELOG's own style: what changed, why, what a user must do, and the
    evidence (tests, sabotage). Plain Markdown; code fences and lists are kept as written.

- **The first line is `Kind: title`.** `Kind` is what the CHANGELOG already uses: `Added`, `Changed`, `Fixed`,
  `Docs`, `Breaking`, or several joined by a comma and a space (`Feature, Breaking`). Pre-1.0 the second number is
  the major, so a breaking change is 6.0 -> 6.1, and a `Breaking` kind belongs in the title line, not the body.
- **The rest is the body**, which must not be empty. It becomes the section's text unchanged.
- **Exactly one fragment per PR.** The `Changelog fragment` workflow checks it (`tools/check-fragment.py`), and that
  the fragment parses. A PR that still carries its own version bump (opened before this mechanism existed, or one
  that must carry its number) adds no fragment; doing both, or neither, fails.
- **The PM allocates the version at the gate** and runs `python tools/stamp-version.py 6.0.0-rc.235`. It sets the
  version in every file that carries it (the root and crate manifests and `Cargo.lock`), writes
  `### <Kind> (rc.235): <title>` and the body above the newest entry of `docs/CHANGELOG.md`, and deletes the
  fragment. `--dry-run` shows the plan and changes nothing. It stamps exactly one fragment at a time and refuses
  anything else, and a version that is not newer than the current one; every refusal leaves the tree as it was.
- **`python tools/stamp-version.py --check`** (CI runs it) fails if a file in the script's list stops carrying the
  version, if a tracked non-documentation file carries it and is not in the list (a new version-bearing file
  nobody told the script about: add it to `VERSION_FILES`), or if the CHANGELOG has no entry for it.
- `python tools/test_fragments.py` runs the tests of both scripts (CI runs it).

The scheme is auth-framework's (`changelog.d`, PR #427), adapted to this repository: `X.Y.Z-rc.N` versions, a
`### Kind (rc.N): title` CHANGELOG, and one fragment per stamp.
