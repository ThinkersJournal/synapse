#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that a pull request carries exactly one CHANGELOG fragment, or bumps the version itself (legacy).

    python tools/check-fragment.py <base-ref>        e.g. origin/main

Compares HEAD with the merge base of <base-ref>. A PR must do exactly one of:

  * add one `changelog.d/<topic>.md` (not README.md) that parses (`Kind: title`, then a body) and leave the
    version alone; or
  * change the version in Cargo.toml itself (a PR opened before fragments existed, or one that must carry
    its own number) and add no fragment.

Doing both, adding two fragments, adding one that does not parse, or doing neither, fails with the reason.
Standard library only.

Adapted from ciresnave/auth-framework `tools/check-fragment.py` (PR #427, the same owner; MIT OR Apache-2.0
in its file headers). The fragment parser is `tools/stamp-version.py`'s, loaded from beside this file, so the
check and the stamp cannot disagree about what a fragment is.
"""
import importlib.util
import os
import re
import subprocess
import sys


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def stamp_module():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stamp-version.py")
    spec = importlib.util.spec_from_file_location("stamp_version", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_version(cargo_toml):
    """The crate's own `X.Y.Z-rc.N` version (a dependency's `version =` is not at the start of a line)."""
    match = re.search(r'^\s*version\s*=\s*"(\d+\.\d+\.\d+-rc\.\d+)"', cargo_toml, re.M)
    return match.group(1) if match else None


def judge(added_fragments, version_changed, parse=None):
    """The verdict for a PR: None when it is fine, else the reason. `added_fragments` is `[(path, text)]`;
    `parse` is the fragment parser (a reason string for one that does not parse)."""
    if added_fragments and version_changed:
        return "this PR both bumps the version and adds a fragment: do one (a fragment, once the PM stamps the version)"
    if version_changed:
        return None
    if not added_fragments:
        return "this PR has no CHANGELOG fragment: add changelog.d/<topic>.md (see changelog.d/README.md)"
    if len(added_fragments) > 1:
        names = ", ".join(path for path, _ in added_fragments)
        return f"this PR adds {len(added_fragments)} fragments ({names}): exactly one"
    path, text = added_fragments[0]
    parsed = parse(text) if parse else None
    if isinstance(parsed, str):
        return f"{path}: {parsed}"
    return None


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    base = git("merge-base", sys.argv[1], "HEAD").strip()
    added = [
        line.split("\t", 1)[1]
        for line in git("diff", "--name-status", "--diff-filter=A", base, "HEAD").splitlines()
        if re.match(r"^A\tchangelog\.d/[^/]+\.md$", line) and not line.lower().endswith("/readme.md")
    ]
    fragments = [(path, git("show", f"HEAD:{path}")) for path in added]
    version_changed = package_version(git("show", f"{base}:Cargo.toml")) != package_version(git("show", "HEAD:Cargo.toml"))
    reason = judge(fragments, version_changed, stamp_module().parse_fragment)
    if reason:
        print("check-fragment: " + reason, file=sys.stderr)
        sys.exit(1)
    print(f"check-fragment: ok ({'version bumped by the PR' if version_changed else added[0]})")


if __name__ == "__main__":
    main()
