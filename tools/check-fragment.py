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

Exemption (`--author <login>`, the PR author as GitHub reports it): a PR by `dependabot[bot]` that touches only
dependency files (`Cargo.lock`, `.github/workflows/*`) may carry no fragment and no bump. A bot PR that touches
anything else, or that adds fragments wrongly, is judged like any other. The exemption lifts the check only: the
PM still stamps a version for what merges, so a merged bot PR with no fragment gets its changelog line written
at the gate.
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


BOT_AUTHORS = {"dependabot[bot]"}
BOT_FILES = re.compile(r"^(Cargo\.lock|\.github/workflows/[^/]+\.ya?ml)$")


def bot_exempt(author, changed_files):
    """True for a dependency bot whose PR touches only dependency files (and at least one)."""
    return author in BOT_AUTHORS and bool(changed_files) and all(BOT_FILES.match(f) for f in changed_files)


def judge(added_fragments, version_changed, parse=None, exempt=False):
    """The verdict for a PR: None when it is fine, else the reason. `added_fragments` is `[(path, text)]`;
    `parse` is the fragment parser (a reason string for one that does not parse)."""
    if added_fragments and version_changed:
        return "this PR both bumps the version and adds a fragment: do one (a fragment, once the PM stamps the version)"
    if version_changed:
        return None
    if not added_fragments and exempt:
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
    args = sys.argv[1:]
    author = None
    if len(args) == 3 and args[1] == "--author":
        author = args[2]
        args = args[:1]
    if len(args) != 1:
        print(__doc__)
        sys.exit(2)
    base = git("merge-base", args[0], "HEAD").strip()
    added = [
        line.split("\t", 1)[1]
        for line in git("diff", "--name-status", "--diff-filter=A", base, "HEAD").splitlines()
        if re.match(r"^A\tchangelog\.d/[^/]+\.md$", line) and not line.lower().endswith("/readme.md")
    ]
    fragments = [(path, git("show", f"HEAD:{path}")) for path in added]
    version_changed = package_version(git("show", f"{base}:Cargo.toml")) != package_version(git("show", "HEAD:Cargo.toml"))
    changed = git("diff", "--name-only", base, "HEAD").splitlines()
    exempt = bot_exempt(author, changed)
    reason = judge(fragments, version_changed, stamp_module().parse_fragment, exempt)
    if reason:
        print("check-fragment: " + reason, file=sys.stderr)
        sys.exit(1)
    how = "version bumped by the PR" if version_changed else (added[0] if added else f"exempt: {author} dependency PR")
    print(f"check-fragment: ok ({how})")


if __name__ == "__main__":
    main()
