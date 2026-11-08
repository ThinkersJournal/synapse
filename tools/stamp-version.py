#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Stamp a version onto a change: the one step that touches the files parallel PRs collide on.

    python tools/stamp-version.py 6.0.0-rc.235 [--dry-run] [--root DIR]
    python tools/stamp-version.py --check [--root DIR]

A PR edits its own files plus ONE fragment, `changelog.d/<topic>.md` (see changelog.d/README.md), and
carries no version line. When the PM allocates the version at the gate, run this script. It

 1. replaces the current version (read from Cargo.toml) with the new one in every file that carries it:
    the root Cargo.toml, every crate's Cargo.toml, and Cargo.lock;
 2. turns the fragment into one `### <Kind> (rc.N): <title>` section above the newest entry of
    docs/CHANGELOG.md;
 3. deletes the fragment it used.

It REFUSES, and changes nothing, unless there is exactly one fragment: two PRs' fragments in one stamp
would give two changes one version, and none would give a version with no entry. It also refuses a
version that is not newer than the current one, a fragment that does not parse, and a file in the list
that does not carry the current version (the list is out of date). Every refusal is decided before the
first file is written, so a refusal leaves the tree as it was.

`--check` changes nothing: it fails if a file in the list no longer carries the current version, if a
tracked non-documentation file carries it and is not in the list (a new version-bearing file nobody told
this script about; documentation, `changelog.d/` and these tools, whose examples name versions, are
not scanned), or if CHANGELOG has no entry for it. CI runs it.

Standard library only; each file keeps its line endings.

Adapted from ciresnave/auth-framework `tools/stamp-version.py` (PR #427, the same owner; MIT OR
Apache-2.0 in its file headers). What changed for Synapse: versions are `X.Y.Z-rc.N`; there is no PEP 440
spelling, OpenAPI or SDK file; the CHANGELOG is `docs/CHANGELOG.md` with `### Kind (rc.N): title`
sections, so a fragment carries its kind and title; and exactly one fragment per stamp.
"""
import argparse
import os
import re
import subprocess
import sys

# Every file that carries the crate version. `Cargo.lock` holds one `version = "..."` per workspace crate.
VERSION_FILES = [
    "Cargo.toml",
    "Cargo.lock",
    "crates/synapse-agent/Cargo.toml",
    "crates/synapse-claude-channel/Cargo.toml",
    "crates/synapse-mailbox-persistant/Cargo.toml",
    "crates/synapse-mcp-server/Cargo.toml",
    "crates/synapse-security/Cargo.toml",
    "crates/synapsectl/Cargo.toml",
    "crates/synapsed-client/Cargo.toml",
    "crates/synapsed/Cargo.toml",
]
CHANGELOG = "docs/CHANGELOG.md"
FRAGMENTS = "changelog.d"
VERSION = re.compile(r"^(\d+\.\d+\.\d+)-rc\.(\d+)$")
# `Added: title`, `Feature, Breaking: title`: the kinds the CHANGELOG already uses, comma separated.
FIRST_LINE = re.compile(r"^([A-Z][A-Za-z]*(?:, [A-Z][A-Za-z]*)*): (\S.*)$")


def die(message):
    print(f"stamp-version: {message}", file=sys.stderr)
    sys.exit(2)


def read(path):
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8")
    return raw.replace("\r\n", "\n"), "\r\n" in raw


def write(path, text, crlf):
    with open(path, "wb") as f:
        f.write((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def current_version(root):
    text, _ = read(os.path.join(root, "Cargo.toml"))
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.M)
    if not match or not VERSION.match(match.group(1)):
        die("cannot read an `X.Y.Z-rc.N` version from Cargo.toml")
    return match.group(1)


def fragment_paths(root):
    directory = os.path.join(root, FRAGMENTS)
    if not os.path.isdir(directory):
        return []
    return [
        os.path.join(directory, name)
        for name in sorted(os.listdir(directory))
        if name.endswith(".md") and name.lower() != "readme.md"
    ]


def parse_fragment(text):
    """`(kind, title, body)` of a fragment, or a reason string. The first line is `Kind: title`; the rest is
    the entry's body in the CHANGELOG's own style (paragraphs, code fences), which must not be empty."""
    lines = text.replace("\r\n", "\n").strip("\n").split("\n")
    match = FIRST_LINE.match(lines[0]) if lines and lines[0] else None
    if not match:
        return "the first line must be `Kind: title`, for example `Added: the thing (ROADMAP row 1)`"
    body = "\n".join(lines[1:]).strip("\n")
    if not body.strip():
        return "the fragment has a title and no body"
    return match.group(1), match.group(2).strip(), body


def rc(version):
    base, number = VERSION.match(version).groups()
    return base, int(number)


def tracked_files(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    return [p.decode("utf-8") for p in out.split(b"\0") if p]


def check(root):
    version = current_version(root)
    problems = []
    for rel in VERSION_FILES:
        try:
            text, _ = read(os.path.join(root, rel))
        except OSError:
            problems.append(f"{rel} is in this script's list and is not there")
            continue
        if version not in text:
            problems.append(f"{rel} does not carry {version}")
    listed = set(VERSION_FILES)
    for rel in tracked_files(root):
        if rel in listed or rel.endswith(".md") or rel.startswith(("changelog.d/", "target/", "tools/")):
            continue
        try:
            text, _ = read(os.path.join(root, rel))
        except (OSError, UnicodeDecodeError):
            continue
        if version in text:
            problems.append(f"{rel} carries {version} and is not in this script's list")
    changelog, _ = read(os.path.join(root, CHANGELOG))
    label = f"(rc.{rc(version)[1]})"
    if not re.search(rf"^### [^\n]*{re.escape(label)}", changelog, re.M):
        problems.append(f"{CHANGELOG} has no `### ... {label}` entry")
    for problem in problems:
        print("stamp-version: " + problem, file=sys.stderr)
    if problems:
        sys.exit(1)
    print(f"stamp-version: every version-bearing file carries {version}")


def stamp(root, new, dry):
    old = current_version(root)
    if not VERSION.match(new):
        die(f"{new!r} is not an `X.Y.Z-rc.N` version")
    if new == old:
        die(f"the version is already {old}")
    if rc(new)[0] == rc(old)[0] and rc(new)[1] < rc(old)[1]:
        die(f"{new} is older than the current {old}")
    paths = fragment_paths(root)
    if len(paths) != 1:
        found = ", ".join(os.path.relpath(p, root) for p in paths) or "none"
        die(f"exactly one fragment in {FRAGMENTS}/ is stamped at a time (found {len(paths)}: {found})")
    text, _ = read(paths[0])
    parsed = parse_fragment(text)
    if isinstance(parsed, str):
        die(f"{os.path.relpath(paths[0], root)}: {parsed}")
    kind, title, body = parsed
    plan = []
    for rel in VERSION_FILES:
        content, crlf = read(os.path.join(root, rel))
        if old not in content:
            die(f"{rel} does not carry {old}: this script's file list is out of date")
        plan.append((rel, content.replace(old, new), crlf))
    changelog, crlf = read(os.path.join(root, CHANGELOG))
    label = f"rc.{rc(new)[1]}"
    if re.search(rf"^### [^\n]*\({re.escape(label)}\)", changelog, re.M):
        die(f"{CHANGELOG} already has an entry for ({label})")
    unreleased = changelog.find("\n## [Unreleased]")
    newest = re.compile(r"^### ", re.M).search(changelog, unreleased) if unreleased >= 0 else None
    if not newest:
        die(f"{CHANGELOG} has no `## [Unreleased]` heading followed by an entry to put this above")
    section = f"### {kind} ({label}): {title}\n\n{body}\n\n"
    plan.append((CHANGELOG, changelog[: newest.start()] + section + changelog[newest.start() :], crlf))
    for rel, _, _ in plan:
        print(f"stamp-version: {'would update' if dry else 'updating'} {rel}")
    if dry:
        print(f"stamp-version: {old} -> {new}, 1 fragment would be used and deleted")
        return
    for rel, content, crlf in plan:
        write(os.path.join(root, rel), content, crlf)
    os.remove(paths[0])
    print(f"stamp-version: {old} -> {new}, 1 fragment used and deleted")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", nargs="?", help="the new version, e.g. 6.0.0-rc.235")
    parser.add_argument("--dry-run", action="store_true", help="print what would change and change nothing")
    parser.add_argument("--check", action="store_true", help="verify the file list against the tree and change nothing")
    parser.add_argument("--root", default=".", help="the repository root (default: the current directory)")
    args = parser.parse_args()
    root = os.path.abspath(args.root)
    if args.check:
        check(root)
    elif args.version:
        stamp(root, args.version, args.dry_run)
    else:
        parser.error("give a version or --check")


if __name__ == "__main__":
    main()
