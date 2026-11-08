#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Tests for tools/stamp-version.py and tools/check-fragment.py (changelog.d/README.md).

    python3 tools/test_fragments.py

Each test builds a small repository in a temporary directory with the files the stamp touches, runs the
real scripts against it, and reads the files back. Standard library only; needs `git`.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
STAMP = os.path.join(HERE, "stamp-version.py")
CHECK = os.path.join(HERE, "check-fragment.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stamp_mod = load("stamp_version", STAMP)
check_mod = load("check_fragment", CHECK)

OLD, NEW = "6.0.0-rc.5", "6.0.0-rc.6"
# The files that carry the version, written out here on purpose: a list the tests took from the script
# would shrink with the script and prove nothing about it.
EXPECTED_FILES = [
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
CHANGELOG = (
    "# Synapse Changelog\n\nintro\n\n## [Unreleased] - 6.0.0 release-candidate series\n\n"
    "### Added (rc.5): the old entry\n\nold body\n\n### Added (rc.4): older\n\nolder body\n"
)
FRAGMENT = "Added: the thing, in a few words (ROADMAP row 1)\n\nFirst paragraph.\n\nSecond paragraph.\n"


def run(args, cwd, check=True):
    return subprocess.run(args, cwd=cwd, check=check, capture_output=True, text=True)


def git(root, *args):
    return run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args], root)


def put(root, rel, text, crlf=False):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def get(root, rel):
    with open(os.path.join(root, rel), "rb") as f:
        return f.read().decode("utf-8")


def snapshot(root):
    out = {}
    for base, _, names in os.walk(root):
        if ".git" in base.split(os.sep):
            continue
        for name in names:
            path = os.path.join(base, name)
            with open(path, "rb") as f:
                out[os.path.relpath(path, root)] = f.read()
    return out


class Repo(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for rel in EXPECTED_FILES:
            if rel == "Cargo.lock":
                put(self.root, rel, f'[[package]]\nversion = "{OLD}"\n\n[[package]]\nversion = "{OLD}"\n', crlf=True)
            else:
                put(self.root, rel, f'[package]\nname = "x"\nversion = "{OLD}"\n')
        put(self.root, stamp_mod.CHANGELOG, CHANGELOG)
        put(self.root, "changelog.d/README.md", "readme\n")
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "add", "-A")

    def stamp(self, *args, check=False):
        return run([sys.executable, STAMP, *args, "--root", self.root], self.root, check=check)


class Workspace(unittest.TestCase):
    def test_the_list_names_every_manifest_of_the_real_workspace_and_the_lock_file(self):
        repo = os.path.dirname(HERE)
        crates = sorted(
            f"crates/{name}/Cargo.toml"
            for name in os.listdir(os.path.join(repo, "crates"))
            if os.path.isfile(os.path.join(repo, "crates", name, "Cargo.toml"))
        )
        self.assertEqual(sorted(stamp_mod.VERSION_FILES), sorted(["Cargo.toml", "Cargo.lock", *crates]))
        self.assertEqual(sorted(stamp_mod.VERSION_FILES), sorted(EXPECTED_FILES))


class Stamp(Repo):
    def test_one_fragment_sets_every_file_writes_the_section_above_the_newest_and_is_deleted(self):
        put(self.root, "changelog.d/thing.md", FRAGMENT)
        done = self.stamp(NEW, check=True)
        self.assertIn(f"{OLD} -> {NEW}", done.stdout)
        for rel in EXPECTED_FILES:
            text = get(self.root, rel)
            self.assertIn(NEW, text, rel)
            self.assertNotIn(OLD, text, rel)
        self.assertEqual(get(self.root, "Cargo.lock").count(NEW), 2, "every occurrence in the lock file")
        changelog = get(self.root, stamp_mod.CHANGELOG)
        want = (
            "## [Unreleased] - 6.0.0 release-candidate series\n\n"
            "### Added (rc.6): the thing, in a few words (ROADMAP row 1)\n\n"
            "First paragraph.\n\nSecond paragraph.\n\n"
            "### Added (rc.5): the old entry\n"
        )
        self.assertIn(want, changelog)
        self.assertIn("### Added (rc.4): older\n\nolder body\n", changelog, "older entries are untouched")
        self.assertFalse(os.path.exists(os.path.join(self.root, "changelog.d", "thing.md")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "changelog.d", "README.md")))

    def test_each_file_keeps_its_line_endings(self):
        put(self.root, "changelog.d/thing.md", FRAGMENT)
        self.stamp(NEW, check=True)
        self.assertIn("\r\n", get(self.root, "Cargo.lock"))
        self.assertNotIn("\r\n", get(self.root, "Cargo.toml"))
        self.assertNotIn("\r\n", get(self.root, stamp_mod.CHANGELOG))

    def test_a_breaking_kind_with_several_words_is_kept(self):
        put(self.root, "changelog.d/b.md", "Feature, Breaking: a thing\n\nbody\n")
        self.stamp(NEW, check=True)
        self.assertIn("### Feature, Breaking (rc.6): a thing\n\nbody\n", get(self.root, stamp_mod.CHANGELOG))

    def refuses(self, why, *args):
        before = snapshot(self.root)
        done = self.stamp(*args)
        self.assertEqual(done.returncode, 2, f"{why}: {done.stdout}{done.stderr}")
        self.assertEqual(snapshot(self.root), before, f"{why}: a refusal must leave the tree as it was")
        return done.stderr

    def test_it_refuses_anything_but_exactly_one_fragment(self):
        self.assertIn("exactly one", self.refuses("none", NEW))
        put(self.root, "changelog.d/a.md", FRAGMENT)
        put(self.root, "changelog.d/b.md", FRAGMENT)
        self.assertIn("exactly one", self.refuses("two", NEW))

    def test_it_refuses_a_version_that_is_not_newer_or_not_a_version(self):
        put(self.root, "changelog.d/a.md", FRAGMENT)
        self.assertIn("already", self.refuses("same", OLD))
        self.assertIn("older", self.refuses("older", "6.0.0-rc.4"))
        self.assertIn("not an", self.refuses("malformed", "6.0.0-rc5"))
        self.assertIn("not an", self.refuses("pep440 spelling", "6.0.0rc6"))

    def test_it_refuses_a_fragment_that_does_not_parse(self):
        put(self.root, "changelog.d/a.md", "no kind here\n\nbody\n")
        self.assertIn("Kind: title", self.refuses("no kind", NEW))
        put(self.root, "changelog.d/a.md", "Added: only a title\n")
        self.assertIn("no body", self.refuses("no body", NEW))

    def test_it_refuses_when_a_listed_file_does_not_carry_the_version(self):
        put(self.root, "changelog.d/a.md", FRAGMENT)
        put(self.root, "crates/synapsed/Cargo.toml", '[package]\nversion = "1.2.3"\n')
        self.assertIn("out of date", self.refuses("stale list", NEW))

    def test_it_refuses_an_entry_that_already_exists_and_a_changelog_with_nowhere_to_put_it(self):
        put(self.root, "changelog.d/a.md", FRAGMENT)
        put(self.root, stamp_mod.CHANGELOG, CHANGELOG.replace("(rc.4)", "(rc.6)"))
        self.assertIn("already has an entry", self.refuses("duplicate", NEW))
        put(self.root, stamp_mod.CHANGELOG, "# Synapse Changelog\n\nno unreleased heading\n")
        self.assertIn("Unreleased", self.refuses("no anchor", NEW))

    def test_dry_run_changes_nothing(self):
        put(self.root, "changelog.d/a.md", FRAGMENT)
        before = snapshot(self.root)
        done = self.stamp(NEW, "--dry-run", check=True)
        self.assertIn("would update", done.stdout)
        self.assertEqual(snapshot(self.root), before)


class Check(Repo):
    def check(self):
        return run([sys.executable, STAMP, "--check", "--root", self.root], self.root, check=False)

    def test_a_consistent_tree_passes(self):
        self.assertEqual(self.check().returncode, 0, self.check().stderr)

    def test_a_listed_file_that_stops_carrying_the_version_fails(self):
        put(self.root, "crates/synapsectl/Cargo.toml", '[package]\nversion = "9.9.9-rc.1"\n')
        done = self.check()
        self.assertEqual(done.returncode, 1)
        self.assertIn("crates/synapsectl/Cargo.toml does not carry", done.stderr)

    def test_a_tracked_file_that_carries_the_version_and_is_not_listed_fails(self):
        put(self.root, "crates/new-crate/Cargo.toml", f'[package]\nversion = "{OLD}"\n')
        git(self.root, "add", "-A")
        done = self.check()
        self.assertEqual(done.returncode, 1)
        self.assertIn("crates/new-crate/Cargo.toml carries", done.stderr)
        # Documentation may mention the version.
        os.remove(os.path.join(self.root, "crates/new-crate/Cargo.toml"))
        put(self.root, "docs/NOTES.md", f"we are at {OLD}\n")
        git(self.root, "add", "-A")
        self.assertEqual(self.check().returncode, 0, self.check().stderr)
        # The tools' own examples may name any version, including the current one.
        put(self.root, "tools/example.py", f"# for example {OLD}\n")
        git(self.root, "add", "-A")
        self.assertEqual(self.check().returncode, 0, self.check().stderr)

    def test_a_changelog_without_an_entry_for_the_version_fails(self):
        put(self.root, stamp_mod.CHANGELOG, CHANGELOG.replace("(rc.5)", "(rc.3)"))
        done = self.check()
        self.assertEqual(done.returncode, 1)
        self.assertIn("(rc.5)", done.stderr)


class Judge(unittest.TestCase):
    def judge(self, fragments, bumped):
        return check_mod.judge(fragments, bumped, stamp_mod.parse_fragment)

    def test_the_verdicts(self):
        one = [("changelog.d/a.md", FRAGMENT)]
        self.assertIsNone(self.judge(one, False), "one good fragment")
        self.assertIsNone(self.judge([], True), "a manual bump")
        self.assertIn("both", self.judge(one, True))
        self.assertIn("no CHANGELOG fragment", self.judge([], False))
        self.assertIn("2 fragments", self.judge(one + [("changelog.d/b.md", FRAGMENT)], False))
        self.assertIn("Kind: title", self.judge([("changelog.d/a.md", "oops\n\nbody\n")], False))
        self.assertIn("no body", self.judge([("changelog.d/a.md", "Added: t\n")], False))

    def test_the_version_regex_reads_the_crates_own_version_only(self):
        toml = f'[package]\nname = "x"\nversion = "{OLD}"\n[dependencies]\nsynapse = {{ path = "..", version = "{OLD}" }}\n'
        self.assertEqual(check_mod.package_version(toml), OLD)
        self.assertIsNone(check_mod.package_version('synapse = { version = "6.0.0-rc.5" }\n'))
        self.assertIsNone(check_mod.package_version('version = "6.0.0rc5"\n'))


class PullRequest(Repo):
    """check-fragment.py against a real branch: the merge base, the added files, the version change."""

    def setUp(self):
        super().setUp()
        git(self.root, "commit", "-q", "-m", "base")
        git(self.root, "checkout", "-q", "-b", "pr")

    def verdict(self):
        done = run([sys.executable, CHECK, "main"], self.root, check=False)
        return done.returncode, done.stderr

    def commit(self):
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "pr")

    def test_one_fragment_passes(self):
        put(self.root, "changelog.d/a.md", FRAGMENT)
        self.commit()
        self.assertEqual(self.verdict()[0], 0)

    def test_nothing_fails(self):
        put(self.root, "src/x.rs", "fn main() {}\n")
        self.commit()
        code, why = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("no CHANGELOG fragment", why)

    def test_two_fragments_fail(self):
        put(self.root, "changelog.d/a.md", FRAGMENT)
        put(self.root, "changelog.d/b.md", FRAGMENT)
        self.commit()
        self.assertEqual(self.verdict()[0], 1)

    def test_a_manual_bump_passes_and_a_bump_with_a_fragment_fails(self):
        put(self.root, "Cargo.toml", f'[package]\nname = "x"\nversion = "{NEW}"\n')
        self.commit()
        self.assertEqual(self.verdict()[0], 0, "a PR that carries its own number is allowed")
        put(self.root, "changelog.d/a.md", FRAGMENT)
        self.commit()
        code, why = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("both", why)

    def test_a_readme_edit_is_not_a_fragment(self):
        put(self.root, "changelog.d/README.md", "edited\n")
        self.commit()
        self.assertEqual(self.verdict()[0], 1)

    def test_adding_the_readme_is_not_adding_a_fragment(self):
        # The PR that introduces changelog.d adds its README; that is not a fragment either.
        git(self.root, "checkout", "-q", "main")
        git(self.root, "rm", "-q", "changelog.d/README.md")
        git(self.root, "commit", "-q", "-m", "no readme yet")
        git(self.root, "checkout", "-q", "-b", "introduces")
        put(self.root, "changelog.d/README.md", "readme\n")
        self.commit()
        code, why = self.verdict()
        self.assertEqual(code, 1)
        self.assertIn("no CHANGELOG fragment", why)


if __name__ == "__main__":
    unittest.main()
