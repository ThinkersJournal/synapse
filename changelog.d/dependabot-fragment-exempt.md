Changed: a Dependabot PR that touches only dependency files needs no changelog fragment

`tools/check-fragment.py` takes `--author <login>` (the workflow passes the PR author) and passes a PR by `dependabot[bot]` that changes only `Cargo.lock` or `.github/workflows/*.yml` with no fragment and no bump. Any other author, or a bot PR touching anything else, is judged as before. Why: no Dependabot PR had ever merged here because the check failed every one on "no fragment" (#313 open since 2026-11-01, #370); fragments were added to those two by hand. The exemption lifts the check only: the PM still stamps a version at the gate, so a merged bot PR needs its changelog line written then. Tests: `tools/test_fragments.py` (an exempt lock-only bot PR passes; the same PR by another author fails; a bot PR that also touches source fails).

— lane: synapse
