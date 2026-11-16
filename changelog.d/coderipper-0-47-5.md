Changed: move the CodeRipper portfolio pin to 0.47.5

The portfolio workflow call in `.github/workflows/ci_cd.yml` now pins coderipper at c72a6e03 (0.47.5). The rule-id migration tool found nothing to rename: `.coderipper.toml` names no renamed rule and no workflow passes one.
