Docs: ROADMAP row 54 (email as an opt-in feature) and the stale shared-state rows 30 and 50

ROADMAP.md only; no code. Row 54 records the agreed split of `email` out of `native-base` (the PM's 2026-11-18 ask from agentlife): measured at origin/main 0a811e31, `lettre` is a non-optional dependency and the email modules are compiled unconditionally, so the feature list alone drops nothing; the entry names the work, the breaking surface and the check (`cargo tree -i lettre` empty under `native-base`, present under `native`). Rows 30 and 50 said the adapters had no write tools; #366 (rc.254) merged `state_create` and `state_patch`, so both now say that, name the test that shows it, and keep S7b as not built. Found by pm-platform's claims-to-command audit.

— lane: synapse
