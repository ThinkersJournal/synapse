Docs: state.redb through PersistAnt, design note

Adds docs/superpowers/specs/2026-11-09-state-redb-via-persistant.md: the exact terms a PersistAnt-backed state Backend needs (atomic multi-key transaction, read-your-writes, snapshot reads, ordered scans, owner-only file, one process per file, durability Machine), what PersistAnt 0.16.8 already offers (batch with Require, ordered_scan_values), the gaps and asks for the PersistAnt lane, migration and order of work. Docs only, no code change; slice C1 stays at 2026-11-30.
