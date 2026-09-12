# ghidra-cli TODO (historical)

> **Status: archived 2026-07-17.** All bugs in the original list (v0.2.0,
> found on the parasolid-re project) were fixed and are covered by unit/E2E
> tests; the bug write-ups were dropped. This file keeps only the open
> follow-ups (all resolved — see below; the refactor's open follow-ups live in
> `docs/history/refactor-plan.md`).

## Follow-ups — ALL RESOLVED (2026-09-12)

- ~~`test_import_binary` 300 s timeout~~ — raised to 600 s (and the four
  sibling JVM-spawning timeouts) in the P7 split commit (`1758f39`).
- ~~Filter grammar not anchored with `SOI`/`EOI`~~ — anchored + parser test in
  `4f31a85` (trailing garbage is now rejected).
- ~~parasolid-re `docs/GHIDRA_WORKFLOW.md` `--limit 0` workaround~~ — the
  external doc; `--limit 0 = all rows` is the implemented behavior.

(Open follow-ups from the refactor era live under "Open follow-ups" in
`docs/history/refactor-plan.md`.)
