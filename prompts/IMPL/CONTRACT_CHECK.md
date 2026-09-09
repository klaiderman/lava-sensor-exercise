# Contract Check — IMPL prompt (`prompt.md`)

Maps every load-bearing item from `prompts/raw/IMPL.intent.md` to its exact line range in the final `prompts/IMPL/prompt.md`. All items present. Result: **PASS**.

**Re-verified after the hardening-only pass 2** (5 attacks re-run: payload_splitting, language_switching, data_extraction, output_manipulation, refusal_bypass — see `audit.json` v2 and `LIFECYCLE_LOG.md` Stage 12). The 4 patches from that pass were in-place edits inside the existing `<context>` (line 10) and `<invariants>` preamble (line 63) — no lines were added or removed, so every mapping below is unchanged and still holds. Re-checked line-by-line: PASS, no gaps.

## Direction Lock bullets (intent lines 8–24)

| # | Direction Lock item | prompt.md lines |
|---|---|---|
| — | Deliverable/CLI, safety scope (writes/exec/secret boundary) | 4, 9–10, 22 |
| 1 | Deliverable & CLI (`sensor scan --out`, `--version`, `--timeout`, exit-code contract, stderr-only logs) | 30 |
| 2 | Frozen architecture LD-9 — `internal/probe` (Observation, ObsStatus, classify, bounded read primitive, bounded exec runner, out-of-band-deadline read) | 32–33 |
| 2 | `internal/scan` (Check interface, `checks.All()`, engine loop + `recover()`, shared `Env`, `finalize()` a/b/c, deterministic writer, structural self-check) | 34–35 |
| 2 | `internal/checks` (machine collectors + registered checks) | 36 |
| 2 | "Not allowed, anywhere" list (no capability pre-phase, no evidence store, no data-driven table, no `init()` self-registration, no logger, no extra flags, no network, no third-party runtime import except `jsonschema/v6` in tests) | 37 |
| 3 | 26 checks in two tiers + `BOOT_KERNEL_DRIFT` spec (FAIL/PASS/UNKNOWN rule, evidence) | 39–40 |
| 3 | Tier 1 roster (exact order, vertical slice first) | 41 |
| 3 | Tier 2 roster | 42 |
| 3 | Tier-cut floor (≥3 checks/category) + OPEN-1..6 resolutions | 43–44 |
| 4 | Custom categories LD-1 (`STORAGE_POSTURE`, `BOOT_CHAIN`) + rationale-to-NOTES rule | 46 |
| 5 | Machine description strategy LD-4 (host_id HMAC, fallback chain, owner/owner_candidates, vendor/model, os, cpu, memory, storage[], AM-5 unknown representation) | 48 |
| 6 | Severity rule LD-2 (impact-on-fail/unknown, info-on-pass, Observational→info, never set by hand) | 50 |
| 7 | Build command (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" ...`), Go 1.26, stdlib-only-unless-REUSE, cross-compile note | 52 |
| 8 | Vertical slice FIRST rule (exact exercise list: exec runner, bounded reader, UNKNOWN path, CONTESTED path; stop-and-report) | 54–55 |
| 9 | Author ≠ reviewer | 57 |

## Invariant checklist (intent lines 27–40, all 14 items)

| # | Invariant | prompt.md line |
|---|---|---|
| 1 | Read-only / no writes outside `--out` / no network / no sudo / no device-node reads | 65 |
| 2 | Bounded subprocesses (context deadline, process group, kill-as-group, capped stdio, minimal env, evidence fields) | 66–67 |
| 3 | Bounded reads (cap, `/proc`/`/sys` bounded reader, bounded walks, pruned secret scan, deliberate symlink handling) | 68–69 |
| 4 | Isolation (`recover()`, panic→unknown, per-check + scan deadline, failure containment) | 70 |
| 5 | No silent omission (one finding per check, unknown+reason+evidence, check_id uniqueness fail-fast + tested) | 71 |
| 6 | Evidence semantics (EACCES≠absent, TIMEOUT≠false, missing-utility≠missing-capability, absence-only-from-listing, contested-not-first-wins, no under-claiming) | 72 |
| 7 | No secret values (path/type/mode/owner/size/mtime only; PEM/`sk-`/`AKIA`/JWT grep test) | 73–74 |
| 8 | Unknown representation in `machine` (literal `"unknown"`, `0`+`unknowns` object, `*_source` on every field) | 75 |
| 9 | Determinism (stable key order, sort order, UTC RFC 3339, fixed-clock test) | 76 |
| 10 | Schema (jsonschema/v6 format-assertion test + binary structural self-check) | 77 |
| 11 | Portability (no hostname/vendor/customer strings, capability-gated branches, generic-profile fixture proof) | 78 |
| 12 | Testability without production overrides (unexported test-only seams, `testdata/` profiles A/B/C, FIXTURE_MATRIX cases, golden files) | 79–80 |
| 13 | Safety under root | 81 |
| 14 | Documentation (`sensor/README.md` contents, `IMPLEMENTATION_NOTES.md` contents) | 82 |

## Vertical-slice-first rule

Stated twice, consistently: as a Direction Lock bullet (line 54–55) and restated as the mandatory first step of the Method (line 93, "Stop and self-report before continuing").

## The two check tiers

Tier 1 roster: line 41. Tier 2 roster: line 42. Both reproduced verbatim from the intent's binding lists, in the same order, including the tier-cut floor rule and the lead's OPEN-item resolutions (lines 43–44).

## Deliverables (intent lines 50–53)

| Deliverable | prompt.md coverage |
|---|---|
| `sensor/` Go module: `cmd/sensor/`, internal packages, tests, `testdata/`, `README.md`, `go.mod` | Direction Lock items 1–2, 7 (lines 30, 32–37, 52); Invariant 12 (79–80); Invariant 14 (82); Definition of Done (116–124) |
| `reports/IMPLEMENTATION_NOTES.md` | Direction Lock item 4 (46), Invariant 14 (82), Method item 8 (97), Fallback rules (106, 109) |
| Final report format (build/test counts, vertical-slice validation, check_ids per category, invariants-with-tests, not-finished list) | `<output_format>` block, lines 128–140 |

## Gaps found

None. Every Direction Lock bullet, all 14 invariants, the vertical-slice-first rule (stated twice), both check tiers, and all three deliverable categories map to a concrete line range. No re-check iteration was required.
