# IMPLEMENTATION raw intent — the Go sensor (vertical slice first, then the full check set)

- role: `implementation-author`
- target model: {{IMPL_MODEL}}  (chosen at architecture freeze: Opus 5 if the frozen design needs cross-cutting judgment during coding; Sonnet 5 for focused implementation of a fully specified design)
- inputs the worker reads at runtime: `CLAUDE.md`, `task/derived/TASK_CONTRACT.md`, `task/derived/finding.schema.json` (+ `SCHEMA_PROVENANCE.md`), `research/DECISIONS.md` (frozen architecture + check list), `research/DESIGN_LAWS.md`, `research/PRIOR_ART.md`, `research/R4/HOST_SPECIFIC_PLAN.md`, `research/R4/GENERIC_FALLBACK_PLAN.md`, `research/R5/PATTERNS.md`, `research/R5/TEST_STRATEGY.md`, `research/R3/FIXTURE_MATRIX.md`, `research/R3/EVIDENCE_MODEL.md`, `state/HOST_SNAPSHOT.json` (what the target looks like; never hardcode it)
- output dir: `sensor/` only (Go module) plus `reports/IMPLEMENTATION_NOTES.md`

## Direction Lock (lead decisions — do not re-open)
- Deliverable: a Go module at `sensor/` producing one static binary `sensor` with the exact CLI `sensor scan --out findings.json` (plus `--version`; optional `--timeout <duration>` for the whole scan with a safe default). Exit 0 when the scan completed and wrote the file, even if findings fail/unknown; non-zero only if the output could not be written or the scan aborted. Logs to stderr only, never to the output file.
- Frozen architecture: {{ARCHITECTURE}}
- Checks to implement (category → check_id → what PASS/FAIL/UNKNOWN mean → impact severity → primary evidence → fallback → UNKNOWN triggers): {{CHECK_LIST}}
- Custom category: {{CUSTOM_CATEGORY}} (decided by the lead; rationale goes to NOTES.md, not into code comments beyond one line)
- Machine description strategy (host_id chain, owner sources, cores basis, memory source, storage enumeration): {{MACHINE_STRATEGY}}
- Severity-vs-status rule (central, enforced by the engine): {{SEVERITY_RULE}}
- Build: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sensor ./cmd/sensor` from `sensor/`; Go 1.26; stdlib only unless `research/PRIOR_ART.md` marks a dependency REUSE (then pin it in go.mod with `go mod tidy` and vendor-free). The target host has no Go: the binary is cross-compiled locally; the source must still build with plain `go build`.
- Vertical slice FIRST: CLI → machine collection → ONE real check (the lead names it: {{SLICE_CHECK}}) → typed evidence → verdict → findings.json → validate against `task/derived/finding.schema.json` in a test. Stop, report, and only then expand to the full check list.
- Author ≠ reviewer: you never review your own work as "independent"; you write tests, you do not write the TEST_REPORT verdict.

## Invariant checklist (every item must be implemented AND covered by a test; the prompt-engineer maps each to prompt lines)
1. Read-only: no writes except the `--out` file; no temp files unless created under `os.TempDir()` and removed; no network sockets opened (no DNS, no HTTP); never invokes sudo/su/doas; never opens device nodes, FIFOs or sockets for reading (`Lstat`/`Stat` mode check first).
2. Bounded subprocesses: every exec uses a context deadline, runs in its own process group (`Setpgid`), is killed as a group on timeout (`Cancel` + `WaitDelay`), has stdout/stderr capped (bounded reader + kill on overflow), stdin from `/dev/null`, minimal environment (`PATH`, `LC_ALL=C`), and records exit code / signal / timeout / truncation in the evidence.
3. Bounded reads: file reads capped (e.g. 1 MiB default, per-source override), `/proc` and `/sys` reads via a bounded reader (sizes lie), directory walks bounded by depth, entry count, wall time and `xdev` (never cross mounts), prune `/proc`, `/sys`, `/dev`, `/run` in secret scans; symlinks resolved deliberately (allowed under `/sys`, not followed into other users' home directories).
4. Isolation: each check runs under `recover()`; a panic becomes an `unknown` finding with `reason` "internal error" + the panic string in evidence; a per-check deadline; the scan deadline; one check's failure never affects another's result or the output write.
5. No silent omission: every registered check emits exactly one finding per run; a check that cannot run (missing capability, EACCES, timeout, budget) emits `unknown` with `reason` and evidence of why; `check_id` uniqueness enforced at registration (fail fast) and tested.
6. Evidence semantics: EACCES ≠ absent; TIMEOUT ≠ false; missing utility ≠ missing capability (sysfs/procfs first, exec fallback); absence only from a successful listing; contradictions between observations recorded as such (not first-wins); under-claiming forbidden where a fallback exists.
7. No secret values: secret checks report path, type (by name/extension/permission and at most a bounded header sniff), mode, owner, size, mtime; never content, never partial key material, never environment variable values; a test greps the output for PEM headers, `sk-`, `AKIA`, JWT shapes, etc.
8. Unknown representation in `machine`: strings use the literal `unknown`; integers use 0 ONLY together with a machine-level `unknowns` object mapping the field to `{reason, sources_tried}`; never an empty string; every field carries provenance (`*_source`).
9. Determinism: stable key order (structs), findings sorted by category then check_id, no map iteration in output, times in UTC RFC 3339; two runs differ only in timestamps/volatile values (test with a fixed clock).
10. Schema: the output validates against `task/derived/finding.schema.json` in tests (the schema is embedded via `go:embed` for a self-check before writing, if PRIOR_ART approves a validator; otherwise tests validate with the chosen validator and the binary performs structural self-checks).
11. Portability: no hostname/vendor/customer string in any check's logic; capability probes gate branches; the same binary must produce a schema-valid, honest output on a machine without NVMe/IPMI/systemd/sshd (tested with the generic profile fixtures).
12. Testability without production overrides: filesystem root and command runner are injected internally (test-only seams, unexported); fixtures under `sensor/testdata/` (host-shaped profile A from the sanitized snapshot, generic profile B, restricted profile C with EACCES/missing tools); fault injection cases from `research/R3/FIXTURE_MATRIX.md`; golden files for findings.json shape.
13. Safety under root: if someone runs it as root it must still be read-only and bounded; no behaviour that mutates state becomes reachable.
14. Documentation: `sensor/README.md` with the exact one command to build and the exact one command to run, expected runtime, exit codes, and what UNKNOWN means; `reports/IMPLEMENTATION_NOTES.md` listing every check with its evidence sources and every place the implementation deviates from DECISIONS.md and why.

## Host context (read at runtime; summarized here for calibration only)
{{HOST_SUMMARY_SHORT}}

## Deliverables
- `sensor/` Go module: `cmd/sensor/`, internal packages per the frozen layout, tests, `testdata/`, `README.md`, `go.mod`
- `reports/IMPLEMENTATION_NOTES.md`
- Final message: build/test results (counts), the vertical-slice findings.json validation result, the list of implemented check_ids per category, invariants with their covering tests, and anything not finished (explicit).
