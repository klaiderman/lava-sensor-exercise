# GRILL-ME raw intent — architecture options + adversarial challenge

- role: `architecture-challenger`
- target model: `claude-opus-5` (architecture challenge and adversarial reasoning where a wrong conclusion is expensive; the FINAL choice is made afterwards by the lead, Fable 5.1, not by this worker)
- inputs the worker reads at runtime: `research/DECISIONS.md` (draft), `research/DESIGN_LAWS.md`, `research/PRIOR_ART.md`, `research/FACTS.jsonl`, `research/CONTRADICTIONS.md`, `research/R4/HOST_SPECIFIC_PLAN.md`, `research/R4/GENERIC_FALLBACK_PLAN.md`, `research/R5/ARCHITECTURE_NOTES.md`, `research/R5/IMPL_BVB.md`, `research/R5/TEST_STRATEGY.md`, `task/derived/TASK_CONTRACT.md`, `task/derived/finding.schema.json`, `state/HOST_SNAPSHOT.json`, `CLAUDE.md`
- output dir: `research/GRILL/` only

## Direction Lock (lead decisions — do not re-open)
- Intent: produce FOUR genuinely different architecture options for the sensor (not cosmetic variants), attack each one hard, and hand the lead a decision-ready comparison. The worker recommends; it does not decide.
- Pre-task defaults that must be challenged, not assumed: runtime = Fixed Registry of checks (deterministic, no runtime LLM, no planner, no external rule engine); Go stdlib-first; static linux/amd64 binary; test-only seams.
- Audience: the lead (final decision), the implementation-prompt author, the Ponytail YAGNI reviewer.
- Output format: `research/GRILL/OPTIONS.md` (four options, each with a one-paragraph shape, module layout sketch, check-registry/evidence model, bounded-exec model, unknown-handling model, machine-description strategy, testing model, dependency list, LOC estimate, what it does on the Lava host vs a generic host), `research/GRILL/ATTACKS.md` (per option, attacks on: task fit, correctness, evidence quality, safety, host fit, generic-machine behaviour, portability, complexity, time-to-build within the remaining exercise budget, build-vs-buy, failure modes, testability; each attack cites a fact id or law id and states whether it is fatal, serious, or cosmetic), `research/GRILL/SCORECARD.md` (matrix + ranked recommendation + the fact that would reverse the ranking), `research/GRILL/OPEN_QUESTIONS.md`.
- Constraints: every claim about the host cites `state/HOST_SNAPSHOT.json` probe ids or FACTS ids; every claim about Go behaviour cites a law/fact or Go docs; no new web research beyond verifying a cited claim (this is a reasoning task over the KB); no code beyond illustrative ≤ 15-line sketches; no ssh; no `.env`; no writes outside `research/GRILL/`.

## The four option families to instantiate (the worker may replace one if the evidence suggests a genuinely different, stronger family — say why)
1. **Fixed Registry, flat** — one package of check functions registered in a slice; shared bounded runner; evidence typed per observation; no plugins.
2. **Fixed Registry, capability-gated tree** — checks declare required capabilities (sysfs paths, utilities, permissions); a deterministic capability probe runs first; checks not gated in still emit `unknown` with the gate reason (never skipped).
3. **Data-driven check table** — checks described as data (YAML/JSON: source path or command, parser, predicate, severity) interpreted by a small engine; easier to add checks, harder to express effective-config derivations (sshd Include semantics) and evidence typing.
4. **Collector/evaluator split** — collectors gather typed observations into an evidence store first (bounded, isolated); evaluators are pure functions over the store producing findings; enables a single observation feeding many checks and clean testing via recorded stores.

## Attack requirements
- For each option, show concretely how it handles: EACCES on `/etc/sudoers.d`, `sshd -T` failing unprivileged, socket-activated sshd, `/dev/ipmi0` root-only + no ipmitool, `nvme smart-log` EACCES, unused `nvme1n1`, Secure Boot disabled + Setup Mode + tainted `bnxt_en`, a machine with no NVMe/no IPMI/no systemd, a hanging subprocess, a 200 MB sysfs read, a check that panics, a budget cut mid-scan, two observations that disagree.
- State the severity-vs-status rule each option would implement and whether it can be enforced centrally.
- Estimate honestly what can be built and tested in the remaining time; penalize options that need more than ~90 minutes of implementation to reach the first schema-valid real-host run.
- Name the single fact for each option that would make it the wrong choice.

## Deliverables (in addition to the contract-free standard set)
- `research/GRILL/OPTIONS.md`, `ATTACKS.md`, `SCORECARD.md`, `OPEN_QUESTIONS.md`
- Final message: ranked options with one-line reasons, the top fatal attack per option, and the fact that would flip the ranking.
