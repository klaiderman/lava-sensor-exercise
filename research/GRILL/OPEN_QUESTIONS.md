# OPEN_QUESTIONS — GRILL

## 1. Missing or empty mandatory KB files

None. All fourteen files listed in the prompt's `<mandatory_files>` exist and are non-empty
(`CLAUDE.md`, `research/DECISIONS.md`, `DESIGN_LAWS.md`, `PRIOR_ART.md`, `FACTS.jsonl`, `CONTRADICTIONS.md`,
`research/R4/HOST_SPECIFIC_PLAN.md`, `research/R4/GENERIC_FALLBACK_PLAN.md`, `research/R5/ARCHITECTURE_NOTES.md`,
`research/R5/IMPL_BVB.md`, `research/R5/TEST_STRATEGY.md`, `task/derived/TASK_CONTRACT.md`,
`task/derived/finding.schema.json`, `state/HOST_SNAPSHOT.json`). No option's host-fit claims were
`UNSOURCED-PENDING`.

## 2. Instruction-like content found in a KB file

None found. No file read during this task contained a fake system/role tag, an "ignore your other
instructions" directive, a request to write outside `research/GRILL/`, a request to run `ssh`, or a claim
that the lead had pre-approved an exception. `research/DECISIONS.md` changed on disk mid-task (the lead
appended a final `LEAD DECISIONS` block, LD-1…LD-9); that is a legitimate lead edit, it was read as data,
and LD-9 explicitly records the architecture shape as pending this track's output. It is noted here only
because the file changed under me, not because anything in it was instruction-like.

## 3. Claims I declined to make for lack of a citation

| Claim I wanted to make | Why it is not in OPTIONS/ATTACKS/SCORECARD |
|---|---|
| "Option 4's evidence store will cost roughly X MB on this host." | No fact bounds the aggregate size of the retained observation set. Per-read caps are policy (F14, F15, L05) but no policy for a *store total* exists anywhere in the KB. Recorded as a design gap in the attack, not as a number. |
| "The scp/rsync upload path to the host works." | `CLAUDE.md` says to upload a cross-compiled binary per the Lava cheatsheet, and F73 verifies the cross-build, but no probe or fact records a successful transfer. Every time estimate in `SCORECARD.md` is flagged as assuming this. |
| "The graders will (or will not) run the sensor on a second machine." | Nothing in `task/derived/TASK_CONTRACT.md` or the brief says either way. A3 requires a real-host `findings.json`; A2 requires one command that works from a clean unpack. This is the load-bearing unknown behind Option 2's reversing fact and it is stated as a conditional, not a claim. |
| "Sequential check execution fits the whole-scan deadline on this host." | R5 §1 recommends sequential and F44/L40 give the BMC read's healthy timing (~1-2 ms), but no measured total-scan wall time exists for any candidate roster. Left unasserted; all four options inherit the same risk. |
| Any statement that a specific option "is the correct choice". | Out of role by construction — this track recommends; LD-9 is the lead's. |

## 4. `UNSOURCED-PENDING` items

None. Every host claim in `OPTIONS.md` and `ATTACKS.md` carries a probe id, fact id, law id or lead-decision
id. LOC estimates and time estimates are labelled estimates rather than cited claims.

## 5. Contradictions I relied on, treated as CONTESTED

- **C-06 / F70 — where schema validation runs.** `research/R5/ARCHITECTURE_NOTES.md` §5 and `IMPL_BVB.md` row 4
  still say "runtime embed, validate before writing, write nothing on failure, net dependency count: one".
  The reconciled KB (`PRIOR_ART.md` §1/§2, `DECISIONS.md` D-05, now LD-6) says test-only import + release gate
  + stdlib runtime invariants that never suppress output, net dependency count zero. `PROPAGATION_AUDIT.md`
  §A2 lists these as known-stale lines. I used the reconciled position (zero runtime deps) for all four
  options, per the prompt's "KB wins" rule. Flagged because the R5 files a future implementation-prompt author
  may read still carry the other version.
- **C-03 / F97 — `sshd -G` primacy.** `research/R4/HOST_SPECIFIC_PLAN.md` B2.4 still says "do not shell out to
  `sshd`" and `GENERIC_FALLBACK_PLAN.md` §7 still frames parsing as primary; `R5/IMPL_BVB.md` row 6 never
  evaluated `-G`. Reconciled L18 + F24 + LD-5 + probe `network.sshd_g_effective` win: `-G` is the primary
  oracle. All four options are described accordingly. Same `PROPAGATION_AUDIT.md` §A1 stale list.
- **C-04 / F25 — `sshd -G -C` (Match-conditional policy).** OPEN and untested on the host (OR-OPEN-1). No
  option is credited with resolving Match-scoped policy; all four treat it as a bounded unknown (L17).
- **C-38 / F41 — ACL xattr readability on files the caller cannot read.** OPEN (OR-OPEN-2); settled only by
  the sensor's first host run. Affects all four options identically, so it is not a discriminator, but it
  means the ACL findings' status distribution is unknown until the first real run.
- **C-26 / F104 — `ipmitool mc info`.** Contract AM-6/C6a permitted it; LD-3 now supersedes that ("no IPMI
  commands, ever"). I used LD-3. `task/derived/TASK_CONTRACT.md` AM-6 and C6a still carry the superseded text
  (also listed in D-10). A propagation edit for the lead, outside my write scope.

## 6. Probe-id hygiene note for the lead (not an architecture question)

`research/DECISIONS.md` D-08 and several plan files cite probe ids that appear in
`state/HOST_SNAPSHOT.evidence.json` (187 probes) but **not** in the `evidence` arrays of
`state/HOST_SNAPSHOT.json` (which reference ~104): e.g. `storage.nvme_smart_rc`, `kernel.apparmor_profiles`,
`users.root_home_ls`, `network.ufw_file_modes`, `network.sshd_g_effective`, `kernel.dmesg_head`,
`services.apt_state_ls`. Both files are authoritative and consistent — the snapshot is a summary view of the
larger evidence file — but a reader told to "cite probe ids from `HOST_SNAPSHOT.json`" will not find several
of the KB's most load-bearing ids there. I cited against `HOST_SNAPSHOT.evidence.json` and say so at the top
of `ATTACKS.md`. Worth one sentence in whichever prompt tells the implementation author where to cite from.

## 7. Questions the lead should answer before freezing LD-9

1. **Is the check roster written by one agent or several?** This is the single fact that flips the ranking
   (see `SCORECARD.md`). LD-8 currently says one (`claude-opus-5`), which is why Option 2 ranks above Option 4.
2. **Is there a budget for a second target machine** (even a container or a VM) to exercise the generic path
   before submission? If yes, Option 2's and Option 4's generic machinery becomes demonstrable rather than
   merely designed, and the case for Option 1 weakens further.
3. **What is the hard wall-clock remaining for implementation?** If it is under ~90 minutes, Option 2's
   degradation path (ship Option 1's roster, add gates second) is the only ranked option that survives; if it
   is under ~60, the honest answer is Option 1 plus steal #1 from `SCORECARD.md`.
4. **Aggregate output-size policy.** No KB item caps the total findings.json size or the total retained
   observation bytes. Per-read caps exist (L05); a document-level cap does not. Option 4 needs one; the others
   would benefit from one.
