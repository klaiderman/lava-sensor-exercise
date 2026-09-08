# TASK_INDEX — Lava Sensor Exercise Contract

## Requirements and Ambiguities Table

| ID | Tag | Section | One-line gist | Pending schema? |
|---|---|---|---|---|
| A1 | EXPLICIT | A. Deliverable | CLI tool `sensor scan --out findings.json` | No |
| A2 | EXPLICIT | A. Deliverable | Deliver source + one command runs from clean | No |
| A3 | EXPLICIT | A. Deliverable | Real findings.json from Lava host run | No |
| A4 | EXPLICIT | A. Deliverable | NOTES.md one page: assumptions, ambiguities, category | No |
| A5 | EXPLICIT | A. Deliverable | Native Claude session transcript export unchanged | No |
| A6 | EXPLICIT | A. Deliverable | One tarball by email; no repo/accounts needed | No |
| A7 | EXPLICIT | A. Deliverable | Any language; Go preferred, unscored | No |
| A7a | ASSUMPTION | A. Deliverable | Implement in Go with stdlib-first | No |
| A8 | EXPLICIT | A. Deliverable | Use Claude and send session export | No |
| A9 | EXPLICIT | A. Deliverable | Both SSH and local workflows allowed | No |
| B1 | EXPLICIT | B. Machine desc | Identity: stable host_id and hostname | No |
| B1a | INTERPRETATION | B. Machine desc | Stable identity across runs/reboots with provenance | No |
| B2 | EXPLICIT | B. Machine desc | Owner: who machine belongs to or unknown | No |
| B2a | AMBIGUITY→INTERPRETATION | B. Machine desc | Owner evidence sources in precedence order | No |
| B3 | EXPLICIT | B. Machine desc | Hardware: vendor, model, CPU, memory | No |
| B3a | INTERPRETATION | B. Machine desc | Vendor/model from DMI readable paths | No |
| B3b | AMBIGUITY | B. Machine desc | Physical cores vs logical CPUs settled | No |
| B3c | INTERPRETATION | B. Machine desc | Memory from /proc/meminfo MemTotal bytes | No |
| B4 | EXPLICIT | B. Machine desc | OS: distribution, version, kernel release | No |
| B5 | EXPLICIT | B. Machine desc | Storage: block devices, models, sizes | No |
| B5a | INTERPRETATION | B. Machine desc | Block devices from /sys/block; exclude loop/ram | No |
| B6 | EXPLICIT | B. Machine desc | Unknown explicit; no empty strings/guesses | Yes |
| B7 | EXPLICIT | B. Machine desc | Extra fields welcome if schema permits | Yes |
| C1 | EXPLICIT | C. Checks | Categories ≥2 checks each; distinct results | No |
| C2 | EXPLICIT | C. Checks | Three required: REMOTE_ACCESS, SECRETS_ON_DISK | No |
| C3 | EXPLICIT | C. Checks | At least one custom category with reason | No |
| C4 | EXPLICIT | C. Checks | REMOTE_ACCESS: listeners, sshd, auth, users | No |
| C4a | INTERPRETATION | C. Checks | Derive effective sshd config without root | No |
| C5 | EXPLICIT | C. Checks | SECRETS_ON_DISK: credentials presence, protection | No |
| C5a | INTERPRETATION + SAFETY | C. Checks | Evidence metadata only; never secret content | No |
| C6 | EXPLICIT | C. Checks | BMC_INBAND_ACCESS: interface, permissions | No |
| C6a | INTERPRETATION | C. Checks | BMC read-only query allowed with timeout | No |
| C7 | EXPLICIT | C. Checks | Severity info is valid observational answer | No |
| C8 | EXPLICIT | C. Checks | Evidence-backed status; no assumption defaults | No |
| C9 | EXPLICIT | C. Checks | Prefer depth: 3–6 thoughtful checks per category | No |
| D1 | EXPLICIT | D. Semantics | Finding fields: category, check_id, status, severity | Yes |
| D1a | INTERPRETATION | D. Semantics | check_id stable, UPPER_SNAKE_CASE, unique | No |
| D2 | EXPLICIT | D. Semantics | Evidence real: paths, values, commands, errno | No |
| D3 | EXPLICIT | D. Semantics | Every check emits one finding; unknown if unreachable | No |
| D4 | EXPLICIT | D. Semantics | Top-level: schema_version, collected_at, machine | No |
| D5 | EXPLICIT | D. Semantics | Output validates against finding.schema.json | No |
| D6 | AMBIGUITY | D. Semantics | Severity impact when fail/unknown, info otherwise | No |
| D7 | INTERPRETATION | D. Semantics | collected_at RFC 3339; per finding completion time | No |
| D8 | ASSUMPTION | D. Semantics | Single UTF-8 JSON document, deterministic order | No |
| E1 | EXPLICIT | E. Safety | Read only: no writes except --out file | No |
| E1a | ASSUMPTION | E. Safety | No outbound network calls at all | No |
| E2 | EXPLICIT | E. Safety | Bounded: timeouts, caps, no device blocking | No |
| E3 | EXPLICIT | E. Safety | Does not crash: per-check panic recovery | No |
| E4 | EXPLICIT | E. Safety | Unprivileged: no sudo/setuid/capabilities | No |
| E5 | EXPLICIT | E. Safety | Out of scope: daemon, database, UI, API, CI | No |
| E6 | EXPLICIT | E. Safety | Safe on others' machines: bounded I/O, no SMART | No |
| F1 | EXPLICIT | F. Evaluation | Graceful handling of unanswerable checks | No |
| F2 | EXPLICIT | F. Evaluation | Wixie-engineered: specified, rejected, verified | No |
| F3 | EXPLICIT | F. Evaluation | Not testing prior BMC/IPMI/Go knowledge | No |
| F4 | EXPLICIT | F. Evaluation | Four hours is guide; ask when blocked | No |
| F5 | EXPLICIT | F. Evaluation | Follow-up topics only; nothing extra required | No |
| AM-1 | AMBIGUITY | G. Ambiguities | finding.schema.json not supplied locally | Yes |
| AM-2 | AMBIGUITY | G. Ambiguities | Owner semantics settled provisionally | No |
| AM-3 | AMBIGUITY | G. Ambiguities | Core count settled: physical + logical + basis | No |
| AM-4 | AMBIGUITY | G. Ambiguities | Severity vs status settled provisionally | No |
| AM-5 | AMBIGUITY | G. Ambiguities | Explicit unknown representation depends on schema | Yes |
| AM-6 | AMBIGUITY | G. Ambiguities | In-band BMC query settled as read-only | No |
| AM-7 | AMBIGUITY | G. Ambiguities | Extra fields vs schema strictness unsettled | Yes |
| AM-8 | AMBIGUITY | G. Ambiguities | No parent directory creation for --out | No |

## Summary Counts

**By Tag:**
- EXPLICIT: 41 requirements
- ASSUMPTION: 3 requirements
- INTERPRETATION: 7 requirements
- AMBIGUITY→INTERPRETATION: 1 requirement
- AMBIGUITY: 2 requirements
- INTERPRETATION + SAFETY: 1 requirement
- (Ambiguities section) AMBIGUITY: 8 items

**Pending Schema (PENDING_SCHEMA state):**
- B6, B7, D1, AM-1, AM-5, AM-7 (6 items)

## Coverage Checklist Verification

| Checklist Item | Covering IDs | Status |
|---|---|---|
| required machine-description fields | B1, B2, B3, B4, B5, B6, B7 | All resolve |
| stable host identity requirements | B1, B1a | All resolve |
| owner semantics incl. explicit unknown | B2, B2a, AM-2 | All resolve |
| hardware/OS/CPU/memory/storage requirements | B3, B3a, B3b, B3c, B4, B5, B5a | All resolve |
| REMOTE_ACCESS | C4, C4a | All resolve |
| SECRETS_ON_DISK | C5, C5a | All resolve |
| BMC_INBAND_ACCESS | C6, C6a, AM-6 | All resolve |
| at least one custom category | C3 | All resolve |
| minimum relevant checks per category | C1, C9 | All resolve |
| status/severity/reason/evidence semantics | D1, D2, D6, D7, C7 | All resolve |
| no silent omission of unexecutable checks | D3 | All resolve |
| actual findings.json schema requirements | D4, D5, AM-1, AM-5, AM-7 | All resolve |
| required source + one-command execution | A1, A2 | All resolve |
| real-host findings.json | A3 | All resolve |
| NOTES requirements | A4, C3 | All resolve |
| native Claude session/export requirement | A5, A8 | All resolve |
| safety invariants (read-only, bounded, no crash, unprivileged) | E1, E1a, E2, E3, E4, E5, E6 | All resolve |
| out-of-scope guard | E5, F5 | All resolve |

**Checklist resolution status:** All 18 checklist items resolve to existing requirement or ambiguity IDs.
