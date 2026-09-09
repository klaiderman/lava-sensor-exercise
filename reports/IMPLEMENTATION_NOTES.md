# IMPLEMENTATION_NOTES

Written by the implementation author alongside the code. It records what each
check observes, and every place the implementation departs from
`research/DECISIONS.md`, `research/CHECK_REGISTRY.md` or `research/R5/PATTERNS.md`,
with the reason. It is not a review and it makes no claim about the quality of
the code it describes.

**Status: vertical slice only.** Tier 1 and Tier 2 are not implemented yet; this
file grows with them.

## Custom categories (LD-1)

- **`STORAGE_POSTURE`** — data-at-rest and decommissioning hygiene on rented
  hardware: whether anything is encrypted at rest, whether `/` has any
  redundancy, whether an attached device is unused (and therefore never opened),
  and drive health as a *proved* unknown rather than a silence.
- **`BOOT_CHAIN`** — whether the machine's own boot path can be trusted: Secure
  Boot state, platform Setup Mode, kernel lockdown, unsigned/out-of-tree module
  taint, TPM presence, and world-readable boot artifacts.

## Checks implemented so far

| check_id | category | impact | evidence sources |
|---|---|---|---|
| `SSH_ROOT_LOGIN_POLICY` | `REMOTE_ACCESS` | high | bounded exec `sshd -G` (primary oracle, run once per scan and shared); Include-aware walk of `/etc/ssh/sshd_config` and its `Include` expansions (always run: provenance and cross-check); `lstat` of `/root/.ssh` and `/root/.ssh/authorized_keys` (metadata only) |

## Machine description

Sources per field are in `internal/checks/machine.go` and are also emitted in
the artifact as `*_source` siblings, so the report documents its own provenance.
`host_id` is `HMAC-SHA256("lava-sensor-host-id", <first source that yields
bytes>)` over `product_uuid` → `machine-id` → a keyed hash of stable hardware
ids (`/sys/block/*/wwid`, permanent NIC MACs gated on `addr_assign_type == 0`)
→ the literal `"unknown"`. The raw `/etc/machine-id` is never emitted, and a
test greps the produced artifact for it.

## Deviations and resolved gaps

### 1. `finalize()` writes the artifact even when the self-check fails (Direction Lock over `R5/PATTERNS.md` §6)

`research/R5/PATTERNS.md` §6 shows the writer refusing to write when validation
fails. The Direction Lock and `DECISIONS.md` D-05 both require the opposite:
write the file, record the failure in it, print the failing JSON pointers to
stderr and exit 1. Implemented as the Direction Lock specifies. Suppressing the
output would turn a formatting bug into a silent omission of every finding.

### 2. `ObsStatus` stays at eight values; the finding-level `reason` vocabulary is wider

The Direction Lock freezes `ObsStatus` to eight values, while
`R3/EVIDENCE_MODEL.md` §7 defines eleven `reason` classes and `DESIGN_LAWS.md`
L03 requires `EPERM` to stay distinct from `EACCES`. These are reconciled rather
than collapsed: `ObsStatus` is the coarse class, `Observation.Errno` carries the
exact symbolic errno, and `Observation.Reason()` prefers the errno when there is
one. `EPERM`, `EINVAL`, `ENODEV` and `EOPNOTSUPP` therefore survive into the
finding while the frozen enum stays eight values wide.

### 3. `probe.NewRootedReader` is an exported test seam

`R5/TEST_STRATEGY.md` §1.1 shows the fixture-root seam as an unexported
constructor in the reading package. The checks live in a different package from
the reader, so the constructor has to be exported. It is compensated by
`TestNoRootOverrideInProduction`, which walks the whole production tree and
fails if any non-test file references `NewRootedReader`, calls `os.Getenv` /
`os.LookupEnv`, or defines a root/unsafe/no-timeout flag.

### 4. Gap filled: `prohibit-password` with root key material *proven absent*

`CHECK_REGISTRY.md` §2.1 defines PASS only for `permitrootlogin no`, FAIL for
`prohibit-password` **with** root key material present, and UNKNOWN for
`prohibit-password` with `/root/.ssh` denied. It does not say what to do when
`/root/.ssh` is readable and holds no key. Implemented as the conservative
reading — `unknown`, reason `ENOENT` — because the policy still permits
key-based root login, `AuthorizedKeysFile` may name a path other than the one
checked, and a key can be added without any policy change. A `pass` there would
be a statement about today's key inventory dressed up as a statement about
policy.

### 5. Gap filled: no daemon and no configuration means no policy to default

`DESIGN_LAWS.md` L19 permits a cited, distro-scoped compiled-in default when a
directive is absent. That is only meaningful when a daemon exists. When neither
an `sshd` binary nor a readable configuration chain is found, the check reports
`unknown` / `UTILITY_MISSING` and states that the absence of an SSH listener is
not the absence of remote access to the machine (L21). Defaulting there would
invent a policy for software that is not installed.

### 6. Gap filled: a `Match` block whose verdict class differs downgrades the global answer

`CHECK_REGISTRY.md` requires that a `Match` block make a global verdict
evidence-only (L17). Implemented narrowly: a `Match` occurrence is only
downgrading when its value falls in a *different* verdict class than the global
one (refused / key-only / permitted). A `Match` that is strictly more
restrictive does not rescue a global `fail`, and does not manufacture an
`unknown` out of a global `pass` that it agrees with. The reason emitted is
`CONTESTED`, with the block's criteria, path and line in evidence.

### 7. `AssetTag.Placeholder` is a pointer

"We could not read this tag" and "we read it and it is not a vendor
placeholder" are different facts. A non-pointer boolean reported the first as
the second. The field is now omitted entirely when the tag was not read, and the
tag still appears with its `errno` — denied is not absent.

### 8. `Check` gained an optional `Budget()` via a separate interface

The Direction Lock fixes the `Check` interface at `ID, Category, Title, Impact,
Observational, Run`. The engine needs a per-check deadline
(`CHECK_REGISTRY.md` §3.9 classifies checks cheap / medium / expensive), so
`scan.Budgeted` is a separate optional interface the engine type-asserts. The
`Check` interface itself is unchanged.

### 9. No temporary file is used for the output write

Invariant 1 requires any temporary file to live under `os.TempDir()`;
`R5/PATTERNS.md` §6 writes `<out>.tmp` next to the output and renames. Writing
`<out>.tmp` on the target would be a write outside the `--out` file, and a
cross-filesystem rename from `os.TempDir()` would fail. The document is instead
rendered fully in memory and written with a single `os.WriteFile`, so a failure
never leaves a half-written artifact and nothing but `--out` is ever created.

### 10. The derived schema is duplicated into `sensor/testdata/`

`go:embed` and test-relative reads cannot reach outside the module, and the
sensor's source tree must be self-contained in the tarball.
`sensor/testdata/finding.schema.json` is a byte copy of
`task/derived/finding.schema.json`, and `TestShippedSchemaMatchesTheAuthoritativeOne`
fails if the two ever differ. There is still exactly one authored schema.

## Bugs the tests found during implementation

- A binary that exists but is not executable was classified `EXECUTION_ERROR`
  rather than `EACCES`, collapsing two of the five failure classes.
  `TestFourFailureClassesStayDistinct` caught it; the runner now separates a
  child that ran and failed (`*exec.ExitError`) from a fork/exec that never
  started.
- `unresolvedReason` preferred a missing config file over a timed-out daemon,
  reporting `ENOENT` where `TIMEOUT` was the actionable fact.
