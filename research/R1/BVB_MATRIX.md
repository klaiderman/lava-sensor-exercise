# R1 — BUILD vs BUY DECISION MATRIX

Verdict labels: **REUSE** (import or exec as-is) · **STEAL_PATTERN** (re-implement a specific technique, cited) · **BUILD** (own it) · **REJECT** (with reason).
Licence rule applied throughout: permissive only (MIT / BSD / Apache-2.0 / ISC) for REUSE and STEAL_PATTERN. Copyleft is flagged as a **licensing** blocker separately from any technical one, so the two never get confused.

## 1. Machine identity & hardware inventory

| Option | Verdict | Facts | Reasoning |
|---|---|---|---|
| `github.com/jaypipes/ghw` | **REJECT** (evidence layer) / **STEAL_PATTERN** (chroot seam, `linuxdmi.Available` capability gate) | R1-F3, R1-F4, R1-F5 | Converts EACCES into the untyped string `"unknown"` with no errno, destroying the `reason` the schema requires; its memory path scrapes `/var/log/syslog` and silently substitutes usable RAM for installed RAM — and our host user is not in `adm`. |
| `github.com/shirou/gopsutil/v4` | **STEAL_PATTERN** (host-id ladder, udev-db serial route) | R1-F6, R1-F12 | BSD-3, CGO-free, and its techniques are right — but `HostID()` returns `("", nil)` on total failure, the exact empty string the brief forbids. The useful part is ~40 lines. |
| `github.com/prometheus/procfs` | **REUSE (candidate)** / **STEAL_PATTERN (minimum)** | R1-F7 | Apache-2.0; the only library that already models DMI as pointer-or-nil with an explicit `os.IsPermission` branch and regular-files-only reads. Still needs a thin wrapper to record *which* errno produced the nil. |
| `github.com/zcalusic/sysinfo` | **REJECT** | R1-F8 | Requires superuser for DMI/RAM and its shipped example `log.Fatal`s as non-root. A library that can abort the process is disqualified by E3 alone. |
| `u-root/pkg/smbios`, `digitalocean/go-smbios` | **REJECT** | R1-F2 | Correct code pointed at unreachable data: all three acquisition paths (DMI tables 0400, EFI systab 0400, `/dev/mem`) are root-only. |
| `dmidecode` / `lshw` / `inxi` / `facter` / `ohai` (exec) | **REJECT** | R1-F2, R1-F11 | GPL-family licensing, root requirements, and absent from the host image. `facter`/`ohai` additionally require a Ruby runtime. |
| `lsblk` / `lscpu` / `blkid` (exec) | **REJECT as runtime** / **STEAL_PATTERN as a map of sysfs** | R1-F11, R1-F12 | Everything they report unprivileged comes from sysfs plus the udev db, which we read directly. `blkid` as uid 1000 prints nothing and exits 0 — silent empty success is worse than an error. |
| osquery inventory tables | **STEAL_PATTERN** (Apache-2.0 arm) / **REJECT as dependency** | R1-F9, R1-F10 | Licence-clean to learn from; but it is a C++ daemon linking libcryptsetup/libudev, so CGO, which breaks the static build. `disk_encryption` returns zero rows non-root. |
| **Own stdlib sysfs/procfs readers behind a test-injectable fs root** | **BUILD** | R1-F1, R1-F2, R1-F7, R1-F12 | The only option that satisfies the contract. Every unprivileged datum is a bounded read of a world-readable regular file; the privileged data is unavailable to *every* option, so no library can beat BUILD on coverage — only on typed-reason quality, where BUILD wins. |

## 2. Remote-access policy

| Option | Verdict | Facts | Reasoning |
|---|---|---|---|
| **`sshd -G` (bounded exec)** | **REUSE** — pending R1-OR9 | R1-F47, R1-F51 | The headline reversal of this track. `-G` dumps the effective config **before** host-key loading, so it succeeds as uid 1000 where `-T` fatals with "no hostkeys available -- exiting". This hands us the daemon's *own* answer — Include expansion and first-match-wins already resolved — instead of us re-implementing OpenSSH's semantics and hoping we match. |
| `sshd -T` | **REJECT** | R1-F47 | Structurally impossible unprivileged: it loads host keys first, which is exactly the observed failure on the target. |
| **Own Include-aware config parser** | **BUILD** (anyway) | R1-F51, R1-F52 | Needed for three things `-G` cannot give: a fallback when `-G` is unavailable, `file:line` provenance for the evidence block, and a free correctness cross-check against `-G`. Also required because `-G -C` fatals, so Match-conditional policy is beyond `-G`'s ceiling. |
| **`/proc/net/tcp{,6}` + `/proc/net/unix` + systemd `.socket` unit files** | **BUILD** | R1-F53, R1-F54 | The primary listener primitives. `/proc/net/tcp` gives owning uid and socket inode for *other users'* sockets; unit files plus `systemctl is-active` (works unprivileged) establish the activation path without asserting a pid. |
| `ss -ltnp` | **REJECT as evidence** / fallback labelling only | R1-F53 | Degrades by silent omission: exit 0, header present, Process column blank. A blank column is not evidence of anything. |
| osquery `ssh_configs` / `authorized_keys` / `sudoers` / `listening_ports` | **REJECT** (capability, **not** licence) | R1-F9 | Licence is clean (dual Apache-2.0/GPL-2.0). Rejected on capability and on being an unlinkable C++ daemon. |
| Lynis SSH-*/AUTH-* | **REJECT as code** / **STEAL_PATTERN heavily** | R1-F9, R1-F56 | GPLv3 licensing blocker and root-dependent. But its `SKIPREASON` taxonomy (`include/functions:2707-2764`) is a ready-made vocabulary for our `reason` field — steal the taxonomy, reject the skip-silently behaviour. |
| Wazuh SCA sshd/CIS policies | **STEAL structure only** | R1-F55 | GPLv2. Its rules are all `c:sshd -T` with no unknown state, so unprivileged it emits **false FAILs** — a cautionary example, not a model. |
| `ssh-audit` | **REJECT** | — | A network scanner; the sensor makes no network calls (E1a). |
| XCCDF result model | **STEAL_PATTERN** | R1-F57 | Nine result values vs our fixed three; the mapping tells us exactly what the `reason` field has to carry. **LIKELY, not VERIFIED** — both NIST primary URLs were blocked. |
| sudoers-based "who can escalate" as a pass/fail | **REJECT** | — | `/etc/sudoers` and `/etc/sudoers.d` are unreadable on the target. Emit `unknown` plus a separate, provable group-membership observation — never infer policy from group membership alone. |

## 3. Secrets on disk

| Option | Verdict | Facts | Reasoning |
|---|---|---|---|
| **Content scanning as a capability** (any tool) | **REJECT — scope decision** | R1-F19, R1-F18 | Private-key regexes structurally require consuming 64+ characters of key body. Header-only classification delivers the same `detected_type` with a provably bounded read, so content scanning buys only "secrets embedded in arbitrary files" at far higher risk. Declare this in NOTES.md as a choice, not an omission. |
| `gitleaks` | **REJECT** (safety + weight, **not** licence) | R1-F14, R1-F15 | Licence is fine — MIT, never relicensed; **our own brief was wrong about this**. It is rejected because `--redact` defaults to 0 and its report serialises raw `Secret` and `Match`, which would make our `findings.json` a new secret-bearing artifact on the customer's disk. 144 modules. |
| `trufflehog` | **REJECT** — two independent blockers | R1-F16 | AGPL-3.0 (licensing blocker) **and** it verifies credentials against live third-party APIs by default (violates the no-network invariant in the most dangerous way). 430 modules. |
| Trivy secret rules | **STEAL_PATTERN** (ideas only) | R1-F19 | Apache-2.0 and a useful catalogue of credential prefixes, but it is a content scanner with no filename rule set — nothing to reuse structurally. |
| **POSIX ACL reader** | **BUILD** (~30 lines) | R1-F17, R1-F44 | The xattr format is fully specified by kernel UAPI and was byte-verified locally on a box with no `getfacl` installed at all. Retires the "getfacl absent so ACLs are unknown" blocker outright. |
| `joshlf/go-acl` | **STEAL_PATTERN, do not depend** | R1-F17 | Permissive and CGO-free but unmaintained since 2020. Take its two-pass `Getxattr` sizing idiom; leave the module. |
| `pkg/xattr` | **REJECT (marginal)** | R1-F44 | A perfectly good library that adds a module for zero capability — `golang.org/x/sys/unix` already exposes `Getxattr`. |
| Go stdlib `io/fs.WalkDir` + `os` | **REUSE** | R1-F20 | Documented-cheaper primitive, does not follow symlinks. Combined with mandatory `lstat`-first (a FIFO `cat` hung the full timeout while `lstat` answered instantly). |
| `openat2(RESOLVE_NO_SYMLINKS)` | **BUILD as optional hardening** | R1-F21 | Linux 5.6+; must degrade via `ENOSYS` capability detection, never a version check. |

## 4. BMC in-band access — **the strongest BUILD case in the track**

| Option | Verdict | Facts | Reasoning |
|---|---|---|---|
| **Read `/sys/devices/platform/ipmi_bmc.N/*` (0444)** | **BUILD** | R1-F25, R1-F49, R1-F50 | The only path yielding real BMC identity unprivileged — the same payload a Get Device ID returns, no privilege, no device open. `guid`'s presence is transitive proof the kernel completed a KCS transaction. **No tool we found does this.** |
| **`readdir` on `/sys/firmware/dmi/entries`, matching `38-*` / `42-*`** | **BUILD** | R1-F26 | Entry files are 0400 but the entry directories are 0755 and named `<type>-<instance>`. A plain listing proves the firmware declares an IPMI device and a Redfish host interface without reading one root-only byte. |
| **`stat` the three ipmitool device paths, retaining errno per path** | **BUILD**, pattern stolen from ipmitool, code not | R1-F23, R1-F27 | Gives "exists but not permitted" vs "absent" correctly — which ipmitool itself gets wrong. |
| **`/proc/devices` + `/proc/modules` corroboration** | **BUILD** | R1-F24 | World-readable and always permitted; proves the driver holds a major even under EACCES. Trap: the registered name is `ipmidev`, not `ipmi0`. |
| `ipmitool` | **REJECT** | R1-F23, R1-F27 | Licence is fine (BSD-3). Absent from the host, needs `O_RDWR` on a root-only node, and misreports EACCES as ENOENT. |
| FreeIPMI | **REJECT** | R1-F23 | GPLv3 licensing blocker **and** still needs the root-only device. |
| `u-root/pkg/ipmi`, `bougou/go-ipmi`, `vmware/goipmi` | **REJECT** | R1-F28 | Permissive, Go, CGO-free — and zero-valued: they all open the 0600 root:root node. Capability fidelity in one line. |
| osquery | **REJECT — no such capability exists** | R1-F29 | Proven absence by search: no IPMI/BMC table in master; the 2017 attempt was closed unmerged. |
| In-band Get Device ID via ioctl | **REJECT** for our host, and do not implement generically | R1-F25, R1-F48 | Strictly dominated by the sysfs path: same payload, no privilege, less hang risk. |
| Redfish over the host interface | **REJECT for querying** / **BUILD for detecting** | R1-F26 | Querying requires network I/O to the BMC, which the sensor forbids; but the type-42 advertisement and the USB NIC's DOWN operstate are valuable read-only findings. |

## 5. Kernel hardening / boot chain

| Option | Verdict | Facts | Reasoning |
|---|---|---|---|
| **efivars Secure Boot / Setup Mode read** | **BUILD**, byte-offset technique **STEAL_PATTERN**-ed from osquery | R1-F30, R1-F31, R1-F32 | One bounded 5-byte read; importing anything would be absurd. The 4-byte attribute prefix is a real correctness trap worth citing. |
| osquery `secureboot` / `kernel_info` / `sysctl` tables | **STEAL_PATTERN** / **REJECT as dependency** | R1-F9, R1-F32 | Its silent-omission-on-read-failure is the exact behaviour the brief calls a critical failure. |
| **`/proc/sys/kernel/tainted` bit decode** | **BUILD**, bit table **STEAL_PATTERN**-ed as *data* from kernel Documentation | R1-F33 | Trivial to implement; the only way to get it wrong is to invent the table instead of citing it. |
| **CPU vulnerabilities enumeration** | **BUILD** | R1-F34 | 0444, no fallback logic needed. Enumerate the directory — the file set is kernel-version dependent. |
| `mokutil` shell-out | **REJECT as primary**, optional bounded cross-check only | R1-F31 | Absent on most hosts, and adds a subprocess where a file read suffices. |
| Lynis BOOT-*/KRNL-*/HRDN-* | **STEAL_PATTERN, behaviour only** | R1-F9 | GPLv3 blocks code reuse. **Not read at source in this pass — see PROVENANCE G5-1.** |
| `kernel-hardening-checker` rule table | **REJECT (provisional, unevaluated)** | — | Over-scope for a handful of thoughtful checks (contract C9). Formally unchecked. |
| `canonical/go-efilib` | **REJECT (provisional, unevaluated)** | R1-F30 | The capability is a 20-line file read. |

## 6. Check framework / evidence model / bounded execution / schema validation

| Option | Verdict | Facts | Reasoning |
|---|---|---|---|
| `santhosh-tekuri/jsonschema/v6` v6.0.3 | **REUSE — test-only** | R1-F38, R1-F39, R1-F40, R1-F43 | Apache-2.0, all five drafts, measured at 2 modules. Because a test-only import is not linked, it costs the shipped binary nothing. |
| `xeipuuv/gojsonschema` | **REJECT** | R1-F41 | draft-07 ceiling, dependencies pinned to 2018. Popularity is not draft coverage. |
| `kaptinlin/jsonschema` | **REJECT** | R1-F42 | Silently forced a Go 1.27 toolchain bump; YAML + i18n tree. |
| `qri-io/jsonschema` | **REJECT** | — | Dormant. Explicitly flagged as not fully checked. |
| Hand-rolled validator | **REJECT** | R1-F38 | Re-implementing `$ref`/`$dynamicRef` resolution is the "four-hour exercise becomes ten hours" trap for zero credit. |
| `golang.org/x/sys` | **REUSE — shipped** | R1-F44, R1-F17 | BSD-3, pure Go, zero transitive deps, effectively an extension of the stdlib. Required for the ACL reader and `openat2`. **The only third-party runtime dependency we take.** |
| **Bounded subprocess runner** | **BUILD**, pattern **STEAL_PATTERN**-ed from the `os/exec` docs | R1-F45, R1-F46 | ~40 lines beats importing anything. The naive `exec.CommandContext(...).Output()` does not satisfy E2. |
| **Out-of-band deadline for uncancellable reads** | **BUILD** | R1-F48, R1-F20 | Neither `context` nor `WaitDelay` helps inside a blocking `read()` on a wedged BMC or a FIFO. Needs `lstat`-first plus a goroutine whose result is abandoned on timeout. |
| osquery as a dependency | **REJECT** | R1-F9 | C++ daemon, not linkable from Go. |
| Declarative rule engine (Wazuh SCA / kube-bench style) | **REJECT — over-engineering** | — | At 3–6 checks per category (contract C9), a rule engine costs more than it saves and adds a parser to the trusted path. |

## Recommended minimal dependency list

| Module | Version | Licence | Approx. size | Shipped? | Why |
|---|---|---|---|---|---|
| `golang.org/x/sys` | v0.48.0 | BSD-3-Clause | single module, **zero transitive deps** | **yes (runtime)** | `Getxattr` for the POSIX-ACL reader, `Statfs` for filesystem-boundary detection, `Openat2` for optional symlink confinement. No stdlib equivalent. [R1-F44, R1-F17, R1-F21] |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Apache-2.0 | 2 modules, 15 linked pkgs (measured) | **no — test-only** | Validates output against the real `finding.schema.json` under whichever draft it turns out to use. Not linked into the sensor. [R1-F38, R1-F40, R1-F43] |

Everything else is the Go standard library. Total third-party runtime surface: **one module with no transitive dependencies.**
Mitigation for R1-OR5 (unknown build expectations): run `go mod vendor` and ship the vendor directory, so the tarball builds offline either way — negligible cost given the size above.
