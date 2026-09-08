# R1 — STOLEN PATTERNS CATALOG

Techniques to re-implement, each with the source location it came from and how it applies to the sensor. Licence discipline: patterns from osquery are taken under the **Apache-2.0** arm of its dual licence; patterns from Lynis (GPLv3), Wazuh (GPLv2) and FreeIPMI (GPLv3) are **behavioural observations only** — no code is copied from them. Full per-stream detail lives in `streams/S1.md` … `streams/S6.md`.

---

## A. Evidence-model patterns (the exercise's real content)

**SP-1 — Pointer-or-nil for "explicit unknown", with the errno retained.**
Source: `prometheus/procfs` `sysfs/class_dmi.go:64` (regular-files-only) and `:74-81` (`os.IsPermission(err)` → `continue`, commented *"Only root is allowed to read the serial and product_uuid files!"*).
Apply: every machine-description field is `*string` / `*uint64`, never `""` or `0`. Where procfs merely skips, we go one better and store the errno alongside the nil so the finding can say *why*. Directly satisfies contract B6. [R1-F7]

**SP-2 — Reason taxonomy for "did not run".**
Source: Lynis `include/functions:2707-2764` (`SKIPREASON` enumeration). Behaviour only — GPLv3.
Apply: fix a closed vocabulary for the `reason` field — `EACCES`, `ENOENT`, `UTILITY_MISSING`, `UNSUPPORTED`, `TIMEOUT`, `BUDGET_EXCEEDED`, `EXECUTION_ERROR`, `RESTRICTED_CONTENT` — so reasons are machine-comparable across runs rather than free prose. Steal the taxonomy; **reject Lynis's behaviour of skipping silently.** [R1-F56]

**SP-3 — Nine-value result model collapsed into three, with the loss carried by `reason`.**
Source: XCCDF result enumeration (NIST IR 7275 Rev 4). **Status LIKELY — both NIST URLs were blocked (403/404 and a landing page); this is an unfetched primary, not a disproven one.**
Apply: our schema fixes `pass|fail|unknown`, which merges XCCDF's `error`, `unknown`, `notchecked` and `notapplicable`. The mapping tells us precisely what `reason` must distinguish, and gives NOTES.md a principled account of why three values are enough. [R1-F57]

**SP-4 — Invert osquery's silent return.**
Source: osquery `osquery/tables/system/linux/secureboot.cpp` @5.15.0 — `if (!readFile(efivarPath, efiData, 5).ok()) { return; }`, emitting no row on failure.
Apply: the check runner emits exactly one finding per registered check **by construction**; a failed read becomes `unknown` carrying the path and errno. Cite this contrast in NOTES.md — mature prior art commits the exact failure the brief calls critical. [R1-F32]

**SP-5 — Three distinct not-answered reasons, never collapsed.**
Source: composed from LOCAL_REPRO observations — `ENOENT` on `/sys/kernel/security/lockdown` (feature absent), `EACCES` on `/dev/ipmi0` (present, not permitted), and a *successful* read of zeroed `/proc/kallsyms` under `kptr_restrict=1` (content degraded).
Apply: the third case is the dangerous one and no prior art we read flags it. Any check consuming kernel addresses must treat all-zero as "restricted", not as a value. [R1-F35, R1-F36]

**SP-6 — EACCES on a file is an answer; EACCES on a directory is not.**
Source: stream S3 contradiction C2.
Apply: `EACCES` on a *file* after a successful `lstat` fully answers "it exists and we may not read it" → a legitimate `pass`/`fail`. `EACCES` on `readdir` means absence is unprovable → genuine `unknown`. Encodes the project law "absence is only provable from a successful listing". Named as the likeliest bug in the secrets check family. [R1-F22]

---

## B. Unprivileged-access patterns

**SP-7 — Prefer the world-readable interface over the root-only one, and record the rejected path.**
Source: osquery `secureboot.cpp` @5.15.0, comment weighing `/sys/firmware/efi/vars` (root) against `/sys/firmware/efi/efivars` (world readable) and choosing the latter because *"the benefit of not requiring root outweighs that"*.
Apply: promote to a design law for the whole sensor. When two paths yield the same fact, take the one that works at uid 1000 **and put the rejected path in evidence**, so a reader knows we tried rather than failed to think of it. [R1-F31]

**SP-8 — efivars 4-byte attribute skip.**
Source: kernel `Documentation/filesystems/efivarfs.rst` (*"4_bytes_of_attributes + efivar_data"*), implemented in osquery `secureboot.cpp` as `readFile(path, data, 5)` then `data.back()`.
Apply: read exactly 5 bytes of `SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`, require length 5, take index **4**; 0 → disabled, 1 → enabled, anything else → `unknown` with the raw byte as evidence. Same for `SetupMode-…`. A reader that takes byte 0 is confidently wrong. [R1-F30]

**SP-9 — Directory-name-as-evidence for root-only data.**
Source: kernel `drivers/firmware/dmi-sysfs.c:607-608` (`kobject_init_and_add(..., "%d-%d", dh->type, entry->instance)`) with `fs/sysfs/dir.c:59` proving the directory is 0755 and listable, while the entry *files* are 0400 (`dmi-sysfs.c:57-61,74-78`).
Apply: a generic helper that extracts structured facts from **names** in a listable directory whose contents are denied. A plain `readdir` proves the firmware declares SMBIOS type 38 (IPMI device) and type 42 (Redfish host interface) with no root and no hang risk. Reusable for any `type-instance` DMI structure. **Converts a root-only data source into an unprivileged presence oracle.** [R1-F26]

**SP-10 — Kernel-as-proxy-prober.**
Source: kernel `drivers/char/ipmi/ipmi_msghandler.c:2941-2946` — the `guid` attribute is exposed only when the kernel actually obtained a GUID from the controller.
Apply: the *presence* of that attribute is transitive proof the kernel completed a real KCS transaction with the BMC. In-band reachability becomes provable without ever opening `/dev/ipmi0`. [R1-F49]

**SP-11 — Second, always-permitted corroboration path.**
Source: `ipmi_devintf.c:792` (`#define DEVICE_NAME "ipmidev"`) and `:869` vs the node name at `:827`.
Apply: grep world-readable `/proc/devices` for `ipmidev` (**not** `ipmi0` — the name mismatch is the trap) to prove the driver holds a major even when the node is EACCES. Generalises: for every privileged artefact, look for an unprivileged corroborator. [R1-F24]

**SP-12 — udev database instead of a privileged device open.**
Source: `gopsutil` `disk_linux.go:604-664`, reading `/run/udev/data/b<major>:<minor>`.
Apply: disk model, serial, WWN, fstype and UUID unprivileged with no subprocess and no device open — recovering most of what `lsblk`/`blkid` would give. `blkid` as uid 1000 prints nothing and exits 0, which is worse than an error. [R1-F11, R1-F12]

**SP-13 — Pure-Go POSIX ACL decode.**
Source: kernel UAPI `include/uapi/linux/posix_acl_xattr.h:24,29-37` — version magic `0x0002` then 8-byte `{le16 tag, le16 perm, le32 id}` entries. Sizing idiom from `joshlf/go-acl` (two-pass `Getxattr`), taken as an idiom, not a dependency.
Apply: ~30 lines of `unix.Getxattr` + `binary.LittleEndian` answers "who can read this" even though `getfacl` is absent from the host. Byte-verified locally against `/var/log/journal`. **Caveat: `ACL_MASK` must be ANDed with `ACL_USER`/`ACL_GROUP` permissions or the answer over-states access.** [R1-F17]

**SP-14 — Effective config from the daemon itself, before it needs privilege.**
Source: OpenSSH `sshd.c:1619-1620` and `:1815-1816` (the `-G` path) versus the host-key loop at `:1831-1936` and its fatal at `:1933-1936`.
Apply: `sshd -G` returns the daemon's own effective configuration *before* the host-key load that makes `sshd -T` fail unprivileged. Use it as the oracle (bounded exec, per SP-17) and keep our own parser as a cross-check. Ceiling: `-G -C` fatals (`sshd.c:1741-1747`) despite `sshd.8:157-165` claiming otherwise, so Match-conditional policy stays an explicit bounded unknown. [R1-F47, R1-F51]

**SP-15 — Include-aware, first-match-wins config resolution.**
Source: OpenSSH `servconf.c:108/139` (sentinels) with guards at `:1404/:1485/:1555`, and `Include` expansion at `:2128-2215` (inline, glob-sorted, non-fatal on no match).
Apply: our parser must expand `Include` inline in glob order and honour first-match-wins. Ubuntu puts `Include` on line 1, so the drop-in wins — a naive top-to-bottom read of `sshd_config` reports **the opposite** of what is in force on this host. Evidence must name the file and line that actually won. [R1-F52]

**SP-16 — `/proc/net/tcp` over `ss`, and claim only what is provable.**
Source: `ss -ltnp` degradation (LOCAL_REPRO: exit 0, header present, Process column blank) against the `PTRACE_MODE_READ_FSCREDS` gate on `/proc/<pid>/fd` documented in `proc_pid_fd(5)`.
Apply: read `/proc/net/tcp{,6}` and `/proc/net/unix` directly for owning uid and socket inode. Report "a socket listens on :22 owned by uid 0" as `pass`; report "sshd owns it" as `unknown` with the ptrace gate as the reason. Never treat `ss`'s blank column as evidence. [R1-F53]

---

## C. Safety / bounded-execution patterns

**SP-17 — Bounded child process that actually terminates.**
Source: Go `os/exec` documentation — `Cmd.Cancel` and `Cmd.WaitDelay`.
Apply: `cmd := exec.CommandContext(ctx, …)`; `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`; `cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }`; `cmd.WaitDelay = <small>`; stdout/stderr into a capped writer. The default `exec.CommandContext(...).Output()` kills only the direct child and then blocks in `Wait` on pipes a grandchild still holds. [R1-F45, R1-F46]

**SP-18 — `lstat` first, and never rely on `O_NONBLOCK`.**
Source: LOCAL_REPRO — `cat` on a FIFO hung for the full `timeout 2` (exit 124) while `lstat` reported `S_ISFIFO` before any open.
Apply: `lstat` → confirm `S_ISREG` → only then open. This is the mechanism; `O_NONBLOCK`/`O_NOFOLLOW` are belt-and-braces. Satisfies "nothing hangs forever on a device that does not answer". [R1-F20]

**SP-19 — Out-of-band deadline for uncancellable reads.**
Source: kernel `drivers/char/ipmi/ipmi_kcs_sm.c:103-106` — 5 s IBF + 5 s OBF timeouts with up to 10 retries, matching IPMI v2.0 §9.20; and `ipmi_msghandler.c` `device_id_show` → `send_get_device_id_cmd`.
Apply: **the "safe" 0444 BMC sysfs read is not free** — it triggers a live IPMI transaction that can block for tens of seconds inside `read()`, and a Go goroutine cannot be cancelled mid-syscall. The BMC check needs a goroutine whose result is *abandoned* on timeout, plus a whole-scan budget, degrading to `unknown` with `TIMEOUT` as the reason. Counter-intuitive and easy to miss. [R1-F48]

**SP-20 — Per-path errno retention (invert ipmitool's bug).**
Source: `ipmitool` `src/plugins/open/open.c:102-118` — tries `/dev/ipmi0`, `/dev/ipmi/0`, `/dev/ipmidev/0` but overwrites `errno` on each retry and reports only the last, so EACCES on the first path surfaces as ENOENT (corroborated by Debian bug #866574).
Apply: steal the **path list** (it encodes real devfs-era layout variation we would otherwise miss); invert the **control flow** — `lstat` each candidate, store `(path, err)` for *every* candidate, and resolve with explicit precedence: any `EACCES` outranks every `ENOENT`, a successful `stat` outranks both. Never `open()` at all. [R1-F27]

**SP-21 — Central read-limit and glob-depth budget.**
Source: osquery's `read_max` / `kMaxRecursiveGlobs` / `checkFileReadLimit` design.
Apply: one place that enforces max bytes per file, max files per walk, max directory depth and max wall time, so no individual check can decide to be expensive. Satisfies E6 ("no heavy I/O on hardware other people depend on").

**SP-22 — Header-only credential classification instead of content scanning.**
Source: OpenSSH `PROTOCOL.key:8-19` — `ciphername` is second in the header and the key material is structurally last; contrast gitleaks' private-key regex at `gitleaks.toml:2784-2788`, which must consume ≥64 characters of key body to match.
Apply: `ciphername == "none"` proves an **unencrypted on-disk SSH key** from roughly the first 48 decoded bytes, with provably zero leak risk. Combined with RFC 7468 PEM armor labels and DER/PKCS#12 magic bytes, this gives `detected_type` for every credential file without ever ingesting secret material. **This is the single best argument that we do not want content scanning at all.** [R1-F18, R1-F19]

**SP-23 — Capability detection, never version comparison.**
Source: `openat2` availability (Linux 5.6+) and its `ENOSYS` failure mode.
Apply: attempt the syscall, fall back to the portable `lstat` + `O_NOFOLLOW` + `st_dev` path on `ENOSYS`. Never parse a kernel version string to decide. Same rule for every optional capability in the sensor — it is the concrete form of "gate on capabilities/evidence, never on hostname or vendor". [R1-F21]

**SP-24 — Test-only conformance gate.**
Source: Go build/link semantics, measured (`go list -deps` for a `main` package excludes test-only imports).
Apply: import the JSON-schema validator **only** from `_test.go`. The shipped binary's third-party runtime surface stays at exactly one module (`golang.org/x/sys`) with zero transitive dependencies, while schema conformance is still proven against the real `finding.schema.json` and against the real host output. [R1-F43]
