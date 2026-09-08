# R1 — Build vs Buy for the Lava posture sensor

**Verdict in one line:** build the sensor from the Go standard library plus exactly **one** third-party runtime module (`golang.org/x/sys`), steal a specific, cited catalogue of techniques from osquery, OpenSSH, gopsutil, prometheus/procfs, ipmitool and the kernel's own documentation, and take a JSON-schema validator as a **test-only** dependency so the shipped binary carries no schema machinery at all.

The reason is not a preference for writing code. It is that **every mature tool in this space either cannot reach the data as uid 1000, or reaches it and then destroys the evidence** — and the evidence is what this exercise is actually grading. Three independent, widely-deployed tools were found committing the precise failure the brief calls critical: claiming to have checked when they could not [R1-F32, R1-F27, R1-F55].

Full per-stream evidence with pinned commits and line numbers is in `streams/S1.md` through `streams/S6.md`. Verdict table: `BVB_MATRIX.md`. Techniques: `STOLEN_PATTERNS.md`. Blast-radius analysis: `PROPAGATION_NOTES.md`.

---

## 1. Machine identity and hardware inventory

The kernel draws a hard, deliberate line here, and it settles the whole question. `drivers/firmware/dmi-id.c:41-62` hardcodes mode **0400** on exactly four attributes — `product_serial`, `product_uuid`, `board_serial`, `chassis_serial` — and **0444** on everything else [R1-F1]. Every raw SMBIOS route is likewise root-only: `/sys/firmware/dmi/tables/{DMI,smbios_entry_point}` are `S_IRUSR` (`dmi_scan.c:757-758`), `/sys/firmware/efi/systab` is 0400 (`efi/efi.c:157`), and `/dev/mem` is `root:kmem` [R1-F2].

That means vendor, model and family are readable at uid 1000 while serial and UUID are not, **for every tool equally**. No library can beat direct sysfs reads on coverage, because there is no coverage to be had. u-root's `pkg/smbios` and `digitalocean/go-smbios` are correct code pointed at unreachable data [R1-F2]; `zcalusic/sysinfo` documents a superuser requirement and its shipped example calls `log.Fatal` as non-root, which safety requirement E3 alone disqualifies [R1-F8].

So libraries can only compete on **evidence quality**, and this is where they lose badly.

`ghw` advertises "No root privileges needed for discovery" on README line 14 and then documents permission-denied warnings on lines 1045-1051 [R1-F4]. The source resolves it: `pkg/linuxdmi/dmi_linux.go:33-37` converts *any* DMI read error — EACCES included — into the untyped literal string "unknown", with no errno and no error return [R1-F3]. Our schema requires a `reason`; ghw deletes exactly the information the reason needs. Worse, `pkg/memory/memory_linux.go:28,41-52,209-236` scrapes `/var/log/syslog` for installed RAM and **silently substitutes usable RAM when that fails** [R1-F5] — and the Lava host's login user is in `ubuntu sudo` but not `adm`, so syslog is unreadable and ghw would report a plausible, wrong number with no unknown marker. Under contract B6 that is the worst possible outcome.

`gopsutil` has the right *techniques* — its host-id ladder and its udev-database route at `disk_linux.go:604-664` — but `HostID()` returns an empty string with a nil error on total failure [R1-F6], the empty string the brief explicitly forbids. `prometheus/procfs` is the one library that already models this correctly: `sysfs/class_dmi.go` uses a pointer per field, reads regular files only (`:64`), and has an explicit `os.IsPermission(err)` continue branch commented "Only root is allowed to read the serial and product_uuid files!" (`:74-81`) [R1-F7]. It is a genuine REUSE candidate and, at minimum, the shape to copy.

Two false-negative traps are worth naming because they are silent. osquery's `disk_encryption` table returns **zero rows** when non-root (`disk_encryption.cpp:111-114`), indistinguishable from "nothing is encrypted" [R1-F10] — on the Lava host, which genuinely has no dm-crypt, the correct answer requires proving absence by successful listing, which osquery cannot evidence. And `blkid` as uid 1000 prints nothing and **exits 0**, because the block devices are `brw-rw---- root:disk` [R1-F11]. Silent empty success is worse than an error.

The unprivileged data that *does* exist is ample: `/etc/machine-id` at 0444, full CPU topology under `/sys/devices/system/cpu/*/topology/`, and disk model, serial, WWN, fstype and UUID from the world-readable udev database at `/run/udev/data/b<major>:<minor>` [R1-F12]. One nuance the contract's ambiguity register (B3c) anticipated: installed RAM and `MemTotal` genuinely differ — measured locally at 8064 MiB installed versus 7721 MiB visible [R1-F13] — so "memory" needs a named source, not a number.

**Verdict: BUILD**, with `prometheus/procfs` as a REUSE candidate and its pointer-or-nil pattern as the minimum steal.

## 2. Effective remote-access policy

This area produced the single verdict reversal of the track.

The assumption going in — reinforced by the host snapshot, where `sshd -T` as uid 1000 returns "no hostkeys available -- exiting" — was that effective sshd policy is root-only and must be re-derived by parsing. That assumption is wrong, and the source says why. OpenSSH 9.6p1 has `sshd -G`, and it dumps the effective configuration **before** host-key loading: the `-G` path is at `sshd.c:1619-1620` and `:1815-1816`, while the key loop that produces the observed fatal is at `:1831-1936` with the fatal itself at `:1933-1936` [R1-F47]. `-T` fails precisely because it loads keys first. `-G` returns before that point.

That hands us the daemon's own answer — Include expansion and first-match-wins precedence already resolved by the implementation that enforces them — instead of us re-implementing OpenSSH's semantics and hoping we match. It is the difference between reporting what is in force and reporting what we think is in force. **This is the one blocking observation request in the track (R1-OR9)**, because it decides which component is load-bearing.

It has a hard ceiling: `sshd -G -C <connspec>` **fatals** at `sshd.c:1741-1747` even though `sshd.8:157-165` documents the combination as supported [R1-F51]. Code beats man page. So we get global effective config with no Match-block evaluation, and Match-conditional policy becomes an explicitly bounded unknown rather than a silent omission.

We build the Include-aware parser anyway, for three things `-G` cannot give: a fallback, file-and-line provenance for the evidence block, and a free correctness cross-check. And the parsing semantics matter enormously on this host. OpenSSH is first-match-wins (`servconf.c:108/139` sentinels, guards at `:1404/:1485/:1555`), and `Include` expands **inline**, glob-sorted, non-fatal on no match (`servconf.c:2128-2215`). Ubuntu puts `Include /etc/ssh/sshd_config.d/*.conf` on **line 1**, so the drop-in wins [R1-F52]. A sensor that reads `sshd_config` top-to-bottom without expanding includes reports **the opposite** of what is in force here. That is the most likely way this category produces a confidently wrong answer.

For listeners, `ss -ltnp` degrades by silent omission as uid 1000 — exit 0, header present, Process column blank — because inode-to-pid mapping needs `/proc/<pid>/fd`, gated by a `PTRACE_MODE_READ_FSCREDS` check. `/proc/net/tcp` by contrast is fully readable and gives owning uid and socket inode for *other users'* sockets [R1-F53]. So "a socket listens on :22 owned by uid 0" is provable and "sshd owns it" is permanently unknown for another user's process. The check must claim exactly the first and explicitly decline the second — and must never read anything into ss's blank column.

Socket activation complicates both "is sshd running" and "who owns :22": Ubuntu switched at `1:9.0p1-1ubuntu1` (22.10), and on 24.04 the listening address is derived from `sshd_config` by a systemd generator, with the listening fd moving from pid 1 to the service after first activation under `Accept=no` [R1-F54 — LIKELY only; Debian's actual `ssh.socket` text could not be fetched, see R1-OR10]. The fix is to assert the *activation path* from world-readable unit files plus `systemctl is-active` (verified to work unprivileged), never a pid.

On sudo: `/etc/sudoers` (0440) and `/etc/sudoers.d` (0750) are unreadable on the target. "Who can escalate" must therefore be `unknown` with a separate, provable group-membership observation beside it — never policy inferred from group membership.

**Verdict: REUSE `sshd -G` as the oracle (pending R1-OR9), BUILD the parser and the listener primitives, REJECT ss as evidence.**

## 3. Secrets on disk

The central question here is not which scanner to use — it is whether we want content scanning **at all**. The answer is no, and the argument is a safety argument, not a preference.

Start with a correction to our own brief. The R1 prompt asserted that gitleaks had been relicensed away from MIT. That is **false**: gitleaks is MIT at HEAD (v8.30.1), and its LICENSE file has three commits total, the newest dated 2019-12-04 [R1-F14]. Rejecting it for a licence myth would have been a checkable error in front of the customer.

The real reason to reject it is better. gitleaks does **not** redact by default — `--redact` defaults to 0 at `cmd/root.go:86-87` (the `NoOptDefVal=100` applies only to a bare flag) — and `report/finding.go:14-55` serialises the raw `Secret` and `Match` fields, excluding only `Line` [R1-F15]. Embedding it would make our own `findings.json` a **new secret-bearing artifact on the customer's disk**. trufflehog is worse on two independent axes: AGPL-3.0 (a hard licensing blocker) and it verifies discovered credentials against live third-party APIs **by default** (`main.go:60`, `main.go:643`) — violating the no-network invariant in the most dangerous way imaginable [R1-F16]. 430 modules versus gitleaks' 144 is a distant third reason.

The capability-level argument is the one to put in NOTES.md. Private-key regexes structurally require ingesting key material: gitleaks' rule at `gitleaks.toml:2784-2788` must consume at least 64 characters of the base64 body to match [R1-F19]. Header-only classification does not. OpenSSH's `PROTOCOL.key:8-19` puts `ciphername` **second** in the header with the key material structurally **last**, so a `ciphername` of "none" proves an *unencrypted on-disk SSH key* from roughly the first 48 decoded bytes, with provably zero leak risk [R1-F18]. That is a high-value finding obtained safely. Content scanning buys only "secrets embedded in arbitrary files" — a lower-value finding at much higher risk. Declaring this as a scope decision is honest; omitting it silently would not be.

The other significant result here retires a blocker we thought we had. `getfacl` is absent from the Lava host, which looked like it made "who can read this" unanswerable. It does not: POSIX ACLs are decodable in pure Go from the `system.posix_acl_access` xattr, whose format is pinned by kernel UAPI (`posix_acl_xattr.h:24,29-37`: version `0x0002`, then 8-byte tag/perm/id entries) [R1-F17]. This was **byte-verified locally on a machine with no getfacl, setfacl or getfattr installed at all** — `/var/log/journal` returned 44 bytes = 4 + 8x5, decoding to the exact systemd ACL. Roughly 30 lines of `unix.Getxattr` plus `binary.LittleEndian`. One caveat carried forward: `ACL_MASK` must be ANDed with `ACL_USER`/`ACL_GROUP` permissions or the answer over-states access.

Two safety findings govern traversal. `lstat`-first is **mandatory** and `O_NONBLOCK` is not a substitute: a local reproduction had `cat` on a FIFO hang for the full 2-second timeout (exit 124) while `lstat` reported `S_ISFIFO` before any open [R1-F20]. And `openat2` with `RESOLVE_NO_SYMLINKS` is Linux 5.6+, so it is optional hardening behind an `ENOSYS` fallback, never the mechanism and never a version-string comparison [R1-F21].

Finally, the distinction most likely to produce a bug in this family: **EACCES on a file after a successful `lstat` is a complete answer** (it exists, we may not read it); **EACCES on `readdir` is a genuine unknown** (we cannot enumerate, so absence is unprovable) [R1-F22].

**Verdict: REJECT content scanning as a capability; BUILD the ACL reader and the bounded walker; REUSE stdlib `WalkDir` and `golang.org/x/sys`.**

## 4. BMC in-band access

This is the strongest BUILD case in the track, and the buy options are not close.

Every external option is gated on `/dev/ipmi0`, and the reason it is `crw------- root root` is now a closed proof rather than a guess: `ipmi_devintf.c:810-812` registers `ipmi_class` with **no devnode callback**, and `devtmpfs.c:122-130` therefore applies mode 0600 (with `core.c:3913-3931` showing `device_get_devnode()` only writes a mode when a class or type supplies one) [R1-F23]. That matters for what we *report*: the EACCES on the Lava host is the **stock upstream Linux default**, not a Supermicro or Latitude.sh hardening decision. Calling it a misconfiguration would be wrong.

Because the gate is a kernel default rather than a site choice, unprivileged reuse of ipmitool, FreeIPMI, u-root's `pkg/ipmi`, `bougou/go-ipmi` or `vmware/goipmi` is not *degraded* — it is **zero-valued**. u-root's is the clearest illustration: permissive licence, Go, CGO-free, and it calls `os.OpenFile(path, os.O_RDWR, 0)` on a node we cannot open [R1-F28]. Licence and language are fine and completely irrelevant. FreeIPMI adds a GPLv3 licensing blocker on top. And osquery has **no IPMI/BMC table at all** — proven by search, with a 2017 attempt closed unmerged over native-library and per-vendor breakage [R1-F29]. There is no prior art to reuse.

Meanwhile the two paths that *do* work unprivileged are used by no tool we found and are a few dozen lines of stdlib each.

First, the BMC identity attributes under `/sys/devices/platform/ipmi_bmc.N/` are all **0444** (`ipmi_msghandler.c:2758-2911`) [R1-F25, R1-F50], yielding IPMI version, firmware revision, manufacturer id, product id, device id and GUID — the same payload a Get Device ID command would return, with no privilege and no device open. Better, `guid` is exposed only when the kernel actually obtained one from the controller (`ipmi_msghandler.c:2941-2946`) [R1-F49], so **its presence is transitive proof that the kernel completed a real KCS transaction with the BMC**. In-band reachability becomes provable without touching the device node.

Second — and this is the most transferable find in the track — DMI entry *files* are 0400 root-only, but the entry *directories* are 0755 and named `<type>-<instance>` (`dmi-sysfs.c:607-608`, with `fs/sysfs/dir.c:59` for the mode) [R1-F26]. A plain `readdir` therefore proves the firmware declares SMBIOS type 38 (IPMI device) and type 42 (Redfish host interface), unprivileged, with no hang risk. **The directory name is the data.** A root-only source becomes an unprivileged presence oracle.

Two traps. The chrdev registers the name "ipmidev" (`ipmi_devintf.c:792`, `:869`) while the node is `ipmi%d` (`:827`), so world-readable `/proc/devices` shows `238 ipmidev` and never `ipmi0` — a sensor grepping for `ipmi0` finds nothing and wrongly concludes absence [R1-F24]. And ipmitool clobbers `errno` across three `open()` attempts (`open.c:102-118`), printing only the last, so on our exact host configuration it reports "No such file or directory" for a device that demonstrably exists (corroborated by Debian bug #866574) [R1-F27]. We steal its path list — it encodes real devfs-era layout variation — and invert its control flow.

The counter-intuitive finding sits here too: **the "safe" 0444 sysfs read is not free.** `device_id_show` calls `send_get_device_id_cmd`, a live IPMI transaction, and kernel KCS timeouts are 5 s IBF plus 5 s OBF with up to 10 retries (`ipmi_kcs_sm.c:103-106`), matching IPMI v2.0 section 9.20 [R1-F48]. Against a wedged BMC that is tens of seconds inside an **uncancellable** `read()` — a Go goroutine cannot be interrupted mid-syscall. This check needs an out-of-band deadline (a goroutine whose result is abandoned) plus the whole-scan budget, not a naive context. This is exactly the "nothing hangs forever on a device that does not answer" case the brief names, and it would have been very easy to miss.

**Verdict: BUILD, decisively.**

## 5. Kernel hardening and boot chain

The customer's own benchmark example for a custom category, and it is largely, cleanly answerable unprivileged — contrary to the common assumption.

Secure Boot is the case in point. The usual claim is that it needs root or mokutil. It does not: `/sys/firmware/efi/efivars` is **world readable** while the older `/sys/firmware/efi/vars` is root-only, and osquery chose efivars *specifically* for that reason, with the comment that "the benefit of not requiring root outweighs that" (`secureboot.cpp` @5.15.0) [R1-F31]. There is a correctness trap: each efivar file carries **4 bytes of little-endian UEFI attributes before the data** (kernel `Documentation/filesystems/efivarfs.rst`: "4_bytes_of_attributes + efivar_data"), so a reader that takes byte 0 gets the wrong answer confidently [R1-F30]. Read 5 bytes, take index 4.

That same osquery function also demonstrates the failure mode we must not copy: on read failure it returns and **emits no row at all** [R1-F32]. Silent omission is what the brief calls a critical failure. Our runner must emit one finding per registered check by construction.

The rest of the category is cheap and solid. `/proc/sys/kernel/tainted` is world-readable, and the kernel's own bit table gives bit 12 (4096) = O, out-of-tree, and bit 13 (8192) = E, unsigned, so the host's **12288 decodes exactly to "unsigned, out-of-tree module loaded"** [R1-F33] — a defensible finding whose evidence is a decode, not a bare integer. The files under `/sys/devices/system/cpu/vulnerabilities/` are 0444 with one file per vulnerability [R1-F34]; the file set is kernel-version dependent (recent kernels add `ghostwrite`, `indirect_target_selection`), so enumerate the directory or the check silently under-reports elsewhere.

Two findings sharpen the evidence model generally. On a kernel without lockdown, `/sys/kernel/security/` is `dr-xr-xr-x` and traversable but **empty**, so the read returns **ENOENT, not EACCES** [R1-F36] — feature-absent and not-permitted are different reasons and must be reported differently. This also withdrew our own briefing assumption that securityfs was root-only. And with `kptr_restrict=1`, `/proc/kallsyms` returns a **successful read of zeroed addresses** to a non-root reader [R1-F35]: a third failure mode beyond EACCES and ENOENT — the read works and the data is false. No prior art we examined flags it.

Genericity is free here: `/sys/firmware/efi` is absent entirely on a non-UEFI system, which makes its existence the correct UEFI discriminator, and `/sys/class/dmi/id` is likewise absent under WSL2 [R1-F37]. On a BIOS host, "Secure Boot disabled" would be a **false fail**; the correct output is an explicit not-applicable with a reason. Usefully, the local WSL lab exercises the no-EFI and no-DMI branches at no cost.

**Verdict: BUILD; steal the efivars byte offset from osquery and the taint bit table, as data, from kernel Documentation.**

## 6. Check framework, evidence model, bounded execution, schema validation

The real finding in this area is a reframing: **schema validation is a test capability, not a runtime one.** Go links only what the built package imports, and a package imported solely from `_test.go` files is not in `go list -deps` for the main package [R1-F43]. Put the validator in tests and the shipped binary carries zero third-party schema machinery — the supply-chain question simply leaves the artifact that runs on the customer's machine.

That makes the choice cheap, which is fortunate, because the real `finding.schema.json` has not been supplied and **we do not know its draft** (contract AM-1). Only one candidate is correct under all three possibilities: `santhosh-tekuri/jsonschema/v6` v6.0.3, Apache-2.0, covering draft-04 through 2020-12 (`draft.go` L27/L53/L66/L80/L103) [R1-F38], measured at exactly **2 modules and 15 linked packages** with the real toolchain [R1-F40]. One hazard to record: it defaults to **2020-12** when `$schema` is absent (`draftLatest = Draft2020`, `draft.go:124`) [R1-F39], and a draft-07 schema validated under 2020-12 differs on ref-with-siblings and tuple-form `items` — so we could pass locally and fail on Lava's validator. Hence R1-OR1.

The alternatives fail on measured facts, not impressions. `xeipuuv/gojsonschema` — by far the most popular — tops out at **draft-07** by its own README, with dependencies pinned to 2018 pseudo-versions [R1-F41]: popularity is not draft coverage. `kaptinlin/jsonschema` **silently raised the toolchain requirement during `go get`** ("go: upgraded go 1.26.2 => 1.27") and drags `goccy/go-yaml`, an i18n stack and a decimal library [R1-F42] — indefensible in a tarball that must build reproducibly.

The one runtime dependency worth taking is `golang.org/x/sys` (v0.48.0, BSD-3-Clause, pure Go, resolved as a single module with **no transitive requirements**) [R1-F44]. It is effectively an extension of the standard library and it is what makes the pure-Go ACL reader, filesystem-boundary detection and `openat2` possible.

On bounded execution, the folklore is wrong and the documentation says so. `exec.CommandContext` "sets the command's Cancel function to invoke the Kill method on its Process, and **leaves its WaitDelay unset**", and `Wait` "waits for any copying to stdin or copying from stdout or stderr to complete" [R1-F45]. So killing the child does not close pipes a *grandchild* still holds, and `Wait` blocks past the deadline — the naive `exec.CommandContext(ctx, ...).Output()` that an LLM emits by default does **not** satisfy safety requirement E2. `Cmd.WaitDelay` exists precisely to bound "a child process that fails to exit after the associated Context is canceled, and a child process that exits but leaves its I/O pipes unclosed", closing the pipes on expiry [R1-F46]. Combined with `SysProcAttr{Setpgid: true}` and a Cancel that kills the process group, that is the whole pattern — about forty lines, and no library needed.

For the evidence model itself, XCCDF's nine result values (pass, fail, error, unknown, notapplicable, notchecked, notselected, informational, fixed) show exactly what our fixed three-value vocabulary collapses, and therefore what the `reason` field must carry [R1-F57 — **LIKELY only: both NIST primary URLs were blocked, 403/404 and a landing page. A blocked fetch is not a disproof**]. Lynis's SKIPREASON taxonomy (`include/functions:2707-2764`) is a ready-made vocabulary to steal — while rejecting its behaviour of skipping silently [R1-F56]. A declarative rule engine in the Wazuh SCA or kube-bench style is over-engineering at 3-6 checks per category (contract C9), and adds a parser to the trusted path.

**Verdict: REUSE `golang.org/x/sys` (shipped) and `santhosh-tekuri/jsonschema/v6` (test-only); BUILD the runner, the bounded-exec wrapper and the evidence model.**

---

## Classification summary (question 3)

Full table with fact citations in `BVB_MATRIX.md`. Headline counts across all six areas:

- **REUSE (2 modules):** `golang.org/x/sys` (shipped) and `santhosh-tekuri/jsonschema/v6` (test-only). Plus one **tool** as an oracle: `sshd -G` via bounded exec, pending R1-OR9. `prometheus/procfs` is a live REUSE candidate for the DMI layer.
- **STEAL_PATTERN (24 catalogued):** osquery (efivars offset, world-readable-path preference, read-limit budgets — Apache-2.0 arm), OpenSSH (`-G` oracle, Include/first-match-wins semantics, PROTOCOL.key header layout), gopsutil (host-id ladder, udev db), prometheus/procfs (pointer-or-nil plus `os.IsPermission`), ipmitool (device path list, control flow inverted), kernel Documentation (taint bits, efivarfs layout, DMI entry naming, KCS timeouts), Lynis (SKIPREASON taxonomy, behaviour only), XCCDF (result-model collapse), `joshlf/go-acl` (two-pass Getxattr idiom).
- **BUILD:** the check runner and evidence model, all sysfs/procfs readers, the Include-aware sshd parser, listener enumeration, the POSIX-ACL reader, the bounded walker, all four BMC evidence paths, all kernel-flag checks, the bounded subprocess wrapper, and the out-of-band deadline.
- **REJECT:** ghw, zcalusic/sysinfo, u-root/pkg/smbios, digitalocean/go-smbios, dmidecode/lshw/inxi/facter/ohai, lsblk/lscpu/blkid as runtime, osquery as a dependency, gitleaks, trufflehog, pkg/xattr, ipmitool/FreeIPMI/u-root-ipmi/bougou-go-ipmi/vmware-goipmi, ssh-audit, ss as evidence, xeipuuv/kaptinlin/qri-io validators, hand-rolled validation, and any declarative rule engine.

**Licensing note kept separate from technical merit, as instructed:** copyleft blockers are trufflehog (AGPL-3.0), FreeIPMI (GPLv3), Lynis (GPLv3), Wazuh (GPLv2) and the GPL-family CLI tools. osquery's dual "Apache-2.0 OR GPL-2.0-only" [R1-F9] means pattern reuse from it is clean. Notably, **gitleaks' licence is fine (MIT)** — it is rejected on safety grounds, and our own brief was wrong to say otherwise [R1-F14].

## What would be stupid to rebuild (question 4a)

1. **JSON Schema validation.** Ref and dynamic-ref resolution, `$vocabulary`, format assertions and five drafts of divergent semantics. Apache-2.0, two modules, and — because it is test-only — literally zero cost to the shipped artifact [R1-F38, R1-F40, R1-F43]. Rebuilding this is the "four-hour exercise becomes a ten-hour one" trap the brief warns about, for zero credit.
2. **Raw syscall bindings.** Getxattr, Statfs, Openat2, Faccessat — hand-rolling these means hand-rolling architecture-specific syscall numbers and struct layouts. `golang.org/x/sys` is BSD-3, pure Go, zero transitive deps [R1-F44].
3. **OpenSSH's effective-config resolution — *if* R1-OR9 confirms `sshd -G` works.** The daemon that enforces the policy is a better authority on the policy than our parser, and it resolves Include ordering and first-match-wins for free [R1-F47]. Re-deriving it and hoping to match is the definition of avoidable risk. We still build the parser, but as provenance and cross-check, not as the oracle.
4. **The kernel's own reference data.** Taint bit meanings, efivar layout, DMI entry naming, KCS timeout values. These are published in kernel Documentation and should be embedded verbatim as data. The only way to get them wrong is to invent them.
5. **PEM/DER structure knowledge.** RFC 7468 armor labels and OpenSSH's PROTOCOL.key header layout are specifications to follow, not formats to guess at [R1-F18].

## What is safer and smaller to own ourselves (question 4b)

1. **The evidence model and the check runner.** This is the graded content. Every candidate framework we examined loses the errno, the path or the distinction between "not permitted" and "not present" — the exact three things the brief asks for. Three independent mature tools were caught doing it: osquery emits no row on read failure [R1-F32], ipmitool reports EACCES as ENOENT [R1-F27], Wazuh SCA emits false FAILs from `sshd -T` with no unknown state [R1-F55]. Owning this is not preference; it is the only way to meet the contract.
2. **Every sysfs and procfs read.** Each is a bounded read of a world-readable regular file. The privileged data is out of reach for *every* option [R1-F1, R1-F2], so no library can beat BUILD on coverage — only on evidence quality, where BUILD wins. Importing a library here buys nothing and costs the errno.
3. **The BMC evidence paths.** All four (0444 BMC sysfs, DMI entry readdir, per-path stat with errno retained, /proc/devices corroboration) are a few dozen lines of stdlib, and **no existing tool implements any of them** [R1-F25, R1-F26, R1-F24, R1-F29]. Every buyable option is gated on a node the kernel ships at 0600 by default [R1-F23], making them zero-valued rather than merely degraded.
4. **The POSIX-ACL reader.** About 30 lines against a kernel-UAPI-pinned format, byte-verified locally, with no dependency and no getfacl [R1-F17]. The alternative library is unmaintained since 2020.
5. **Bounded execution and the out-of-band deadline.** About 40 lines from a documented pattern [R1-F45, R1-F46], plus the abandon-on-timeout goroutine that the BMC's uncancellable read() demands [R1-F48]. Nothing off the shelf handles the syscall-level hang, and this is where the "safe on someone else's machine" requirement actually bites.
6. **Deliberately NOT owned: content secret scanning.** Not built, not imported. Header-only classification delivers the same detected_type with a provably bounded read and zero leak risk [R1-F18, R1-F19]. Stated in NOTES.md as a scope decision, because a silent omission here would be exactly the trust failure the brief describes.

---

## Recommended minimal dependency list (question 5a)

| Module | Version | Licence | Measured size | Shipped? | Why |
|---|---|---|---|---|---|
| `golang.org/x/sys` | v0.48.0 | BSD-3-Clause | 1 module, **zero transitive deps** | **yes (runtime)** | Getxattr for the POSIX-ACL reader, Statfs for filesystem-boundary detection, Openat2 for optional symlink confinement [R1-F44, R1-F17, R1-F21] |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Apache-2.0 | 2 modules, 15 linked pkgs | **no — test-only** | Validates output against the real schema under whichever draft it uses; not linked into the sensor [R1-F38, R1-F40, R1-F43] |

Everything else is the Go standard library. **Total third-party runtime surface: one module with no transitive dependencies.** Mitigation for R1-OR5 (unknown build expectations): run `go mod vendor` and ship the vendor directory so the tarball builds offline either way — negligible cost at this size.

The stolen-patterns catalogue (question 5b) is in `STOLEN_PATTERNS.md`: 24 entries, each with technique, source file and line or pinned commit, and how it applies.

---

## Open items

- **R1-OR9 (blocking)** — confirm `sshd -G` works as uid 1000 on the host. Decides which REMOTE_ACCESS component is load-bearing.
- **R1-OR1 / R1-OR8** — the real `finding.schema.json`: its draft, and whether `additionalProperties` is false anywhere.
- **R1-OR6** — time the BMC sysfs read on the host to size the timeout constant from evidence rather than taste.
- **R1-OR2, OR3, OR4, OR7, OR10** — cheap host reads that upgrade five facts from source-inference to source-plus-reproduction.
- **Research gaps (unfetched, not disproven):** the XCCDF result enumeration (both NIST URLs blocked), SARIF's result model, Lynis kernel/boot test sources, kernel-hardening-checker, canonical/go-efilib, and facter/ohai at source level. Each is recorded in the relevant stream's GAPS section and in `PROVENANCE.md`.
