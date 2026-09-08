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
