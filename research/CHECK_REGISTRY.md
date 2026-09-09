# CHECK_REGISTRY — the concrete list of checks the sensor implements

**Status: DECISION-READY DRAFT for the lead.** Written by `check-registry-drafter` (claude-opus-5,
2026-09-09) from the binding LEAD DECISIONS table (`research/DECISIONS.md` LD-1…LD-9),
`research/DESIGN_LAWS.md` (L01–L52), `research/FACTS.jsonl` (F1–F104),
`research/R4/{HOST_SPECIFIC_PLAN,GENERIC_FALLBACK_PLAN,STORAGE_ASSESSMENT}.md`,
`research/R3/{EVIDENCE_MODEL,FIXTURE_MATRIX}.md`, `research/OBSERVATION_ANSWERS.md`,
`state/HOST_SUMMARY.md` + `state/HOST_SNAPSHOT.evidence.json` (probe ids cited verbatim),
`task/derived/TASK_CONTRACT.md` §§C–D and `task/derived/finding.schema.json`.

Where a per-track report disagreed with FACTS/DESIGN_LAWS, the KB won (noted inline).
Every host claim rests on **n=1 host, one recon window, 187 executed probes** — the "expected on the
Lava host" lines are *predictions to be confirmed by the first real run*, not established output.

**Counts: 25 checks — REMOTE_ACCESS 6, SECRETS_ON_DISK 4, BMC_INBAND_ACCESS 5, STORAGE_POSTURE 4,
BOOT_CHAIN 6.** (C1: every category ≥ 2 checks; C9: depth over volume.)

---

## 0. How to read this document

**Observation typing** (short names used in the check blocks; mapping to the closed `reason`
vocabulary of `R3/EVIDENCE_MODEL.md` §7, which stays authoritative for the code):

| Short name here | `reason` emitted | Meaning |
|---|---|---|
| OK | — | observation succeeded |
| EACCES | `EACCES` | object exists, this uid may not read it (mode/ACL) |
| EPERM | `EPERM` | capability gate, not file mode (`dmesg` under `dmesg_restrict=1`, F8) |
| ENOENT | `ENOENT` | proven absent **by a successful listing/stat of the parent** (F10) |
| TIMEOUT | `TIMEOUT` | budget expired; never `fail`, never "unsupported" (L10) |
| UTILITY_MISSING | `UTILITY_MISSING` | helper binary absent — **never** "capability absent" (L39) |
| UNSUPPORTED | `EINVAL`/`ENODEV`/`EOPNOTSUPP` | attribute exists, operation not supported here |
| EXEC_ERROR | `EXECUTION_ERROR` | the tool ran and failed for its own reasons (non-zero exit + stderr) |
| PARSE_ERROR | `PARSE_ERROR` | output obtained, shape unexpected (tool drift) — never `fail` |
| BUDGET | `BUDGET_EXHAUSTED` | walk/scan cap hit before completion — never "nothing found" |
| CONTRADICTION | `CONTESTED` | two probes disagree; **both** recorded, no first-observation-wins |

**Evidence blocks** use the `observation_type` shapes of `R3/EVIDENCE_MODEL.md`
(`file_read`, `file_metadata`, `dir_walk`, `command_exec`, `config_resolution`, `device_probe`)
plus the universal fields (`check_id`, `status`, `reason`, `observed_at`, `duration_ms`,
`observation_type`, `detail`). Each check block lists only the *check-specific* fields on top of the
universal + type fields. Evidence records the **observation, not the conclusion** (D2).

**Caps and budgets** referenced below — constants, defined once in the code (LD-7):
`READ_CAP_SMALL` 64 KiB (config/proc), `READ_CAP_TINY` 4 KiB (one sysfs attribute),
`HEADER_SNIFF` 64 B (secret classification only, discarded immediately — L23),
`EXEC_TIMEOUT` 3 s default (`sshd -G`: 5 s), `EXEC_OUT_CAP` 256 KiB stdout / 8 KiB stderr,
`WALK_ENTRIES` 200 000, `WALK_DEPTH` 12, `WALK_TIME` 8 s,
`BMC_OOB_DEADLINE` 400 ms per attribute (host healthy path 1–2 ms, `bmc.bmc_read_timing`;
worst case 5 s × retries, F44 — hence L40), `SCAN_DEADLINE` 60 s default.

**Profiles used in the coverage matrix (§5):**
- **A — host-shaped**: bare-metal x86 UEFI Linux with DMI, BMC, NVMe, systemd, OpenSSH (the Lava host).
- **B — generic minimal**: VM or lean Debian/Alpine — no DMI serials or no DMI at all, no BMC,
  no efivars, possibly no systemd, possibly Dropbear or no sshd.
- **C — restricted**: container / hardened host — `/sys/firmware` absent, securityfs unmounted,
  `hidepid`, EACCES-heavy; execution context annotated on every host-scoped finding (L45).

---

## 1. Part one — machine description spec

Global rules: unknown strings are the literal `unknown`; unknown integers are `0` **and** an entry in
the machine-level `unknowns` object `{field: {reason, sources_tried[]}}` (AM-5, B6; legal because
`additionalProperties` is open everywhere — AM-7, F70). Every field carries a sibling `*_source`
provenance string naming the exact path or command. No field is ever `""` or a guess (B6).
Execution context is established **before** hardware inventory and annotates every `/sys`-derived
field (L45; F85: a container sees the *host's* `/sys/block` and DMI).

### 1.0 Execution context (extra field `machine.execution_context`, computed first)
- **Primary**: `/run/systemd/system` existence (the documented `sd_booted(3)` test, F53) +
  `/proc/1/cgroup` + `/.dockerenv` + `/proc/1/comm`; `systemd-detect-virt` only as a bounded exec
  cross-check, with its **inverted polarity** honoured (exit 0 = virtualisation *detected*, F53).
- **Value**: `bare-metal | vm:<id> | container:<runtime> | unknown`, plus `execution_context_source`.
- **Host**: `bare-metal` (`identity.virt` → `none`, rc = 1; DMI + BMC + TPM present).
- **Generic**: container ⇒ every `/sys`-derived field gains `describes_host_kernel: true`;
  `systemd-detect-virt` absent ⇒ UNKNOWN/UTILITY_MISSING, **never** "bare metal"
  (fixtures `detect-virt-polarity`, `detect-virt-missing`).

### 1.1 `host_id` (string, required)
- **Primary**: `HMAC-SHA256(key = ASCII "lava-sensor-host-id", msg = /etc/machine-id)` → lowercase hex
  (LD-4, L32). The raw machine-id is **never** emitted (F6: `machine-id(5)` declares it confidential);
  the build gate `machine-id-not-emitted-raw` greps the artifact for it.
- **Fallback chain** (first that yields bytes): `/sys/class/dmi/id/product_uuid` (EACCES here — record
  *denied*, not absent — L33) → `/etc/machine-id` → keyed hash of stable hardware ids
  (`/sys/block/<d>/wwid` or a permanent NIC MAC gated on `addr_assign_type == 0`) → `unknown`.
  Never random, never time-derived (B1a).
- **Provenance**: `host_id_source` (e.g. `machine-id (keyed hash)`) + `host_id_caveat`
  (`stable across reboots; regenerated on re-image; clone-vulnerable`).
- **Unknown**: string `unknown` + `unknowns.host_id.{reason, sources_tried}`.
- **Host expected**: 64-hex digest, source `machine-id (keyed hash)`; `/etc/machine-id` 0444, 32 hex
  (`identity.machine_id_files`); `product_uuid` 0400 ⇒ EACCES (`identity.dmi_ls`).
  `/var/lib/dbus/machine-id` is a symlink to it and is **not** an independent second source.
  Acceptance B1: two consecutive runs must produce byte-identical `host_id`.
- **Generic**: Alpine/OpenRC may lack `/etc/machine-id` ⇒ hardware-id fallback; on many VMs
  `product_uuid` is world-readable and wins; container ⇒ the container's machine-id, said so in the caveat.

### 1.2 `hostname` (string, required)
- **Primary**: `/proc/sys/kernel/hostname` (one bounded read, no exec).
  **Fallback**: `/etc/hostname` → `os.Hostname()`. Never `hostnamectl` (systemd-only, exec).
- **Provenance**: `hostname_source`. **Unknown**: literal `unknown` (an empty file is unknown, not `""`).
- **Host**: `f4-metal-small-chi-1` (`identity.hostname`, `identity.hostname_files`) — a provider naming
  pattern, recorded as an `owner_candidate`, never as the owner.
- **Generic**: identical on every target; a container's hostname is the container's (annotated).

### 1.3 `owner` (string, required — explicit unknown is a first-class answer; B2, LD-4)
- **Primary**: no authoritative source exists. Evidence classes in precedence order, each subjected to
  a placeholder-class test *before* acceptance: `/etc/machine-info` (`DEPLOYMENT`, `LOCATION`) →
  DMI `chassis_asset_tag`, `board_asset_tag`, `product_sku`, `product_family` → world-readable
  cloud-init `instance-data.json` tenant/org fields → `/etc/issue`, `/etc/motd`.
- **Placeholder detection** by *pattern class*, never literal match (L01, F5): empty, `Not Specified`,
  `Default string`, `To be filled by O.E.M.`, `Chassis Asset Tag`, `System Asset Tag`, `Family`,
  all-zeros, the `0123456789` decade string, `unknown`, `none`.
- **Fallback**: `owner = "unknown"` **plus** the extra `owner_candidates[] = {value, source, confidence}`
  — provider from the cloud-init datasource class (`/run/cloud-init/cloud-id`) and the sshd drop-in
  filename; facility from metadata; the SSH host-key comment as image provenance.
- **Provenance**: `owner_source` (= `none (all sources placeholder or denied)` on this host).
- **Host expected**: `unknown`, candidates `Latitude.sh` (datasource class + drop-in
  `00-latitude-instant-deploy.conf`), facility `CHI`, host-key comment `root@259S052315`
  (`identity.dmi`, `identity.cloud_init_instance_data`, `network.host_key_fingerprints`,
  `network.sshd_config_d`). Unknown **by construction** here: every owner-bearing source is either
  root-only or a vendor placeholder (F5, D-08) — state it, do not apologise.
- **Generic**: a readable `/etc/machine-info` `DEPLOYMENT` or a cloud tenant tag becomes the real
  `owner` with its source (the reversal condition named in LD-4); a container inherits nothing useful.
- **Trap**: inferring a customer from a hostname pattern or a drop-in filename is a guess —
  candidate only (fixture `placeholder-asset-tag`).

### 1.4 `vendor`, `model` (strings, required)
- **Primary**: `/sys/class/dmi/id/sys_vendor` and `product_name` (0444 on kernel ≥ 6.8, F3).
- **Fallback**: `board_vendor`/`board_name` → `/proc/device-tree/model` (devicetree/aarch64) →
  `unknown`. `dmidecode` is **not** a fallback: root-only *and* absent here (L01, L02).
- **Extras**: `board_name`, `board_version`, `bios_vendor`, `bios_version`, `bios_date`,
  `chassis_type`, `product_sku`, `product_family` — each placeholder-tested.
- **Unknown**: literal `unknown` + `unknowns.vendor.reason`, distinguishing `ENOENT` (no DMI platform —
  aarch64, WSL, most containers; F7) from `EACCES` (restricted attribute). These are different
  findings (L33) and the wording must differ.
- **Host**: vendor `Supermicro`; model `AS -3015MR-H10TNR` **verbatim, including the vendor's stray
  space**; board `H13SRE-F` v1.01; BIOS AMI `2.4a` `08/29/2025` (`identity.dmi`, `identity.dmi_ls`).
- **Generic**: VM ⇒ `QEMU` / `VMware, Inc.` / `Microsoft Corporation` with placeholder product names;
  no-DMI ⇒ `unknown` with `ENOENT` on the *directory* (capability class absent, not a denial);
  container ⇒ the **host's** DMI (F85) — annotate, never silently attribute to the container.
- **Trap**: DMI values are firmware-settable ⇒ identification, not attestation (R4-F39).

### 1.5 `os.name`, `os.version`, `os.kernel` (required)
- **Primary**: `/etc/os-release` → `NAME`, `VERSION_ID`; `/proc/sys/kernel/osrelease` → `kernel`.
- **Fallback**: `/usr/lib/os-release` (`/etc` takes precedence, no merging — F54) →
  `/etc/redhat-release` / `/etc/debian_version` **as corroboration only** (prose, not `key=value`) →
  `uname -r` through the bounded runner.
- **Extras**: `os.version_pretty` (`PRETTY_NAME`), `os.id`, `os.id_like`, `os.uname_full`,
  `os.kernel_boot_default` (the `/boot/vmlinuz` symlink target — feeds `BOOT_KERNEL_DRIFT` evidence).
- **Unknown**: `VERSION_ID` may legitimately be absent from a well-formed file (F54) ⇒ `unknown`,
  reason `ENOENT`; never inferred from `ID`.
- **Host**: `Ubuntu` / `24.04` / `6.8.0-139-generic`; pretty `Ubuntu 24.04.4 LTS`; boot default
  `7.0.0-31-generic` (`identity.os_release`, `identity.uname`, `kernel.boot_ls`).
  Note `/etc/os-release` here is a **symlink** to `/usr/lib/os-release`, and `stat` without `-L`
  reports the link length 21 — never size a read from `st_size` (L05, `kernel.stat_sizes`).
- **Generic**: Alpine ⇒ `ID=alpine`, no `/etc/debian_version`; container ⇒ the *image's* userland with
  the *host's* kernel — the two must not be presented as one coherent system (L45).

### 1.6 `cpu.model`, `cpu.cores` (+ B3b extras)
- **Primary**: `cpu.model` = first `model name` in `/proc/cpuinfo` (arm: `Model name` /
  `CPU implementer`+`CPU part`). `cpu.cores` = **physical cores** = count of distinct
  `(physical_package_id, core_id)` pairs from `/sys/devices/system/cpu/cpu*/topology/`, or from
  `/proc/cpuinfo` `physical id`/`core id` when topology is unavailable.
- **Fallback**: online logical CPUs from `/sys/devices/system/cpu/online`, with
  `cores_basis: "logical (topology unavailable)"`. `lscpu` is a last-resort exec, never primary (L39).
- **Extras (B3b)**: `logical_cpus`, `sockets`, `threads_per_core`, `cores_basis`
  (`sysfs-topology` | `cpuinfo-topology` | `logical-fallback`), `cpu_vendor`.
- **Unknown**: `cores: 0` + `unknowns.cpu.cores`; model `unknown`.
- **Host**: `AMD EPYC 4484PX 12-Core Processor`; cores **12**, logical 24, sockets 1,
  threads_per_core 2, basis `sysfs-topology` (`cpu.cpuinfo_summary`, `cpu.nproc_smt`, `cpu.lscpu`).
- **Generic**: VMs often expose a flat topology (`core id` all 0) ⇒ physical == logical and the basis
  must say so; container ⇒ `/proc/cpuinfo` shows all host CPUs regardless of cgroup quota — report
  `cpu_quota_hint` from `/sys/fs/cgroup/cpu.max` as an extra, never as `cores`.

### 1.7 `memory_bytes` (integer, required)
- **Primary**: `/proc/meminfo` `MemTotal` (kB) × 1024, `memory_source: "/proc/meminfo:MemTotal"` (B3c).
- **Fallback**: none that is both unprivileged and honest. DMI installed capacity needs root;
  memory-block arithmetic (`/sys/devices/system/memory/*`) differs materially from MemTotal (F62) and
  is emitted only as the extra `memory_installed_bytes_hint` with its own source — **never**
  substituted (F63 is the named anti-pattern: `ghw` silently substitutes usable RAM).
- **Extras**: `swap_total_bytes`, `memory_installed_bytes_hint`.
- **Unknown**: `0` + `unknowns.memory_bytes`.
- **Host**: MemTotal 97 938 032 kB ⇒ **100 288 544 768** bytes; swap 0 (`cpu.meminfo`, `storage.swap`).
- **Generic**: container ⇒ MemTotal is the host's; add `memory_limit_bytes` from
  `/sys/fs/cgroup/memory.max` as an extra and annotate.

### 1.8 `storage[]` (array; required per item: `device`, `model`, `size_bytes`)
- **Enumeration**: readdir `/sys/block/` **through `os.Root("/sys")`** — every entry is a symlink
  (F18, `storage.sysblock_ls_la`), so `WalkDir` / blanket `O_NOFOLLOW` would enumerate nothing
  (L13, L15). Exclude `loop*`, `ram*`, `zram*`; exclude `dm-*`/`md*` aggregates **only when at least
  one physical disk exists** (T-S5) — when they are all there is, list them.
- **`device`**: kernel name (`nvme0n1`) + extra `device_path` (`/dev/nvme0n1`). The node is **never
  opened** (L13) — the whole storage category depends on this.
- **`model`**: `/sys/block/<d>/device/model` → NVMe `/sys/class/nvme/<c>/model` → udev DB
  `/run/udev/data/b<maj>:<min>` `E:ID_MODEL` (0755, readable — R4-OR8) → `unknown` for *that device*.
  The device is still listed; dropping it would be a silent omission (D3).
- **`size_bytes`**: `/sys/block/<d>/size` × **512** — fixed 512-byte sectors regardless of
  `logical_block_size` (L28, F55; using `logical_block_size` over-reports 8× on a 4Kn drive).
- **Extras per device**: `transport` (`nvme|sata|virtio|usb`, from the parent subsystem — never from
  the name), `rotational`, `logical_block_size`, `physical_block_size`, `wwid`/`eui`
  (**flat** under `/sys/block/nvmeXnY/wwid`, not under a `nvme/` subdir — T-S13),
  `partitions[] {name, size_bytes, fstype_udev, mountpoint}`, `holders[]`, `slaves[]`,
  `filesystem` (udev DB `E:ID_FS_TYPE`, labelled `source: udev-db-at-last-uevent`), `state`,
  `firmware_rev`, `scheduler`, `write_cache` (block-layer flush behaviour only — **never** a
  durability or power-loss-protection claim, F61). `serial` is identity-sensitive and is not emitted
  by default.
- **Unknown**: `size_bytes: 0` + `unknowns.storage["<dev>"].size_bytes`; model `unknown`.
  `/sys/block` unreadable ⇒ `storage: []` **plus** `unknowns.storage` — never a bare empty array.
- **Host**: two entries — `nvme0n1`, `nvme1n1`; model `Micron_7450_MTFDKCC960TFR`;
  1 875 385 008 × 512 = **960 197 124 096** B each; transport `nvme`, rotational 0, logical 512 /
  physical 4096, fw `E2MU200`; `nvme0n1` = p1 vfat (`/boot/efi`) + p2 ext4 (`/`); `nvme1n1` = no
  partitions, no udev fs signature, no holders; eight `loop*` at size 0 excluded
  (`storage.sysblock_loop`, `storage.nvme_class`, `storage.lsblk_json`, `storage.partitions`,
  `storage.blk_queue_detail`).
- **Generic**: VM ⇒ `vda`/`sda`, `model` frequently absent on virtio (`unknown`/ENOENT, not a failure);
  no-NVMe ⇒ the NVMe branch never fires (capability gate, L37/L38); container ⇒ the **host's** block
  devices are visible (F85) and every row is annotated; Alpine ⇒ identical, because the path is pure
  sysfs — "storage unknown because `lsblk` is missing" is an under-claim bug (L39).

---

## 2. The check table

Format per check: `check_id` · title · impact · question · PASS/FAIL/UNKNOWN with the exact
observation and its typing · primary evidence (paths, bounded commands, caps, timeouts) · fallback
chain · evidence fields · expected on the Lava host (probe id) · generic behaviour · traps (law ids) ·
fixtures. Fixture names without "(new)" already exist in `R3/FIXTURE_MATRIX.md`.

---

### 2.1 `REMOTE_ACCESS` — 6 checks

Category question (C4): how can this machine be logged into from elsewhere, what does that permit,
who may connect, by what authentication, as whom — **as actually in force**, not as any single
config file says.

---

#### `SSH_ROOT_LOGIN_POLICY`
- **Title**: Root login over SSH is not permitted by the running sshd policy
- **Impact**: high
- **Question**: Can a remote party authenticate directly as `root` over SSH on the policy the running
  daemon actually loaded?
- **PASS when** the effective `permitrootlogin` is `no` (OK from `sshd -G`, or OK from the
  Include-aware walker when `-G` is unavailable).
- **FAIL when** effective `permitrootlogin` is `yes` (OK), or is `prohibit-password` /
  `without-password` / `forced-commands-only` **and** root key material is demonstrably present
  (`/root/.ssh/authorized_keys` readable and non-empty, OK). `sshd -G` prints
  `without-password` for `prohibit-password` — normalise both spellings (L18).
- **UNKNOWN when**: `sshd -G` fails *and* the config chain is unreadable (EACCES) or `sshd` is absent
  (UTILITY_MISSING) with no readable config; the directive is absent and the distro/version default
  cannot be cited (L19 — `unknown distro ⇒ UNKNOWN`, never an assumed default); the exec times out
  (TIMEOUT); oracle and walker disagree (CONTRADICTION); **or** the value is
  `prohibit-password`/`forced-commands-only` and `/root/.ssh` is EACCES — root key login is then
  *unknown*, not disabled (R4 B2 trap (d)). On this host that last branch is the live one.
- **Primary evidence**: bounded exec `["/usr/sbin/sshd","-G"]`, no shell, `EXEC_TIMEOUT` 5 s,
  Setpgid + group-kill + WaitDelay, stdout capped at `EXEC_OUT_CAP`, real child exit code captured
  (never through a pipeline — L41, F1). Parse lowercase `keyword value` lines.
- **Fallback chain**: (1) own Include-aware walker over the daemon's config path (from the systemd
  unit `ExecStart`/`-f` argument, else `/etc/ssh/sshd_config`), expanding `Include` **at its
  position**, glob-sorted, first-obtained-value-wins (F27, L16), emitting shadowed occurrences;
  (2) cited, version- and distro-scoped compiled-in default (L19, F28 CONTESTED ⇒ every defaulted row
  carries `default_source`); (3) UNKNOWN. Runs **always** (not only on `-G` failure) because it is
  also the provenance source and the cross-check (LD-5).
- **Evidence fields**: `command_exec{command, binary_resolved_path, exit_code, signal, timed_out,
  stdout_bytes, stderr_excerpt, wait_delay_expired}` + `config_resolution{directive:"permitrootlogin",
  effective_value, winning_source{path,line}, shadowed_occurrences[], resolution_rule:
  "first-obtained-value-wins", defaulted, default_source, conditional_blocks}` +
  `file_metadata` for `/root/.ssh/authorized_keys` (`exists`, `errno`, `mode`, `uid`, `gid`, `size`).
- **Expected on the Lava host**: **unknown**, reason `EACCES` — effective value
  `permitrootlogin without-password` (`network.sshd_g_effective`) while `/root/.ssh` is EACCES
  (`users.root_home_ls`), so root *key* login cannot be excluded. Severity `high` (LD-2).
  This is the honest answer and is worth more than a comfortable `pass`.
- **Generic**: RHEL 9 ⇒ same mechanism, different default and an Include that is **not guaranteed** on
  in-place upgrades (R4-F41); Debian ⇒ identical; Alpine/Dropbear ⇒ no config file at all, policy from
  argv where readable, else UNKNOWN (a "no config ⇒ defaults" parser is wrong twice); VM ⇒ unchanged;
  container ⇒ usually no sshd ⇒ UNKNOWN/UTILITY_MISSING with the note that "no SSH listener in a
  container" is not "no remote access to the machine".
- **Traps**: reporting the **last** occurrence of a keyword (OpenSSH takes the first — L16/F27);
  treating `sshd -T` failure as a config error (`-T` loads host keys first and exits 1 unprivileged —
  F26, never used, L18); a `Match` block makes any global verdict evidence-only (L17, F29);
  claiming a default without `default_source` (L19); a blanket UNKNOWN when `-G` fails although the
  walker resolved the chain (under-claim, L36).
- **Fixtures**: `sshd-G-oracle-primary`, `sshd-G-absent-walker-fallback`, `sshd-G-disagrees-with-walker`,
  `sshd-dropin-shadows-main`, `sshd-include-at-bottom`, `sshd-match-user-root`, `sshd-T-no-hostkeys`,
  `sshd-T-failure-not-blanket-unknown` (under-claim), `usepam-absent-unknown-distro`,
  `root-authkeys-eacces-not-disabled` (new), `sshd-G-timeout-group-killed` (new),
  `sshd-G-malformed-output-parse-error` (new).

---

#### `SSH_AUTH_METHODS_POLICY`
- **Title**: SSH accepts only key-based authentication; password and empty-password logins are refused
- **Impact**: high
- **Question**: Which authentication methods can a remote party actually use, and how many attempts
  and how long do they get?
- **PASS when** effective `passwordauthentication no` **and** `kbdinteractiveauthentication no`
  **and** `permitemptypasswords no` **and** `pubkeyauthentication yes` (all OK from the same oracle
  run). `usepam yes` with `kbdinteractive no` is the Ubuntu-correct passing shape.
- **FAIL when** any of: `passwordauthentication yes`, `kbdinteractiveauthentication yes` (PAM can
  serve passwords through it even with `passwordauthentication no` — the classic false PASS),
  `permitemptypasswords yes`, `pubkeyauthentication no` with a password method enabled.
- **UNKNOWN when**: as `SSH_ROOT_LOGIN_POLICY` (EACCES / UTILITY_MISSING / TIMEOUT / EXEC_ERROR /
  PARSE_ERROR / CONTRADICTION / uncitable default), or when a `Match` block scopes any of these
  keywords (then the global verdict is evidence-only and the check reports `unknown` naming the block).
- **Primary evidence**: the same single `sshd -G` run (one exec for the whole SSH family — L41: one
  observation per fact, but not one process per directive), plus `/etc/pam.d/sshd` read
  (`READ_CAP_SMALL`) to record whether PAM is in the path.
- **Fallback chain**: Include-aware walker → cited version/distro default → UNKNOWN.
- **Evidence fields**: `config_resolution` per directive (4 rows), each with `winning_source`,
  `shadowed_occurrences`, `defaulted`, `default_source`; `observed_directives` extra carrying
  `maxauthtries`, `logingracetime`, `maxstartups`, `x11forwarding`, `allowtcpforwarding`,
  `allowagentforwarding`, `gatewayports`, `permittunnel`, `authorizedkeysfile`,
  `authorizedkeyscommand`, `trustedusercakeys`, `banner` — reported because an operator should see
  them, explicitly marked `verdict_contributing: false`. (See §6 OPEN-1: the lead may prefer these as
  a separate `info` check.)
- **Expected on the Lava host**: **pass**, severity `info`. `passwordauthentication no`,
  `kbdinteractiveauthentication no`, `permitemptypasswords no`, `pubkeyauthentication yes`,
  `maxauthtries 6`, `logingracetime 120`, `x11forwarding yes`, `allowtcpforwarding yes`
  (`network.sshd_g_effective`); the drop-in repeats the two `no` values (`network.sshd_config_d`).
- **Generic**: RHEL/Debian identical; Alpine/Dropbear ⇒ UNKNOWN with the "no config file exists"
  reason; VM unchanged; container ⇒ usually UNKNOWN/UTILITY_MISSING.
- **Traps**: passing on `passwordauthentication no` alone while `kbdinteractiveauthentication yes`
  leaves PAM password auth reachable (false PASS); assuming the OpenSSH upstream default when the
  distro patches it (F28 CONTESTED ⇒ default rows need a citation *and* a distro scope, L19);
  `authorizedkeysfile` pointing outside the home directory changes who can add keys (record it).
- **Fixtures**: `kbdinteractive-yes-password-reachable` (new), `usepam-absent-ubuntu`,
  `usepam-absent-unknown-distro`, `pubkey-disabled-password-enabled` (new),
  `permitemptypasswords-yes` (new), `sshd-match-user-root`, `sshd-G-oracle-primary`.

---

#### `SSH_POLICY_IN_FORCE`
- **Title**: The SSH configuration on disk is the configuration the running daemon loaded
- **Impact**: medium
- **Question**: Is the policy we just reported actually the one in force, or has the config changed
  since the daemon started / does the listener contradict the config?
- **PASS when** all of: the newest mtime across the config chain (`sshd_config`, every included
  drop-in, referenced key files) is **older than or equal to** the SSH service's
  `ActiveEnterTimestamp` (OK); the `sshd -G` oracle and the walker agree on every directive the
  walker resolved (OK); the effective listeners match the effective `listenaddress`/`port` **or** the
  divergence is explained by a socket unit whose `ListenStream` we read (OK).
- **FAIL when** a config file in the chain is newer than the service start (OK observation, adverse
  result): the running daemon is enforcing something other than what is on disk.
- **UNKNOWN when**: the service start time is unavailable (no systemd ⇒ UNSUPPORTED; `systemctl show`
  EXEC_ERROR/TIMEOUT); a `Match` block exists so no global statement is valid (L17);
  oracle and walker disagree (CONTRADICTION — both values recorded, contested reported);
  an `Include` glob is unreadable (EACCES).
- **Primary evidence**: `lstat` on every file in the resolved Include chain; bounded exec
  `["systemctl","show","ssh.service","-p","ActiveEnterTimestamp","-p","ActiveState","-p","FragmentPath"]`
  and the same for `ssh.socket` (`-p ListenStream -p ActiveState`), `EXEC_TIMEOUT` 3 s;
  `/proc/net/tcp` + `/proc/net/tcp6` for the actual listeners.
- **Fallback chain**: no systemd ⇒ `/proc/<pid>/stat` field 22 (starttime) of the sshd pid resolved
  from `/proc/net/tcp` inode ownership **where readable** → boot time from `/proc/stat btime` as a
  lower bound → UNKNOWN/UNSUPPORTED. Never guess.
- **Evidence fields**: `file_metadata[]` (path, mtime, mode, uid, gid) for the chain;
  `command_exec` for each `systemctl show`; `config_resolution.conditional_blocks`;
  extras `service_active_enter`, `newest_config_mtime`, `delta_seconds`,
  `oracle_walker_disagreements[]`.
- **Expected on the Lava host**: **pass**, severity `info`. The drop-in mtime
  `2026-09-08 17:37:29.29Z` equals `ssh.service` ActiveEnterTimestamp `17:37:29Z` (~22 h after boot):
  provisioning rewrote the config after boot **and** restarted sshd, so the file is in force
  (`network.sshd_dropin_mtime_vs_boot`, `network.sshd_service_status`, R4-OR9).
  Sub-note in evidence: `ssh.socket` is active with `ListenStream 0.0.0.0:22` and `[::]:22`
  (`network.ssh_socket_cat`) — socket activation, so the config never decides the listener (F30/L20).
- **Generic**: no systemd (Alpine/OpenRC, container) ⇒ UNKNOWN/UNSUPPORTED with the reason
  "systemd not booted" and never a FAIL (fixture `no-systemd`); Debian pre-22.10 ⇒ classic
  `sshd.service`, no socket unit — read the unit, do not assume either shape.
- **Traps**: an equal timestamp is a PASS, not a FAIL (the restart *is* the propagation);
  `sshd_config` mtime older than boot while a drop-in is newer — compare the **whole chain**, not one
  file; a socket-activated daemon is a listener with no running daemon and vice versa (L20);
  `systemctl` present ≠ systemd booted (F53).
- **Fixtures**: `socket-activated-port-mismatch`, `config-newer-than-service-start` (new),
  `config-equal-to-service-start-passes` (new), `no-systemd`, `sshd-G-disagrees-with-walker`,
  `include-glob-unreadable` (new).

---

#### `REMOTE_LISTENING_SURFACE`
- **Title**: Only expected remote-access services are listening on non-loopback addresses
- **Impact**: medium
- **Question**: What can be reached over the network on this machine, and which unit owns it?
- **PASS when** the socket tables were read completely (OK) and every non-loopback listener maps to
  an allow-listed *class* of remote access resolved from evidence — currently: SSH on the port the
  effective sshd policy/socket unit declares. (Allow-list is by **class and evidence**, never by port
  number literal or hostname — L37.)
- **FAIL when** a non-loopback listener exists whose class is a known remote-access path other than
  the SSH one (telnet, VNC/RFB, RDP, X11, Docker/containerd API, Kubernetes API/kubelet, unauthenticated
  Redis/etcd/Elasticsearch, a second sshd, WireGuard/OpenVPN/tailscale endpoints) — classification
  from the owning unit and the port's registered class, both recorded.
- **UNKNOWN when**: `/proc/net/tcp{,6}`/`udp{,6}` are unreadable (EACCES, hardened/containerised) and
  `ss`/`netstat` are absent (UTILITY_MISSING); or the tables were read but **no** listener could be
  attributed to a unit and at least one is unrecognised (owner UNKNOWN/EACCES — never blank, L20).
  Note: partial attribution is not a blanket unknown — attributed rows keep their verdict.
- **Primary evidence**: direct read of `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`,
  `/proc/net/udp6` (`READ_CAP_SMALL`, `st_size` ignored — L05), decoding hex local address/port,
  state `0A` (LISTEN) for TCP, uid and inode columns. Ownership: match inode → `/proc/<pid>/fd` only
  where readable; then `systemctl show '*.socket' -p ListenStream` for socket-activated units.
- **Fallback chain**: `ss -tulnH` (bounded exec, 3 s) → `netstat -tulnp` → UNKNOWN. `ss` is a
  *cross-check*, never the primary: unprivileged `ss` degrades by **silent omission** — exit 0, header
  present, Process column blank for other users' sockets (F31) — so a parser that trusts it reports
  "no owner" as fact.
- **Evidence fields**: `file_read` per `/proc/net/*` (path, bytes_read); `listeners[] = {proto,
  local_addr, port, scope: loopback|link|global, uid, inode, owner_unit|null, owner_reason}`;
  `attribution_gaps[]`; `command_exec` for each fallback; the extra
  `blind_spots: ["outbound reverse tunnels create no listener (F32)"]` — L21 makes this mandatory.
- **Expected on the Lava host**: **pass**, severity `info`. TCP 22 on `0.0.0.0` and `[::]` (two
  distinct listeners, because `ssh.socket` sets `BindIPv6Only=ipv6-only` — not one dual-stack socket),
  systemd-resolved on `127.0.0.53:53` and `127.0.0.54:53` loopback-only
  (`network.ss_listen`, `network.ssh_socket_cat`). Owner of :22 is UNKNOWN/EACCES because
  `/proc/<pid>/fd` of uid 0 is unreadable — recorded as an attribution gap, not as a failure.
- **Generic**: container ⇒ `/proc/net` may be masked (UNKNOWN) and the answer is about the container,
  not the machine; VM ⇒ unchanged; Alpine ⇒ BusyBox `netstat` has different columns, so the
  `/proc/net` path (which is identical everywhere) carries the check.
- **Traps**: attributing a listener to a service without evidence (L20); an installed-but-inactive
  daemon is not a listener, a socket-activated one is (F30); treating a filtered port as absent — the
  ruleset is a *different* check; treating loopback-only as exposure; and the standing blind spot:
  reverse tunnels (Cloudflare Tunnel, ngrok, frp) are outbound-only and structurally invisible here
  (F32, L21) — the finding must say so or it is invalid.
- **Fixtures**: `listener-owner-unknown`, `socket-activated-port-mismatch`,
  `outbound-tunnel-no-listener`, `procnet-unreadable-ss-missing` (new),
  `ss-silent-omission-not-no-owner` (new), `ipv6-only-two-listeners` (new).

---

#### `LOGIN_AND_ESCALATION_SURFACE`
- **Title**: Who can log in to this machine, by what means, and who can escalate
- **Impact**: medium
- **Question**: Which local accounts can obtain an interactive session, how are they authenticated,
  and which of them have a path to root?
- **PASS when** the account inventory completed (OK) and: every account with a login shell either has
  a locked/no password *for the accounts we may legitimately determine* or is key-only; the set of
  members of privileged groups (`sudo`, `wheel`, `adm`, `disk`, `docker`, `lxd`, `systemd-journal`)
  is enumerated (OK) and contains no unexpected *class* of principal (e.g. no member of `docker`/`lxd`,
  which are root-equivalent); and no privileged group has a member that is not also an
  administratively-shelled account.
- **FAIL when** a member of a root-equivalent group (`docker`, `lxd`, `disk`, `kmem`) exists that is
  not a system account (OK observation, adverse); or an account with a login shell is proven to have
  an empty password field in a **readable** `/etc/shadow` (OK — vanishingly rare, but a real FAIL);
  or `nsswitch.conf` names a directory backend we cannot query **and** a privileged group is
  non-empty (that is a FAIL of the *enumeration completeness* claim? — **no**: see UNKNOWN).
- **UNKNOWN when**: `/etc/shadow` is unreadable (EACCES — the normal case: the password state of
  other accounts is unknown and must never be reported as "no password set", L22);
  `/etc/sudoers` / `/etc/sudoers.d` are unreadable (EACCES) so the *policy* behind group membership is
  unknown; another user's home or `/root/.ssh` is unreadable (EACCES) so their key material is
  unknown; `nsswitch.conf` names a non-`files` backend (LDAP/SSSD) we cannot query (UNSUPPORTED).
  On such a host the check reports `unknown` **with the fully enumerated group membership in
  evidence** — the enumerable part is never discarded.
- **Primary evidence**: reads of `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, `/etc/login.defs`
  (`READ_CAP_SMALL`); `lstat` of `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d`,
  `/root/.ssh`, `/root/.ssh/authorized_keys`, each home's `.ssh/authorized_keys`;
  `file_metadata` + line **count** (never content) of our own `~/.ssh/authorized_keys`;
  bounded exec `["passwd","-S"]` **for our own account only** (`passwd -S` reports only the caller
  unprivileged — F33; generalising it to other users is a false claim).
- **Fallback chain**: `getent passwd`/`getent group` (bounded exec) only if the files are unreadable;
  the files are primary because they need no tool (L39).
- **Evidence fields**: `accounts[] = {name, uid, shell, shell_class: login|nologin|false,
  home, home_mode, authorized_keys{exists, mode, uid, gid, size, key_count|null, errno}}`;
  `privileged_groups[] = {group, gid, members[], effectively_root_only: bool}`;
  `password_state_self` (`command_exec` with exit code); `policy_boundaries[] = {path, errno}`;
  `nsswitch_backends[]`. **Never** a password hash, never a key body.
- **Expected on the Lava host**: **unknown**, reason `EACCES`, severity `medium`. Enumerable: only
  `root` and `ubuntu` have login shells (`users.login_shells`); `ubuntu` (uid 1000) is in
  `ubuntu` and `sudo`; every other privileged group (`disk`, `adm`, `systemd-journal`, `kmem`,
  `video`, `render`, `input`, `dialout`) is **empty** — a stronger statement than absence (R4-F13,
  `users.group_members`, `users.priv_groups`); our own password is locked (`passwd -S` → `L`,
  `users.passwd_status`) so our login is key-only; `~/.ssh/authorized_keys` 0600, 98 B
  (`network.authorized_keys`). Unknown: `/etc/sudoers` 0440 and `/etc/sudoers.d` 0750
  (`users.sudoers_ls`) ⇒ the sudo *policy* (incl. any NOPASSWD) is unknown; `/root/.ssh` EACCES
  (`users.root_home_ls`) ⇒ root's keys unknown; `/etc/shadow` 0640 root:shadow (`users.shadow_ls`)
  ⇒ other accounts' password state unknown. nsswitch is `files` only (`users.nsswitch`), so the
  files *are* the whole story here — that is itself evidence and is recorded.
- **Generic**: RHEL ⇒ `wheel` instead of `sudo` (gate on the *group's* root-equivalence, resolved
  from `/etc/sudoers` when readable, else from a documented well-known set with a citation);
  Alpine ⇒ BusyBox `getent` differences (files path unaffected); container ⇒ the image's accounts, not
  the machine's; LDAP/SSSD hosts ⇒ UNSUPPORTED for the completeness claim.
- **Traps**: counting `nologin`/`false` accounts as login-capable; treating an empty privileged group
  as absent — empty means group-mode files are **root-only in practice** (L43, R4-F13) and that
  helper feeds the BMC and storage device checks; generalising `passwd -S` beyond the caller (F33);
  **never run `sudo`, `su` or `doas`** even to test (E4, L22, fixture `sudo-never-invoked`);
  `~/.sudo_as_admin_successful` existing is a marker, not a policy.
- **Fixtures**: `shadow-unreadable-not-passwordless`, `sudo-never-invoked`,
  `empty-privileged-group-root-only`, `unreadable-home-not-clean`,
  `docker-group-member-is-root-equivalent` (new), `nsswitch-ldap-unsupported` (new),
  `nologin-shell-not-login-capable` (new).

---

#### `HOST_FIREWALL_STATE`
- **Title**: A host-based packet filter is enabled and its policy is verifiable
- **Impact**: medium
- **Question**: Is anything filtering inbound traffic on this host, and can we see what it does?
- **PASS when** a filtering subsystem is enabled (OK) **and** its effective ruleset or default policy
  is readable and denies by default on input (OK) — e.g. `nft list ruleset` readable, or ufw enabled
  with a readable `DEFAULT_INPUT_POLICY=DROP|REJECT`.
- **FAIL when** every candidate subsystem is provably inactive/absent (ENOENT after successful
  listings + `is-active` = `inactive` for each candidate) **and** at least one global-scope listener
  exists — i.e. the machine is unfiltered and reachable; or an enabled firewall's readable default
  input policy is `ACCEPT` with no readable rules narrowing it.
- **UNKNOWN when**: a subsystem is enabled but the ruleset is unreadable (EACCES with the exact
  stderr: `iptables -S` → `Could not fetch rule set generation id: Permission denied (you must be
  root)`; `ufw status` → `ERROR: You need to be root to run this script`); `nft` is absent
  (UTILITY_MISSING — which says **nothing** about whether nftables rules exist, because `iptables`
  here is the nf_tables variant); no init system to ask (UNSUPPORTED); exec TIMEOUT.
  **Never** report "no firewall rules" from an unreadable ruleset.
- **Primary evidence**: capability gate first (`/run/systemd/system` — F53/L38), then bounded exec
  `["systemctl","is-active","--quiet","<unit>"]` per candidate (`ufw`, `firewalld`, `nftables`,
  `iptables`, `netfilter-persistent`), 3 s each; readable config: `/etc/ufw/ufw.conf` (`ENABLED=`),
  `/etc/default/ufw` (`DEFAULT_INPUT_POLICY`), `/etc/firewalld/firewalld.conf` (`DefaultZone`),
  `/etc/nftables.conf`; `lstat` of `/etc/ufw/*.rules` to record the 0640 boundary.
- **Fallback chain**: `nft list ruleset` (bounded, 3 s) → `iptables -S` / `iptables-nft -S` →
  `/proc/net/ip_tables_names` and `/proc/net/nf_conntrack` existence as *capability* signals →
  UNKNOWN. Presence of the `nf_tables`/`ip_tables` module in `/proc/modules` is recorded as a
  capability signal only, never as "rules exist" (T-S1 reasoning).
- **Evidence fields**: `subsystems[] = {name, unit, is_active, is_active_rc, config_path,
  config_values{}, ruleset_readable, errno, stderr_excerpt}`; `command_exec` per attempt with the
  real exit code (L41 — no pipelines); `default_policy_source`.
- **Expected on the Lava host**: **unknown**, reason `EACCES`, severity `medium`.
  `systemctl is-active ufw` = `active` (`network.firewall_active`) but the rule files
  `/etc/ufw/*.rules` are 0640 root:root and `ufw status` / `iptables -S` need root
  (`network.ufw_file_modes`, `network.firewall_rules`); `nft` is absent
  (`services.utility_inventory`). `/etc/ufw/ufw.conf` and `/etc/default/ufw` are 0644 and **are**
  readable, so `ENABLED=` and the default policies go into evidence — a partial answer that must be
  reported rather than discarded (anti-under-claim, L36).
- **Generic**: RHEL ⇒ `firewalld` with a readable `firewalld.conf` default zone; Alpine ⇒ often no
  firewall service at all (that is a provable FAIL only together with a global listener);
  VM ⇒ unchanged; container ⇒ netfilter is usually the host's — annotate and downgrade to UNKNOWN.
- **Traps**: `is-active` means the unit runs, not that any rule is loaded; an active ufw with a
  default-allow policy is not protection; the observed listener set is **not** a substitute for the
  ruleset (a filtered port still appears in `ss`); `nft` missing ≠ nftables unused (L39).
- **Fixtures**: `ufw-active-rules-unreadable` (new), `nft-missing-not-no-rules` (new),
  `no-firewall-with-global-listener-fails` (new), `firewalld-default-zone-readable` (new),
  `no-systemd`, `four-failure-classes-one-check`.

---

### 2.2 `SECRETS_ON_DISK` — 4 checks

Category question (C5): what credential material is on the machine and how well is it protected.
**Metadata only, never content** (C5a, L23): path, type from name + a ≤ 64-byte header sniff that is
classified and discarded, mode, owner, group, ACL, size, mtime. Every walk carries its boundary —
`root`, `entries_scanned`, `dirs_pruned`, `unreadable_dirs`, `crossed_mounts: false`,
`budget_exhausted` — or the finding is invalid (L25). World-readable **boot** artifacts are
**not** here: they live in `BOOT_ARTIFACT_READABILITY` (§2.5), because the reasoning there is about
the boot chain's own integrity; this category cross-references that check id in its evidence so a
reader is not left to wonder (decision recorded, see §6 OPEN-2 for the reversal).

---

#### `PRIVATE_KEY_MATERIAL_EXPOSURE`
- **Title**: Private key material on disk is not readable beyond its owner
- **Impact**: high
- **Question**: Where is private key material sitting, and who can pick it up?
- **PASS when** the walk completed within budget (OK, `budget_exhausted: none`) and every discovered
  private-key-class file has mode with no group **or** other read bit (`0600`/`0400`, or `0640` with
  a group whose membership is empty — resolved by the L43 helper) and no ACL granting a non-owner
  principal read.
- **FAIL when** any private-key-class file is world-readable or group-readable by a non-empty
  non-privileged group (OK), or is owned by a different uid than the directory's expected owner while
  world-readable. `pem-key-world-readable` is the canonical case.
- **UNKNOWN when**: the walk hit `WALK_ENTRIES`/`WALK_DEPTH`/`WALK_TIME` (BUDGET — "none found" is
  then not a result, L25); a scan root is unreadable (EACCES — e.g. `/root`, another user's 0700
  home: "present, contents unknown", never "clean"); `getxattr(system.posix_acl_access)` returns
  EACCES/ENOTSUP on a hit (the *who* is then partly unknown, L52); a hit is a non-regular file
  (FIFO/device) — recorded and **not opened** (L13).
- **Primary evidence**: bounded `WalkDir` over a fixed root set — `/etc/ssh`, `/etc/ssl`, `/etc/pki`,
  `/etc/kubernetes`, `/etc/docker`, `/etc/nginx`, `/etc/apache2`, `/etc/httpd`, `/opt`, `/srv`,
  `/home/*`, `$HOME`, `/var/lib/*/.ssh` — with `xdev` keyed on `Stat_t.Dev` of the walk root (F20,
  R5-OR3: this correctly excludes `/proc`, `/sys`, `/dev`, `/run`, `/boot/efi` on the host), prune
  list (`/proc`, `/sys`, `/dev`, `/run`, `/snap`, any non-native fstype), no symlink following.
  Candidate selection by name/extension class (`id_*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`,
  `*.keytab`, `*server.key`) **then** `lstat` **then** a `HEADER_SNIFF` ≤ 64 B classification
  (RFC 7468 PEM armor; `openssh-key-v1` with `ciphername` second in the header — F37) that is
  classified into `magic_class` and immediately discarded.
- **Fallback chain**: none needed (this is `lstat`, not `open`); ACL: `syscall.Getxattr` decoded in
  pure Go (L52, F41) — `getfacl` absence must not turn the ACL question into UNKNOWN (L39).
- **Evidence fields**: `dir_walk{root, entries_scanned, dirs_pruned, unreadable_dirs, crossed_mounts,
  budget_exhausted}` per root; `file_metadata[]` per hit `{path, file_type, mode, uid, gid, size,
  mtime, magic_class, acl_present, acl_grants_nonowner, encrypted_key: bool|null}`;
  never bytes, never a hash of bytes (EVIDENCE_MODEL §8).
- **Expected on the Lava host**: **pass**, severity `info`. Within scope the bounded name-based find
  returned only `/home/ubuntu/.ssh/authorized_keys` 0600 (a public-key file), `/etc/shadow` 0640
  root:shadow (covered by `SYSTEM_SECRET_STORE_PROTECTION`) and two world-readable CA **bundles**
  (`/usr/share/gnupg/sks-keyservers.netCA.pem`, `certifi/cacert.pem`) that are public certificates,
  not private keys — the `magic_class` test is what prevents a false FAIL on those
  (`secrets.sensitive_file_find`). SSH host **private** keys are 0600 (`network.ssh_dir_ls`).
  Boundary recorded: `/root` and `/etc/ssl/private` EACCES (`users.root_home_ls`,
  `secrets.tls_private_ls`).
- **Generic**: RHEL ⇒ `/etc/pki/tls/private`, `/etc/pki/entitlement` (a Debian-shaped root list
  under-reports on RHEL — the root set is a union, gated on directory existence);
  Alpine ⇒ smaller surface, and **never** shell out to GNU `find` (BusyBox lacks predicates) — walk
  in-process; container ⇒ add `/run/secrets` and tmpfs secret mounts from `/proc/self/mountinfo`, and
  say the scope is the container, not the machine.
- **Traps**: a `.pem` that is a certificate is not a private key (classify, do not name-match);
  `find / -xdev … 2>/dev/null` silently skips other filesystems and every unreadable directory
  (T-U2, F10) so "none found" is only valid *inside the printed scope*; a 0644 file in a 0700
  directory is not reachable by others — report both and say which one gates;
  emitting even 16 contiguous bytes of a key body fails the build (`no-secret-bytes-in-output`).
- **Fixtures**: `pem-key-world-readable`, `no-secret-bytes-in-output` (build gate),
  `unreadable-home-not-clean`, `entry-cap-hit-is-unknown`, `fifo-at-config-path`, `chardev-at-path`,
  `ca-bundle-not-private-key` (new, under-claim/false-FAIL guard),
  `encrypted-openssh-key-lower-severity` (new), `acl-grants-other-user-read` (new),
  `symlink-into-other-fs-not-followed` (new).

---

#### `CREDENTIAL_FILE_EXPOSURE`
- **Title**: Application credential files follow their own documented permission rules
- **Impact**: high
- **Question**: What reusable credentials (cloud, registry, cluster, database, package-manager,
  application) are on disk, and are they protected as their own software requires?
- **PASS when** the enumeration completed (OK) and every discovered credential file satisfies the
  rule **its own software documents** (L24, F39): `~/.pgpass` ⊆ 0600 (PostgreSQL ignores it
  otherwise), `~/.ssh/config`/key files per `StrictModes`, `~/.netrc` 0600 (curl/ftp convention),
  `~/.docker/config.json`, `~/.aws/credentials`, `~/.kube/config`, `~/.git-credentials`, `~/.npmrc`,
  `~/.pypirc`, `*.env`, `*.keytab`, `*token*` not group/other-readable.
- **FAIL when** any of them is group- or world-readable (OK observation, adverse) — cite the rule and
  its source in the reason (e.g. "PostgreSQL ignores `.pgpass` unless 0600 or stricter").
- **UNKNOWN when**: a home directory is unreadable (EACCES — that user's credential exposure is
  unknown, never "clean"); the walk hit budget (BUDGET); an ACL is unreadable (EACCES/ENOTSUP).
- **Primary evidence**: `lstat` over a fixed relative path set inside every readable home plus
  `/etc` equivalents (`/etc/docker/config.json`, `/etc/kubernetes/admin.conf`,
  `/root/.aws` — EACCES expected), each with `mode/uid/gid/size/mtime` and the ACL xattr.
  For `~/.docker/config.json` the finding **names that base64 `auths` is not encryption** and never
  decodes it (F39).
- **Fallback chain**: home directory list from `/etc/passwd` (not `getent`, no exec); if a home is
  unreadable the path set is still `lstat`-ed (an `lstat` on a child of a 0700 dir yields EACCES,
  which is recorded as the boundary).
- **Evidence fields**: `file_metadata[]` per candidate `{path, exists, mode, uid, gid, size, mtime,
  acl_present, rule_id, rule_source, rule_satisfied}`; `unreadable_homes[]`.
- **Expected on the Lava host**: **pass**, severity `info` — no cloud/registry/cluster credential
  files exist in `/home` and no shell or database histories were found
  (`secrets.cloud_cred_dirs_ls`, `secrets.home_history_ls`); `/root` is unreadable and appears in
  `unreadable_homes[]` so the claim is scoped, not global.
- **Generic**: RHEL/Debian identical (path set is a union); Alpine ⇒ same; container ⇒ add
  `/run/secrets` and env-file mounts; VM ⇒ unchanged. On a machine with a real `~/.aws/credentials`
  at 0644 this check is the one that fires.
- **Traps**: reporting a *value*, or decoding a base64 `auths` entry (never); treating a missing file
  as a PASS for a home we could not read (that is UNKNOWN); `0640` with an empty group is effectively
  owner-only (L43) — say so rather than failing it; a credential file that is a symlink to another
  filesystem is recorded, not followed.
- **Fixtures**: `pgpass-0644`, `pgpass-0600`, `docker-config-present`, `unreadable-home-not-clean`,
  `kubeconfig-world-readable` (new), `netrc-0600-passes` (new), `env-file-with-token-metadata-only` (new),
  `no-secret-bytes-in-output` (build gate).

---

#### `PROVISIONING_DATA_PROTECTION`
- **Title**: Provisioning and instance metadata on disk is not readable by unprivileged users
- **Impact**: medium
- **Question**: What did the provisioning system leave on this machine, and who can read it?
- **PASS when** every existing provisioning artifact (`/var/lib/cloud/instance/user-data.txt` and
  `.i`, `/var/lib/cloud/instances/*`, `/var/lib/cloud/seed/*`, `/run/cloud-init/*`,
  `/etc/cloud/cloud.cfg.d/*`, Ignition `/usr/share/oem`, kickstart `/root/anaconda-ks.cfg`) is
  0600/0640-with-empty-group or absent (OK/ENOENT after a successful parent listing).
- **FAIL when** any provisioning artifact that can carry injected credentials is group/world-readable
  (OK, adverse) — in particular a non-empty `user-data`, a seed `meta-data`/`user-data`, or a
  `cloud.cfg.d` drop-in containing an `ssh_authorized_keys`/`password`/`chpasswd` *key name*
  (key name only; the value is never read or emitted).
- **UNKNOWN when**: `/var/lib/cloud` or `/run/cloud-init` is unreadable (EACCES); a readable
  `instance-data.json` self-redacts for non-root readers, so an empty-looking field is redaction, not
  absence (R4-F24) — any conclusion that depends on such a field is UNKNOWN;
  the directory exists but the walk hit budget (BUDGET).
- **Primary evidence**: `lstat` + directory listing of the paths above; `file_read` of
  `/run/cloud-init/cloud-id` and the **key names only** of `instance-data.json` (`READ_CAP_SMALL`);
  `lstat` of `instance-data-sensitive.json`, `combined-cloud-config.json`, `/etc/cloud/ds-identify.cfg`
  to record the 0600 boundary.
- **Fallback chain**: no cloud-init ⇒ check the Ignition/kickstart/Anaconda equivalents; none present
  (proven by parent listings) ⇒ PASS with `applicable: false` recorded in evidence, not UNKNOWN
  (proven absence is a real answer, F10).
- **Evidence fields**: `file_metadata[]`; `dir_walk` for `/var/lib/cloud`;
  `redaction_observed: bool`; `datasource_class`; `sensitive_paths_denied[]`.
- **Expected on the Lava host**: **pass**, severity `info`. `user-data.txt` is 0 bytes, 0600 root and
  the sibling `.i` is 308 B 0600 (`secrets.cloud_userdata_ls`); `instance-data.json` is 0644 and
  self-redacting while `instance-data-sensitive.json`, `combined-cloud-config.json` and
  `/etc/cloud/ds-identify.cfg` are 0600 (`identity.cloud_init_dirs`, F40). Evidence must state that
  **a 0-byte `user-data.txt` is not proof that no user-data was supplied** — the 308-byte `.i` sibling
  is the counter-evidence (R4 C1 trap).
- **Generic**: RHEL ⇒ kickstart `/root/anaconda-ks.cfg` (root-only, EACCES ⇒ UNKNOWN);
  Alpine ⇒ usually nothing (proven-absent PASS); container ⇒ nothing meaningful, `applicable: false`;
  VM ⇒ often a NoCloud seed ISO mounted read-only — enumerate it, do not read values.
- **Traps**: reading user-data *content* (never — it is the exact place a password ends up);
  concluding "no provisioning secrets" from a self-redacted readable file; treating ENOENT on
  `/var/lib/cloud` as PASS without having listed `/var/lib` successfully (F10).
- **Fixtures**: `cloud-init-userdata-world-readable` (new), `zero-byte-userdata-not-empty` (new),
  `instance-data-redacted-is-unknown` (new), `no-cloud-init-proven-absent-passes` (new),
  `entry-cap-hit-is-unknown`.

---

#### `SYSTEM_SECRET_STORE_PROTECTION`
- **Title**: System credential stores keep their expected restrictive permissions
- **Impact**: high
- **Question**: Are the OS's own secret stores still protected as the distro ships them, and where
  does our visibility stop?
- **PASS when** each existing store matches its expected class (OK): `/etc/shadow` and `/etc/gshadow`
  not other-readable (0640 root:shadow or 0600 root:root); `/etc/ssl/private` (or `/etc/pki/tls/private`)
  not other-traversable; `/etc/sudoers` 0440 and `/etc/sudoers.d` not other-writable/readable;
  SSH host **private** keys 0600 root; `/var/lib/systemd/random-seed` 0600;
  `/etc/krb5.keytab` 0600 when present.
- **FAIL when** any of them is other-readable or other-writable (OK, adverse); or an ACL grants a
  non-root principal read on one of them (decoded from `system.posix_acl_access`, L52).
- **UNKNOWN when**: `lstat` on the store itself returns EACCES because a **parent** is restrictive
  (the store's own mode is then unknown — the EACCES boundary is the finding, not a pass);
  the ACL xattr returns EACCES/ENOTSUP (L52: `ENODATA` = *no ACL* and is a positive answer, not an
  unknown); the store is absent and the parent listing also failed (EACCES ≠ ENOENT).
- **Primary evidence**: `lstat` + `Getxattr(system.posix_acl_access)` per path; group membership from
  the L43 helper to decide whether a group-readable mode is *effectively* root-only (e.g. `shadow`
  group with zero members).
- **Fallback chain**: none (metadata only). `getfacl` absence is irrelevant — the xattr is read
  directly (L39, R4-F28).
- **Evidence fields**: `file_metadata[]` `{path, exists, file_type, mode, uid, gid, size,
  acl_present, acl_entries_summary, group_member_count, effectively_root_only, errno}`.
- **Expected on the Lava host**: **pass**, severity `info`. `/etc/shadow` 0640 root:shadow with the
  `shadow` group empty ⇒ effectively root-only (`users.shadow_ls`, `users.group_members`);
  `/etc/ssl/private` `drwx--x---` root:ssl-cert, no `+` (`secrets.tls_private_ls`);
  `/etc/sudoers` 0440, `/etc/sudoers.d` 0750 (`users.sudoers_ls`); SSH host keys 0600 with 0644
  public halves (`network.ssh_dir_ls`). The ACL xattr result on `/etc/shadow` is **OPEN** — it is one
  of the two open observation requests (OR-OPEN-2) and will be settled by this check's first host run.
- **Generic**: RHEL ⇒ `/etc/shadow` 0000 root:root (still a PASS — stricter than expected is not a
  failure), `/etc/pki/tls/private`; Alpine ⇒ `/etc/shadow` 0640 root:shadow; container ⇒ the image's
  stores, annotated.
- **Traps**: mode bits are not authorisation (L42) — a 0444 file that returns EACCES is
  policy-denied, not a mode contradiction; a group-readable store with an **empty** group is
  effectively root-only (L43) and failing it is a false positive; `ENODATA` from the ACL xattr means
  "no ACL", not "unknown" (L52); EACCES on a store is a *boundary*, and reporting the boundary is the
  point — "we could not check" is a legitimate, required output (D3).
- **Fixtures**: `shadow-unreadable-not-passwordless`, `empty-privileged-group-root-only`,
  `mode-readable-but-eacces`, `acl-bytes-decode`, `acl-enodata-is-no-acl`,
  `acl-version-not-2-unknown`, `shadow-world-readable-fails` (new),
  `sudoers-d-world-writable-fails` (new).

---

### 2.3 `BMC_INBAND_ACCESS` — 5 checks

Category question (C6): can this machine talk to its own BMC from inside the OS, through which
interface, and who is permitted. **LD-3 is absolute: the sensor never opens `/dev/ipmi*` for
commands, never executes `ipmitool`/FreeIPMI/ipmiutil, never issues a Redfish or DSP0270 request**
(DSP0270 credential bootstrapping *creates a BMC account* despite reading like a query — R4-F50).
L26 splits this into separable findings; L27 covers the latent host interface.

---

#### `BMC_INBAND_INTERFACE_PRESENT`
- **Title**: Firmware declares an in-band management-controller interface
- **Impact**: info (observational — always `info` severity, LD-2)
- **Question**: Does this platform's firmware declare a BMC interface the OS could use?
- **PASS when** at least one of these is observed (OK): a `/sys/firmware/dmi/entries/38-*` directory
  (SMBIOS type 38, IPMI device), an ACPI `IPI0001*` device under `/sys/bus/acpi/devices/`, or a
  `dmi-ipmi-si.*` / `ipmi_si.*` platform device — **and** the enclosing directory listing succeeded.
  PASS here means "declared", not "usable".
- **FAIL when** never — this is observational. A platform with no declaration yields **pass** with
  `interface_declared: false` and `applicable: false`, provided the parent listings succeeded
  (`/sys/firmware/dmi/entries` readable and without a 38-*, plus no ACPI/platform device): that is a
  *proven* negative (F10) and it is the answer a VM should produce.
- **UNKNOWN when**: `/sys/firmware/dmi/entries` is absent **and** `/sys/bus/acpi` is absent (no
  SMBIOS/ACPI at all ⇒ the capability class is unavailable, UNSUPPORTED, not "no BMC");
  the directory exists but readdir returns EACCES.
- **Primary evidence**: readdir of `/sys/firmware/dmi/entries` (works unprivileged — R1-OR7),
  `/sys/bus/acpi/devices`, `/sys/devices/platform`, all via `os.Root("/sys")`.
  Per-entry **attributes are 0400** (`handle`, `instance`, `length`, `position`, `type`, `raw` — F4,
  R4-OR7): the sensor attempts one, records EACCES, and **never claims to have decoded type-38
  fields** (base address, IRQ, interface type stay unknown).
- **Fallback chain**: ACPI/platform device path alone → `/proc/devices` containing `ipmidev` →
  UNKNOWN. Never `dmidecode` (root-only *and* absent).
- **Evidence fields**: `device_probe{sysfs_path, capability_present, driver, module}`;
  `entries_observed[]`; `attribute_reads[] = {path, errno}`;
  `decoded_fields: null` with `decode_blocked_by: "EACCES on entry attributes (kernel 0400)"`.
- **Expected on the Lava host**: **pass**, severity `info`, `interface_declared: true`.
  `38-0` and `42-0` exist (`bmc.dmi_smbios_entries`); ACPI `IPI0001:00` at `\_SB_.PCI0.SBRG.SIKC` and
  the `dmi-ipmi-si.0` platform device are present (`bmc.ipmi_acpi_devices`,
  `bmc.platform_ipmi_devices`); all entry attributes EACCES (`bmc.dmi_entry_attrs`).
- **Generic**: VM ⇒ no `38-*`, no `/sys/class/ipmi`, no `/dev/ipmi*` — **the three together** are what
  prove "no BMC hardware"; one missing signal alone is not proof. Container ⇒ inherits the host's
  `/sys/firmware/dmi/entries` (F85) and would otherwise claim a BMC it cannot reach — annotate with
  the execution context (L45). Alpine ⇒ the DMI entry exists on the same hardware even if no driver
  is built (a *host configuration* fact, not a hardware fact).
- **Traps**: a firmware declaration can outlive a disabled BMC — pair with `BMC_RESPONDS_IN_BAND`
  (L26); `dmidecode` absence is irrelevant (L39); the entry directory existing is not a decode.
- **Fixtures**: `bmc-present-node-root-only`, `smbios-raw-eacces` (under-claim),
  `dmi-entries-listable-attrs-denied`, `bmc-absent-on-vm-proven` (new),
  `container-sees-host-sysfs`, `sysfs-symlink-topology`.

---

#### `BMC_RESPONDS_IN_BAND`
- **Title**: The BMC answers the host over the in-band interface
- **Impact**: info (observational)
- **Question**: Is there a live management controller behind the declared interface, and what is it?
- **PASS when** at least one attribute under `/sys/devices/platform/ipmi_bmc.*/` returns a parseable
  value within `BMC_OOB_DEADLINE` (OK) — that read *is* a live Get Device ID over KCS once the
  driver's short dynamic cache expires (F44), so a successful read is proof the BMC responded, with
  **no command issued by us**.
- **FAIL when** never (observational). "Interface declared but no `ipmi_bmc.*`" is reported as
  **unknown**, not fail — see below.
- **UNKNOWN when**: `ipmi_bmc.*` is absent while a type-38 entry exists (interface declared, driver
  not bound — the "present but not usable" middle state that is most often mis-reported as "no BMC");
  an attribute read exceeds `BMC_OOB_DEADLINE` (TIMEOUT — the goroutine is **abandoned**, the scan
  continues, and no cached value is presented as fresh, L40); the attribute returns EACCES
  (would be non-standard: they are 0444, F43) or UNSUPPORTED.
- **Primary evidence**: `os.Root("/sys")` reads of
  `/sys/devices/platform/ipmi_bmc.0/{ipmi_version,firmware_revision,manufacturer_id,product_id,device_id,guid}`,
  each in its own goroutine under a `BMC_OOB_DEADLINE` timer independent of the check context (L40),
  `READ_CAP_TINY`, `elapsed_ms` recorded per attribute.
  `manufacturer_id` is resolved through a small **embedded** IANA PEN table (offline; `0x002a7c` =
  10876 = Super Micro) with the raw value always shown next to the resolved name.
- **Fallback chain**: `/sys/class/ipmi/ipmi0` existence + `/proc/modules` refcounts for
  `ipmi_si`/`ipmi_msghandler`/`ipmi_devintf`/`ipmi_ssif` → `/proc/devices` `ipmidev` → UNKNOWN.
  A loaded `ipmi_si` is **not** proof of a responding BMC — only a populated identity attribute is.
- **Evidence fields**: `device_probe{sysfs_path, capability_present, access_permitted: n/a,
  driver, module}`; `attributes[] = {path, value, bytes_read, elapsed_ms, errno}`;
  `deadline_ms`; `manufacturer_resolved`; `never_issued_ipmi_command: true` (an explicit,
  auditable claim, LD-3).
- **Expected on the Lava host**: **pass**, severity `info`. IPMI 2.0, firmware 1.5,
  manufacturer `0x002a7c` (Super Micro), product `0x1d6e`, device_id 32, guid readable
  (`bmc.bmc_sysfs_attrs`); measured read latency 0.98–1.63 ms (`bmc.bmc_read_timing`, R1-OR6) — hence
  a 400 ms budget is generous by ~250× while still bounding the F44 worst case.
- **Generic**: VM ⇒ none of these paths exist ⇒ pass with `applicable: false` (paired with
  `BMC_INBAND_INTERFACE_PRESENT`); Alpine without the driver ⇒ UNKNOWN "driver not bound";
  container ⇒ no `ipmi_bmc.*` even on this hardware ⇒ UNKNOWN, annotated.
- **Traps**: conflating "no `ipmitool`" with "BMC unreachable" — the single worst error in this
  category (L39, R4 D2.4); `provides_device_sdrs=0` / `additional_device_support=0xbf` are capability
  bitmaps, **not** health; presenting a cached value as a fresh response; blocking the scan on an
  uncancellable read (L40 exists precisely for this).
- **Fixtures**: `bmc-unknown-because-no-ipmitool` (under-claim), `bmc-attr-read-hangs` (new),
  `bmc-attr-read-fast-path` (new), `bmc-no-devintf`, `proc-devices-ipmidev-name`,
  `stuck-read-does-not-block-output`.

---

#### `BMC_DEVICE_NODE_ACCESS`
- **Title**: The in-band BMC device node is not reachable by unprivileged local users
- **Impact**: high
- **Question**: Who on this machine can open the BMC device and issue IPMI commands to it?
- **PASS when** `/dev/ipmi*` exists and, from mode + owner + group + decoded ACL + resolved group
  membership, **no non-root principal** can open it (OK) — e.g. `0600 root:root`, `ENODATA` from the
  ACL xattr, and (if group-readable) an empty group (L43).
- **FAIL when** the node is other-accessible, or group-accessible with a **non-empty** group, or an
  ACL grants a named user/group read or write (OK, adverse). A local unprivileged user with an open
  path to the BMC is a full out-of-band-equivalent compromise path — hence `high`.
- **UNKNOWN when**: the node exists but the ACL xattr returns EACCES/ENOTSUP (L52 — `ENODATA` is a
  positive "no ACL", not an unknown); `stat` on the node fails; `/dev/ipmi*` is absent **while**
  `BMC_INBAND_INTERFACE_PRESENT` passed (then it is "`ipmi_devintf` not loaded", not "no BMC" —
  status unknown, reason ENOENT-with-context); the group database is unreadable.
- **Primary evidence**: `lstat` of `/dev/ipmi0`, `/dev/ipmi/0`, `/dev/ipmidev/0`
  (all three, because `ipmitool` itself confuses their errnos and reports EACCES as ENOENT — F46),
  `Getxattr(system.posix_acl_access)` decoded in pure Go (L52), `/etc/group` membership via the L43
  helper, plus a listing of `/etc/udev/rules.d` + `/lib/udev/rules.d` and `/etc/modprobe.d` for any
  rule that relaxes the default. **The node is never opened** (not even `O_RDONLY|O_NONBLOCK`).
- **Fallback chain**: udev rules and modprobe.d listings alone (to show nothing relaxes the kernel
  default) → UNKNOWN.
- **Evidence fields**: `device_probe{device_node, mode, uid, gid, capability_present,
  access_permitted}`; `acl{errno, version, entries_summary}`; `group_members`;
  `udev_rules_matching[]`; `modprobe_conf_matching[]`; `node_opened: false`.
- **Expected on the Lava host**: **pass**, severity `info`. `/dev/ipmi0` is `crw------- root:root`
  (0600) with `/dev/ipmidev/` absent (`bmc.ipmi_dev_ls`, `bmc.ipmi_dev_perms`, R3-OR5);
  no ipmi udev rules and no modprobe.d entries (`bmc.udev_rules_ipmi`, `bmc.modprobe_ipmi`);
  our account is in group `sudo` but the sudo **policy** is unreadable and we must not run `sudo` to
  find out — group membership is reported as an escalation *path with unknown policy* (R4 D3 trap (b)).
  The ACL xattr result is **OPEN** (OR-OPEN-2), settled by this check's first host run.
- **Generic**: RHEL ⇒ OpenIPMI packaging may ship different device handling (read the rules, do not
  assume); Alpine ⇒ the driver may not be built ⇒ ENOENT with the interface-declared context;
  VM ⇒ absent, `applicable: false`; container ⇒ no `/dev/ipmi0` even on BMC hardware.
- **Traps**: reporting 0600 root:root as "hardened by policy" — it is the plain devtmpfs default with
  **no** `capable()` gate in `ipmi_devintf` open (F42/R4-F48), so the precise, actionable statement is
  "restricted by default file mode, not by a capability check"; `/dev/ipmidev/` ENOENT says nothing
  about `/dev/ipmi0`; mode bits are not authorisation (L42) — pair with ACL + membership;
  never open the node "just to see" (LD-3, E1).
- **Fixtures**: `bmc-present-node-root-only`, `bmc-node-group-readable-nonempty-group` (new),
  `bmc-node-acl-grants-user` (new), `acl-enodata-is-no-acl`, `empty-privileged-group-root-only`,
  `bmc-no-devintf`, `no-getfacl-xattr-path` (under-claim).

---

#### `BMC_CLIENT_TOOLING_INVENTORY`
- **Title**: IPMI client tooling installed on the host (inventory)
- **Impact**: info (observational)
- **Question**: What local tooling exists that could drive the in-band BMC path, if the node were
  reachable?
- **PASS when** the inventory completed: every candidate name was resolved to found-or-not-found by
  scanning the `PATH` directories (OK). Found tools are listed with their resolved path and mode;
  none of them is ever executed (LD-3).
- **FAIL when** never (observational). A host with `ipmitool` **and** a non-root-accessible node is
  the adverse combination, and that verdict belongs to `BMC_DEVICE_NODE_ACCESS`, which cites this
  check's evidence.
- **UNKNOWN when**: `PATH` is empty/unset, or every PATH directory read returns EACCES, or the
  lookup budget is exhausted (BUDGET).
- **Primary evidence**: `lstat` of `<dir>/<name>` for each PATH entry × candidate set
  {`ipmitool`, `ipmi-*` (FreeIPMI: `bmc-info`, `ipmi-sensors`, `ipmi-chassis`), `ipmiutil`,
  `ipmievd`, `openipmish`, `freeipmi-config`}, plus `/usr/sbin`/`/sbin` even when not on our PATH
  (an unprivileged PATH often omits them — a false UTILITY_MISSING otherwise);
  plus `systemctl list-unit-files 'ipmi*'` state only if systemd is booted.
- **Fallback chain**: none. Never `which`/`command -v` through a shell (L41: no shell, no pipeline).
- **Evidence fields**: `tools[] = {name, found, resolved_path, mode, uid, gid}`;
  `path_dirs_scanned[]`; `path_dirs_unreadable[]`; `executed: false`.
- **Expected on the Lava host**: **pass**, severity `info`, all candidates **not found**
  (`bmc.ipmitool_which`, `services.utility_inventory`); `ipmi_si`, `ipmi_devintf`, `ipmi_msghandler`,
  `ipmi_ssif`, `acpi_ipmi` are loaded (`bmc.ipmi_modules`) and no ipmi services exist
  (`bmc.ipmi_services`) — recorded here as context so no reader mistakes tool absence for
  capability absence (L39).
- **Generic**: identical everywhere; the candidate set is name-based and needs no platform gate.
- **Traps**: letting a missing tool set any *other* check to UNKNOWN (the canonical under-claim,
  fixture `bmc-unknown-because-no-ipmitool`); scanning the whole filesystem for the binaries (bounded
  PATH scan only); executing a found tool to get its version (never — LD-3).
- **Fixtures**: `no-ipmitool-still-answers` (under-claim), `ipmitool-present-not-executed` (new),
  `path-dir-unreadable-partial-inventory` (new), `sbin-not-on-path-still-found` (new).

---

#### `BMC_HOST_INTERFACE_EXPOSURE`
- **Title**: Latent BMC host interfaces (USB network gadget / Redfish host interface)
- **Impact**: medium
- **Question**: Is there a second, non-KCS path from this OS to the BMC that could be brought up?
- **PASS when** no management-controller host interface is observed and the enumerations succeeded
  (OK): no SMBIOS type-42 entry (parent listing OK) **and** no USB network gadget whose parent chain
  is a management controller.
- **FAIL when** a management-controller host interface is present **and** currently usable — the
  interface `operstate` is `up` with an address configured, or a route exists toward it (OK, adverse):
  a live host↔BMC network path from the OS.
- **UNKNOWN when**: the interface exists but neither `operstate` nor `carrier` can be read
  (EACCES/UNSUPPORTED); the type-42 entry exists but the USB tree is unreadable; reading `speed` on a
  down link returns EINVAL — that is **normal** for a down link and must be recorded as UNSUPPORTED,
  never as a failure (R4 D4.5).
- **Present-but-down** is reported as **pass** with `latent_exposure: true` and the reason text
  naming that `down` is the *current* state and can be changed by anyone with the capability
  (L27: produce a verdict, not an UNKNOWN). Out-of-band LAN exposure is **unknown by construction** —
  the OS cannot see the dedicated BMC LAN port (F93) — and that sentence is mandatory in the evidence.
- **Primary evidence**: `/sys/class/net/*/` — `operstate`, `carrier`, `address`,
  `device/driver` basename, and the USB parent chain's `manufacturer`, `product`, `idVendor`,
  `idProduct`, `bInterfaceClass`; existence of `/sys/firmware/dmi/entries/42-*` (attributes 0400 ⇒
  no decode, F4).
- **Gating rule**: classify as a BMC host interface when a **USB network gadget** (driver in
  {`rndis_host`, `cdc_ether`, `cdc_ncm`, `usbnet`}) is present **and** firmware declares a
  management-controller host interface (type 42) **or** the gadget's manufacturer/product strings
  match a management-controller class pattern (e.g. an ASPEED/aspeed_vhub or "RNDIS/Ethernet Gadget"
  descriptor). **Never** gate on a vendor id literal (L37).
- **Fallback chain**: type-42 entry existence alone (interface declared, NIC not enumerated) →
  UNKNOWN.
- **Evidence fields**: `device_probe{sysfs_path, driver, capability_present}`;
  `interfaces[] = {ifname, driver, operstate, carrier, has_address, usb{manufacturer, product,
  idVendor, idProduct}, classified_as_bmc: bool, classification_basis[]}`;
  `smbios_type42_present`; `oob_lan_exposure: "unknown by construction (not visible to the OS)"`.
- **Expected on the Lava host**: **pass** with `latent_exposure: true`, severity `info`.
  USB NIC `enx…` on usb1/1-1.2, manufacturer `Linux 5.4.62 with aspeed_vhub`, product
  `RNDIS/Ethernet Gadget`, `0b1f:03ee`, driver `rndis_host`, `operstate` DOWN, no address
  (`bmc.usb_nic_identity`, `bmc.usb_cdc_net`, `network.nic_info`); SMBIOS `42-0` present
  (`bmc.dmi_smbios_entries`).
- **Generic**: VM ⇒ absent, `applicable: false`; most modern BMC servers ⇒ present; container ⇒
  `/sys/class/net` is the container's namespace — annotate and downgrade to UNKNOWN for the
  host-scoped claim.
- **Traps**: a USB NIC is not automatically a BMC NIC (gate on the classification basis, record it);
  `down` is not `absent`; EINVAL on `speed` is normal; inferring OOB reachability from an in-band
  observation (fixture `oob-exposure-unknown-not-absent`).
- **Fixtures**: `bmc-usb-nic-detected`, `oob-exposure-unknown-not-absent`,
  `usb-nic-not-bmc-no-type42` (new, false-positive guard), `usb-gadget-up-with-address-fails` (new),
  `speed-einval-on-down-link` (new).

---

### 2.4 `STORAGE_POSTURE` — 4 checks (custom category, LD-1)

Category thesis: **data-at-rest and decommissioning hygiene on rented hardware.** On a bare-metal
machine that moves between customers, "what is written here survives hand-back" is the question, and
this host answers it definitely: no encryption at rest, no redundancy, an identical idle second NVMe
whose contents the sensor **refuses to inspect**, and a health signal that is unknown *by proof*.
Nothing in this category ever opens a device node (L13, and the refusal is itself reported).

---

#### `DISK_ENCRYPTION_AT_REST`
- **Title**: Block-level encryption at rest for the root and data filesystems
- **Impact**: high
- **Question**: Is the data on this machine's disks encrypted at rest by a mechanism the OS can see?
- **PASS when** every mounted non-virtual filesystem's backing chain reaches a `dm-*` device whose
  `/sys/block/dm-*/dm/uuid` starts with `CRYPT-` (OK) — the unprivileged, tool-free LUKS/dm-crypt
  oracle (F58, cryptsetup's own convention).
- **FAIL when** the `/dev/mapper` and `/sys/block` listings both succeeded (OK) and **no** `CRYPT-`
  mapping exists in the backing chain of `/` — i.e. dm-crypt/LUKS is provably not in use.
  The reason and title are **scoped to dm-crypt/LUKS**; the finding must not assert "the disks are
  unencrypted" (L30).
- **UNKNOWN when**: `/dev/mapper` or `/sys/block` is unreadable (EACCES); `/proc/self/mountinfo`
  cannot be parsed (PARSE_ERROR); a mapping exists whose `dm/uuid` is unreadable.
- **Named blind spots (mandatory in the evidence, each with its reason)**:
  self-encrypting drive / TCG Opal — `block/sed-opal.c` gates every `IOC_OPAL_*` behind
  CAP_SYS_ADMIN and exposes **nothing** in sysfs (R4-F57), and the model string cannot substitute
  because the Micron base part number is shared between the non-SED and Opal SKUs (T-S12/R4-F58);
  ext4 **fscrypt** — the kernel supports it (`/sys/fs/ext4/features/encryption` present) but whether
  the filesystem *uses* it needs the superblock (root/`dumpe2fs`) ⇒ UNKNOWN (R4-OR6);
  ZFS/btrfs native encryption where those filesystems are present.
- **Primary evidence**: readdir `/dev/mapper`; `/sys/block/dm-*/dm/{uuid,name}`;
  `/proc/self/mountinfo` (split on the literal `" - "`, index from **both** ends because a variable
  number of optional fields precedes it — L31/F20); `/sys/block/<d>/holders` and `slaves` to walk the
  backing chain; `/sys/fs/ext4/<dev>/` feature listing; `/etc/crypttab` existence.
- **Fallback chain**: `/proc/crypto` and `/etc/crypttab` presence as weak corroboration →
  `lsblk -J -o NAME,FSTYPE` (bounded exec) looking for `crypto_LUKS` → UNKNOWN.
  `cryptsetup` absence is irrelevant — sysfs answers it (L39).
- **Evidence fields**: `device_probe` per dm device `{sysfs_path, dm_uuid, dm_name}`;
  `mount_chain[] = {mountpoint, source, fstype, backing_devices[]}`;
  `dm_devices_found: 0`; `scope: "dm-crypt/LUKS"`;
  `blind_spots[] = {mechanism, why_unknown, evidence_path_or_errno}`.
- **Expected on the Lava host**: **fail**, severity `high`, reason "no dm-crypt/LUKS mapping in the
  backing chain of `/`". `/dev/mapper` contains only `control`; no `/dev/dm-*`; no `/etc/lvm/lvm.conf`;
  every partition FSTYPE is vfat/ext4, never `crypto_LUKS`
  (`storage.dev_mapper_ls`, `storage.dev_ls`, `storage.lvm_conf_ls`, `storage.lsblk_fs`).
  Blind spots recorded: SED/Opal and fscrypt (`storage.nvme_smart_try`, `storage.ext4_features`).
- **Generic**: RHEL ⇒ frequently LUKS on `/` from the installer ⇒ PASS via the same `CRYPT-` prefix;
  Alpine ⇒ same mechanism; VM ⇒ same; container ⇒ the host's dm state is visible but the container's
  data is elsewhere ⇒ annotate and report UNKNOWN for the container-scoped claim;
  ZFS/btrfs hosts ⇒ add the native-encryption property read, else keep it as a named blind spot.
- **Traps**: "no dm ⇒ unencrypted" (L30, fixture `no-dm-not-unencrypted`) — the *scope* is the whole
  point; inferring SED capability from the model string (T-S12, false positives in **both**
  directions); treating `queue/write_cache` or `discard_granularity` as security properties (F61);
  `/sys/module` listing `dm_mod` proves nothing about mappings (T-S1).
- **Fixtures**: `luks2-dm-uuid`, `no-dm-not-unencrypted`, `sed-unknown-regardless-of-model`,
  `mountinfo-with-propagation-fields`, `dm-uuid-unreadable-is-unknown` (new),
  `fscrypt-supported-not-used-is-blind-spot` (new).

---

#### `ROOT_FILESYSTEM_REDUNDANCY`
- **Title**: The root filesystem survives the loss of a single storage device
- **Impact**: **medium** — decision and justification below
- **Question**: If one drive in this machine dies, does the root filesystem survive?
- **PASS when** the backing chain of `/` resolves to a redundant layer (OK): an `md` array whose
  `/sys/block/md*/md/level` is `raid1|raid5|raid6|raid10` with `degraded == 0`; a dm-raid target; a
  btrfs profile with `raid1`/`raid1c*`/`raid10` metadata **and** data; or a ZFS mirror/raidz.
- **FAIL when** the chain resolves to exactly one physical device and every redundancy enumeration
  succeeded (OK): `/proc/mdstat` readable with no array, `/dev/md*` absent after a successful `/dev`
  listing, no dm target, no btrfs/ZFS multi-device pool.
- **UNKNOWN when**: `/proc/mdstat` unreadable (EACCES); the backing chain cannot be resolved
  (a hardware-RAID controller presents one logical device and its health needs a vendor CLI — gate on
  **PCI class 0104**, never on a controller name, T-S7); `zpool`/`btrfs` are absent while a ZFS/btrfs
  filesystem is mounted (UTILITY_MISSING — the *layout* is then unknown, not absent).
- **Severity decision (asked for explicitly)**: `impact = medium`, status `fail` on a single-device
  root. Justification: on rented bare metal with an **identical idle second NVMe installed**, a
  single-device root is an availability posture fact an operator should act on, and the brief rewards
  a definite verdict where the evidence supports one (C8). It is not a security control, so not
  `high`. `info` was considered and rejected: many fleets deliberately run single-disk + rebuild, but
  `info` would hide the finding in any severity-sorted view, and the "may be intentional" caveat
  belongs in the `reason`, not in the severity. Reversal condition: if the lead judges availability
  out of scope for a *posture* sensor, flip `impact` to `info` — one constant, one line in NOTES.
- **Primary evidence**: `/proc/self/mountinfo` for the `/` source (L31); `/sys/block/<d>/holders`,
  `slaves`, `md/level`, `md/degraded`, `md/raid_disks`; `/proc/mdstat`;
  `/sys/bus/pci/devices/*/class` for class `0x0104`; `/sys/fs/btrfs/*/devices`.
- **Fallback chain**: `lsblk -J -o NAME,TYPE,MOUNTPOINT` (bounded exec) → `mdadm --detail --scan`
  (bounded exec, read-only) → UNKNOWN. `mdadm` is present on the host but unnecessary (L39).
- **Evidence fields**: `mount_chain[]`; `md_arrays[]`; `mdstat_excerpt` (capped);
  `pci_storage_controllers[] = {addr, class, driver}`; `spare_devices_present[]`;
  `redundancy_layer: none|md|dm-raid|btrfs|zfs`.
- **Expected on the Lava host**: **fail**, severity `medium`. `/` is `nvme0n1p2` ext4 on a single
  device; `/proc/mdstat` shows `Personalities : […]` with `unused devices: <none>`; no `/dev/md*`;
  no dm target; the storage controllers are NVMe + an ASMedia **AHCI** (PCI class 0106) with no disks
  (`storage.mountinfo`, `storage.mdstat`, `storage.dev_ls`, `storage.lspci_storage`,
  `storage.dev_mapper_ls`). Evidence names the identical unused `nvme1n1` as the available-but-unused
  redundancy capacity — the fact that makes this actionable.
- **Generic**: RHEL/Debian with md-RAID ⇒ PASS with the level and `degraded` value; a hardware-RAID
  host ⇒ UNKNOWN with the PCI class as evidence and the vendor-CLI gap named; VM ⇒ typically a single
  virtual disk backed by redundant host storage ⇒ FAIL is technically correct but the reason must say
  "guest-visible layout only; underlying host storage is not observable"; container ⇒ UNKNOWN.
- **Traps**: T-S2 — `/proc/mdstat` **always** lists personalities, so a populated `Personalities:`
  line is not an array; T-S11 — `/etc/mdadm/mdadm.conf` **exists** on this host with
  `HOMEHOST <ignore>` (F2), so a check keyed on config-file existence fires a false positive;
  T-S7 — the SATA controller's DMI DeviceName is `Asmedia SATA6G ASM1061R` (trailing "R" = RAID-capable)
  while its PCI class is 0106 and its driver is `ahci`; T-S9 — `/sys/class/nvme-subsystem/*` with
  `iopolicy=numa` is the standard NVMe subsystem layer, **not** multipath.
- **Fixtures**: `mdadm-conf-exists-no-array` (new), `mdstat-personalities-only` (new),
  `md-raid1-clean-passes` (new), `md-raid1-degraded-fails` (new),
  `hwraid-pci-class-unknown` (new), `ahci-controller-named-raid` (new), `mountinfo-with-propagation-fields`.

---

#### `UNUSED_ATTACHED_BLOCK_DEVICES`
- **Title**: Every attached block device is accounted for
- **Impact**: medium
- **Question**: Is there storage attached to this machine that nothing is using — and whose contents
  therefore have an unknown provenance?
- **PASS when** the enumeration completed (OK) and every physical device (excluding `loop`/`ram`/`zram`)
  has at least one of: a partition, a mount, a holder/slave relationship, a swap entry, or a udev
  filesystem/raid-member signature.
- **FAIL when** a physical device has **none** of those and all four enumerations succeeded (OK):
  no entries in `/sys/block/<d>/` matching `<d>p?[0-9]+`, empty `holders/`, no `/proc/swaps` entry,
  no mountinfo reference, and the udev record carries no `ID_FS_TYPE`. Reason wording is exactly
  "no partition table and no filesystem signature known to udev" (T-S10) — never "empty disk".
- **UNKNOWN when**: `/run/udev/data/b<maj>:<min>` is unreadable (EACCES) so the signature question is
  open; `/sys/block` readdir fails; `/proc/swaps` or mountinfo unreadable.
- **Explicit refusal (the point of the check)**: the sensor **does not open** the device to find out
  what is on it. The evidence carries `device_not_opened: true` and
  `remanence: "unknown by design — reading the device is out of scope"` (D-08, E1/E6).
- **Primary evidence**: `/sys/block/<d>/` listing (partitions are child directories),
  `holders/`, `slaves/`, `size`, `removable`, `/proc/swaps`, `/proc/self/mountinfo`,
  `/dev/disk/by-id/` symlink targets (a `-part*` link is a partition signal),
  udev DB `/run/udev/data/b<maj>:<min>` (`E:ID_FS_TYPE`, `E:ID_FS_USAGE`, readable 0755, R4-OR8).
- **Fallback chain**: `lsblk -J -o NAME,FSTYPE,MOUNTPOINT,TYPE` (bounded exec) → `/proc/partitions`
  → UNKNOWN.
- **Evidence fields**: `devices[] = {name, size_bytes, partitions[], holders[], slaves[],
  mountpoints[], udev_fstype, udev_record_path, udev_record_readable, in_use: bool,
  in_use_basis[]}`; `device_not_opened: true`; `udev_caveat:
  "fstype is the udev database at the last uevent, not a read of the disk"`.
- **Expected on the Lava host**: **fail**, severity `medium`. `nvme1n1` (960 GB, identical model to
  the root device) has no partition table, no `-part*` by-id link, empty `holders`, and no udev fs
  signature (`storage.partitions`, `storage.disk_by_id`, `storage.blk_queue_detail`,
  `storage.lsblk_fs`). Combined with `DISK_ENCRYPTION_AT_REST` failing, this is the category's thesis
  in two findings: anything written to this machine survives hand-back in cleartext, and there is a
  whole spare device nobody is tracking.
- **Generic**: VM ⇒ an attached-but-unformatted extra virtual disk produces the same true FAIL;
  a device deliberately used raw (a database or a VM image on the whole device) has **holders** or an
  open reference — record `in_use_basis` so the operator can see why we concluded what we did;
  container ⇒ the host's devices are visible (F85) ⇒ annotate and downgrade to UNKNOWN;
  Alpine ⇒ identical (sysfs + udev DB; if udevd is not running, the udev record is absent ⇒ the
  signature question is UNKNOWN, not "no filesystem").
- **Traps**: T-S3 — `FSTYPE=""` means "udev recorded no signature at the last uevent", and a
  filesystem created afterwards would be invisible; T-S5 — eight zero-byte `loop*` devices are not
  disks; T-S10 — "no partitions" ≠ "empty"; opening the device to check (never).
- **Fixtures**: `unused-second-disk-fails` (new), `raw-device-with-holder-passes` (new),
  `udev-record-partial`, `blockdev-eacces-fstype-known` (under-claim), `udevd-absent-signature-unknown` (new),
  `loop-devices-excluded` (new), `4kn-device-capacity`.

---

#### `MEDIA_HEALTH_VISIBILITY`
- **Title**: Drive health telemetry is observable, and what is observable shows no errors
- **Impact**: medium
- **Question**: Can this account see whether the drives are failing — and if it can, are they?
- **PASS when** a health source is readable **and** clean (OK): NVMe/SATA SMART obtained through a
  readable path, or (where SMART is unavailable but the question is still answerable) every readable
  signal is clean — `md/degraded == 0`, `/sys/block/<d>/device/state == live`, ext4
  `errors_count == 0` — **and** no source returned a permission error.
- **FAIL when** a readable signal shows a problem (OK, adverse): ext4 `errors_count > 0` with
  `first_error_time` populated, an md array `degraded > 0`, a device `state` of `dead`/`offline`,
  or a readable SMART critical-warning bit set.
- **UNKNOWN when**: SMART/health requires privilege we do not have — the canonical case, and the one
  this check exists to demonstrate. Record the **exact** observation: `nvme smart-log /dev/nvme0n1`
  → stderr `Permission denied`, rc 1; `/dev/nvme0` is `crw------- root:root`; the admin passthrough
  is gated by `nvme_cmd_allowed()` on **CAP_SYS_ADMIN**, not by group membership (F59, T-S4).
  Also UNKNOWN when `smartctl` is absent (UTILITY_MISSING — a *separate* fact that would not have
  helped, since it needs the same device) or when a read times out.
- **Partial evidence is not discarded**: an UNKNOWN here still carries `errors_count`,
  `first_error_time`, `lifetime_write_kbytes` and the device `state` — under-claiming by dropping the
  readable signals is as much a bug as over-claiming (L36).
- **Primary evidence**: `/sys/fs/ext4/<dev>/{errors_count,first_error_time,first_error_func,
  lifetime_write_kbytes}`; `/sys/block/<d>/device/state`; `/sys/block/md*/md/degraded`;
  `/sys/class/nvme/<c>/{model,firmware_rev,state}`. **No ioctl, no device open.**
- **Fallback chain**: `smartctl -H -j <dev>` (bounded exec, 3 s, JSON only — a stub that rejects `-j`
  must yield UNKNOWN, never positional parsing, fixture `no-json-flag`) → `nvme smart-log` (bounded
  exec; expected EACCES here and the errno *is* the evidence) → UNKNOWN. Both are fallbacks behind
  sysfs (L39).
- **Evidence fields**: `file_read[]` per sysfs signal `{path, value, bytes_read}`;
  `command_exec[]` per attempted tool `{command, binary_resolved_path, exit_code, stderr_excerpt,
  timed_out}`; `capability_required: "CAP_SYS_ADMIN on the NVMe character device"`;
  `remediation_note` (explicitly **not** "join group disk" — that is the wrong instruction, T-S4).
- **Expected on the Lava host**: **unknown**, reason `EACCES`, severity `medium`. `nvme smart-log` →
  `Permission denied`, rc 1; `nvme id-ctrl` → `Permission denied`; `/dev/nvme0` 0600 root:root;
  `/dev/nvme0n1` 0660 root:disk with group `disk` **empty**; `smartctl` absent
  (`storage.nvme_smart_rc`, `storage.nvme_smart_try`, `storage.dev_ls`, `users.group_members`,
  `storage.smartctl_scan`, R4-OR10). Readable partials carried in evidence:
  `/sys/fs/ext4/nvme0n1p2/errors_count = 0`, `lifetime_write_kbytes ≈ 2.8e6`
  (`storage.ext4_sysfs`), NVMe identity model/firmware from sysfs (`storage.nvme_sysfs_detail`).
  **This is the category's showcase UNKNOWN: an unknown that is a proof, with the errno, the device
  mode, the capability gate and the correct remediation.**
- **Generic**: a host where the account has CAP_SYS_ADMIN or a readable SMART path ⇒ a real PASS/FAIL
  (fixture `smart-eperm-identity-known` guards the under-claim in the other direction);
  SATA with `smartctl` installed and permissive ⇒ PASS/FAIL from JSON; VM ⇒ virtio devices expose no
  SMART at all ⇒ UNKNOWN/UNSUPPORTED (distinct from EACCES); container ⇒ UNKNOWN.
- **Traps**: T-S4 — EACCES, UTILITY_MISSING and device-absent all end in "no health data" and only
  one is true here; emitting the group-`disk` remediation would be a **confidently wrong instruction
  to an operator** (F100 was retracted for exactly this); treating `errors_count == 0` alone as a
  clean bill of health (it is a filesystem counter, not media health);
  `write_cache = write through` is not power-loss protection (F61).
- **Fixtures**: `smart-eperm-identity-known` (under-claim), `no-smartctl-identity-still-known`
  (under-claim), `no-json-flag`, `ext4-errors-count-nonzero-fails` (new),
  `smart-readable-and-clean-passes` (new), `four-failure-classes-one-check`.

---

### 2.5 `BOOT_CHAIN` — 6 checks (custom category, LD-1)

Category thesis: **is the code this machine boots and loads verified, and can the platform's trust
anchors still be changed?** This is the brief's own benchmark ("hardware security features active,
unsigned code permitted, boot chain verified — each its own check") and it holds the single most
severe fact on this host. L46 governs: decode kernel bit tables as data, Setup Mode is its own check,
`efivars` absent = *not applicable*, taint `E` ≠ enforcement.

---

#### `SECURE_BOOT_ENABLED`
- **Title**: UEFI Secure Boot is enabled
- **Impact**: high
- **Question**: Does the firmware verify the boot loader and kernel signatures?
- **PASS when** the `SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c` efivar reads byte **index 4**
  (after the 4-byte little-endian UEFI attribute prefix) as `1` (OK).
- **FAIL when** that byte is `0` (OK).
- **UNKNOWN when**: `/sys/firmware/efi/efivars` is not mounted or `/sys/firmware/efi` is absent —
  that is **legacy BIOS / non-EFI ⇒ not applicable**, reported as `unknown` with
  `applicable: false` and reason `ENOENT`, **never** as `fail` (L46, a classic false positive);
  the variable read returns EACCES (the older `/sys/firmware/efi/vars` interface is root-only —
  efivars is the world-readable one, F48); the file is shorter than 5 bytes (PARSE_ERROR).
- **Primary evidence**: `os.Root("/sys")` read of the efivar (`READ_CAP_TINY`), reporting
  `bytes_read`, the 4 attribute bytes and the value byte separately so a reviewer can verify the
  offset arithmetic.
- **Fallback chain**: `mokutil --sb-state` (bounded exec, 3 s — works unprivileged) → `/proc/cmdline`
  hints → UNKNOWN. `mokutil` absence must **not** turn a readable efivar into UNKNOWN (L39).
- **Evidence fields**: `file_read{path, bytes_read, attribute_prefix_hex, value_byte}`;
  `command_exec` for the fallback; `applicable`; `efi_present`.
- **Expected on the Lava host**: **fail**, severity `high`. The efivar reads
  `6 0 0 0 0` — attributes `06 00 00 00`, value byte **0** (`kernel.secureboot`), corroborated by
  `mokutil --sb-state` (`kernel.mokutil_sbstate`).
- **Generic**: BIOS-mode VMs ⇒ no efivars ⇒ `applicable: false`; Alpine ⇒ same kernel interface, and
  `mokutil` is usually absent (irrelevant); container ⇒ `/sys/firmware` normally absent ⇒
  not applicable, annotated (the *host* may well have Secure Boot on).
- **Traps**: `SecureBoot=0` and "no efivars at all" are different findings (L46);
  reading byte 0 instead of byte 4 inverts the answer on some platforms (fixture
  `efivars-attribute-prefix`); Secure Boot enabled says nothing about *what* keys are enrolled —
  that is the next check.
- **Fixtures**: `efivars-attribute-prefix` (new), `no-efivars-not-applicable` (new),
  `secureboot-enabled-passes` (new), `mokutil-missing-efivar-readable` (new), `oversize-sysfs-attr`.

---

#### `UEFI_PLATFORM_SETUP_MODE`
- **Title**: The UEFI platform is not in Setup Mode (a Platform Key is enrolled)
- **Impact**: **critical**
- **Question**: Can anyone with firmware access enrol their own Secure Boot keys on this machine?
- **PASS when** the `SetupMode-8be4df61-…` efivar value byte is `0` (OK) — a PK is enrolled and the
  platform is in User Mode.
- **FAIL when** that byte is `1` (OK): no Platform Key. Any party with firmware access (including,
  on a rented machine, whoever had it before us, and anyone reaching the BMC's virtual media/BIOS
  console) can enrol arbitrary keys and produce a machine that *appears* to Secure Boot correctly.
  This is `critical` because it defeats the entire boot-chain control class, not one setting.
- **UNKNOWN when**: efivars absent/unmounted (`applicable: false`, reason ENOENT — never `fail`);
  EACCES; short read (PARSE_ERROR).
- **Primary evidence**: same read pattern and offset arithmetic as `SECURE_BOOT_ENABLED`;
  additionally the *existence* of `PK-…`, `KEK-…`, `db-…`, `dbx-…` variables under `efivars` as
  corroboration (existence only; contents are not parsed).
- **Fallback chain**: `mokutil --sb-state` reports `SecureBoot disabled` but **not** Setup Mode on all
  versions — treat its silence as no evidence, not as a negative → UNKNOWN.
- **Evidence fields**: `file_read{path, bytes_read, attribute_prefix_hex, value_byte}`;
  `key_variables_present[]`; `applicable`.
- **Expected on the Lava host**: **fail**, severity `critical`. The efivar reads `6 0 0 0 1` ⇒
  value byte **1** (`kernel.secureboot`). This is the single most severe posture fact found on the
  host and is the reason `BOOT_CHAIN` exists as its own category rather than an `info` bucket (LD-1).
- **Generic**: identical everywhere efivars exist; VM/BIOS ⇒ not applicable; container ⇒ not applicable.
- **Traps**: folding this into `SECURE_BOOT_ENABLED` (L46 explicitly requires its own check — Secure
  Boot cannot be enforcing while the platform is in Setup Mode, so the two observations are one
  consistent state but **not** one finding); treating Setup Mode as a subset of "Secure Boot
  disabled" and therefore reporting only one of them.
- **Fixtures**: `setup-mode-own-check` (new), `efivars-attribute-prefix` (new),
  `no-efivars-not-applicable` (new), `setup-mode-zero-passes` (new).

---

#### `KERNEL_LOCKDOWN_MODE`
- **Title**: Kernel lockdown restricts privileged access to the running kernel
- **Impact**: medium
- **Question**: Even with Secure Boot, can a privileged user modify or read the running kernel
  (kexec, `/dev/mem`, BPF, module loading without signatures)?
- **PASS when** `/sys/kernel/security/lockdown` reads with `[integrity]` or `[confidentiality]`
  selected (OK).
- **FAIL when** it reads `[none]` (OK).
- **UNKNOWN when**: `/sys/kernel/security` is not mounted, or the file is absent (the Lockdown LSM is
  not compiled in ⇒ `applicable: false`, reason ENOENT after a successful parent listing —
  distinguishable from EACCES); the read returns EACCES (would be non-standard: the file is
  `-rw-r--r--` here, F50/R1-OR4).
- **Primary evidence**: `os.Root("/sys")` read of `/sys/kernel/security/lockdown` (`READ_CAP_TINY`),
  parsing the bracketed selection out of the option list; plus `/sys/kernel/security/lsm` (0444,
  the documented comma-separated active-LSM list, F50) recorded as context.
- **Fallback chain**: `/proc/cmdline` `lockdown=` parameter as *configured intent* only (clearly
  labelled: intent ≠ effective state) → UNKNOWN.
- **Evidence fields**: `file_read{path, value, options_offered, selected}`; `lsm_list`;
  `cmdline_lockdown_param`.
- **Expected on the Lava host**: **fail**, severity `medium`. `[none] integrity confidentiality`
  (`kernel.securityfs_modes`, `kernel.lsm`); active LSMs
  `lockdown,capability,landlock,yama,apparmor`.
- **Generic**: container ⇒ `/sys/kernel/security` typically unmounted ⇒ UNKNOWN, and any value read
  would describe the **host** kernel (annotate, L45); Alpine ⇒ often not compiled in ⇒
  `applicable: false`; VM ⇒ usually `[none]`.
- **Traps**: parsing the option list instead of the bracketed selection; `securityfs` unmounted vs
  file absent vs EACCES are three different reasons (L07, fixture `four-failure-classes-one-check`);
  assuming lockdown from Secure Boot state (they are independent; here both are off, but the
  inference direction is invalid).
- **Fixtures**: `lockdown-none-fails` (new), `lockdown-integrity-passes` (new),
  `securityfs-not-mounted-unknown` (new), `mode-readable-but-eacces`.

---

#### `UNSIGNED_OR_OUT_OF_TREE_MODULES`
- **Title**: No unsigned or out-of-tree kernel modules are loaded, and module signatures are enforced
- **Impact**: medium
- **Question**: Is code running in the kernel that the distribution did not sign or ship?
- **PASS when** `/proc/sys/kernel/tainted` reads with **neither** bit 12 (4096, `O` out-of-tree) nor
  bit 13 (8192, `E` unsigned) set (OK).
- **FAIL when** either bit is set (OK) — with **per-module attribution**: the offending modules are
  those whose `/sys/module/<name>/taint` is non-empty, named individually.
- **UNKNOWN when**: `/proc/sys/kernel/tainted` is unreadable (EACCES — non-standard, it is
  world-readable, F49); the bitmask is set but `/sys/module` cannot be enumerated (the *which*
  is then unknown while the *whether* is known — report `fail` for the bits with the attribution gap
  recorded, not a blanket UNKNOWN); `/proc/sys/kernel/tainted` parses to a non-integer (PARSE_ERROR).
- **Enforcement sub-fact (recorded, never inferred)**: `/sys/module/module/parameters/sig_enforce`
  and `CONFIG_MODULE_SIG_FORCE` / `CONFIG_MODULE_SIG_ALL` from the world-readable
  `/boot/config-$(uname -r)` (F40/R4-F25). Taint `E` records an unsigned module **even on a kernel
  that does not enforce signatures** — enforcement must never be inferred from taint (L46(c)).
  `modules_disabled` (`/proc/sys/kernel/modules_disabled`) is recorded as context.
- **Primary evidence**: `/proc/sys/kernel/tainted` (decoded as a **bit table in data**, all 18+ bits
  named, not just the two we judge on); readdir `/sys/module` + read each `taint` (bounded: the host
  has 98 modules, cap the enumeration at `WALK_ENTRIES` and record the count);
  `/boot/config-<kernel>` grep for the three `CONFIG_MODULE_SIG*` keys (`READ_CAP_SMALL`).
- **Fallback chain**: `/proc/modules` for the loaded list when `/sys/module` is unreadable →
  bitmask-only reporting → UNKNOWN. `lsmod` is never required (L39).
- **Evidence fields**: `file_read{path:"/proc/sys/kernel/tainted", value, decoded_bits[]}`;
  `tainting_modules[] = {name, taint_letters, path}`;
  `sig_enforce`; `config_module_sig[] = {key, value, source_path}`; `modules_total`.
- **Expected on the Lava host**: **fail**, severity `medium`. `tainted = 12288` = bits 12+13 = `O`+`E`,
  attributable to exactly **one** module: `/sys/module/bnxt_en/taint = OE` — the only non-empty
  `/sys/module/*/taint` (`kernel.module_taint`, `kernel.module_counts`, F49). Context worth stating:
  `bnxt_en` is a Broadcom NIC driver while the active NICs use `ixgbe` — an unsigned out-of-tree
  driver is loaded for hardware that is not in use. `modules_disabled = 0`
  (`users.kernel_hardening`).
- **Generic**: DKMS modules (VirtualBox, ZFS, NVIDIA) are a common **benign** source of `O` — the
  finding names the module so an operator can judge; container ⇒ `/proc/sys/kernel/tainted` is
  readable and describes the **host** kernel ⇒ attribute correctly or suppress (L45);
  Alpine ⇒ same interfaces.
- **Traps**: inferring signature enforcement from taint (L46); reporting the bitmask without decoding
  (a number is not evidence a reader can act on, D2); collapsing `O` and `E` into one bit;
  enumerating `/sys/module` and concluding "loaded" — `/sys/module` also contains built-in and
  never-instantiated modules (T-S1); the per-module `taint` file is the discriminator.
- **Fixtures**: `taint-E-not-enforcement` (new), `taint-clean-passes` (new),
  `taint-set-sysmodule-unreadable-attribution-gap` (new), `dkms-out-of-tree-named` (new),
  `sysfs-empty-is-unknown` (under-claim).

---

#### `TPM_PRESENCE`
- **Title**: A TPM is present and which version (observational)
- **Impact**: info (observational)
- **Question**: Does this machine have a hardware root of trust available for measured boot or key
  sealing?
- **PASS when** `/sys/class/tpm/tpm0/tpm_version_major` reads `1` or `2` (OK), or the class directory
  exists with an identifiable device (OK). "Present" is the finding; usage is not.
- **FAIL when** never (observational). No TPM ⇒ **pass** with `tpm_present: false` when
  `/sys/class/tpm` is readable and empty (a proven negative, F10).
- **UNKNOWN when**: `/sys/class/tpm` is absent entirely (UNSUPPORTED — no TPM subsystem in this
  kernel/namespace) or unreadable (EACCES).
- **Explicit blind spot (mandatory in evidence)**: TPM **usage** — PCR values and the measured-boot
  event log (`/sys/kernel/security/tpm0/binary_bios_measurements`) — is root-only; a denial there is
  UNKNOWN, **not** "no measured boot" (R4 F.3).
- **Primary evidence**: `/sys/class/tpm/tpm0/{tpm_version_major,device/description}`, the
  `device` symlink target basename (firmware id, e.g. `MSFT0101`), and `lstat` of `/dev/tpm0`,
  `/dev/tpmrm0` (mode/owner — never opened).
- **Fallback chain**: `/sys/class/tpm/` readdir → `/proc/devices` `tpm` → UNKNOWN.
- **Evidence fields**: `device_probe{sysfs_path, capability_present, access_permitted}`;
  `tpm_version`; `device_nodes[] = {path, mode, uid, gid}`;
  `measured_boot_state: "unknown (event log root-only)"` with the errno.
- **Expected on the Lava host**: **pass**, severity `info`. TPM 2.0 at
  `/sys/class/tpm/tpm0` → platform `MSFT0101:00`; `/dev/tpm0` and `/dev/tpmrm0` 0600 root:root;
  event log root-only (`kernel.tpm`, F82).
- **Generic**: most VMs have no TPM (vTPM on some) ⇒ proven-absent pass; container ⇒ `/sys/class/tpm`
  usually absent ⇒ UNKNOWN/UNSUPPORTED; aarch64 ⇒ same interface where a TPM exists.
- **Traps**: reporting "TPM present" as a security control (presence ≠ use; on this host Secure Boot
  is off and the platform is in Setup Mode, so the TPM measures nothing that is verified);
  opening `/dev/tpm0` (never).
- **Fixtures**: `tpm2-present-info` (new), `no-tpm-proven-absent` (new),
  `tpm-eventlog-root-only-unknown` (new).

---

#### `BOOT_ARTIFACT_READABILITY`
- **Title**: Boot artifacts are not readable by unprivileged users
- **Impact**: low
- **Question**: Can any local user read the kernel, initramfs, boot loader configuration or ESP
  contents — material that routinely carries injected provisioning data on provider images?
- **PASS when** every existing boot artifact is not other-readable (OK): `/boot/vmlinuz-*`,
  `/boot/initrd.img-*` / `/boot/initramfs-*`, `/boot/grub/grub.cfg`, `/boot/System.map-*`,
  and the ESP mounted without world-readable masks (`fmask`/`dmask` ≥ 0077).
- **FAIL when** any of them is other-readable (OK, adverse) — the initramfs is the important one,
  because bare-metal provider images frequently inject provisioning material into it.
- **UNKNOWN when**: `/boot` is a separate unreadable mount (EACCES); the running kernel's initramfs
  cannot be identified (the `uname -r`-matched file is absent while `/boot` listed successfully ⇒
  record it, do not guess); `/proc/self/mountinfo` unreadable (the ESP mask question is then open).
- **Primary evidence**: readdir `/boot` + `lstat` per artifact; `/proc/self/mountinfo` for the ESP's
  `fmask`/`dmask`/`umask` options (L31 parsing). **The initramfs is never opened** — extracting it to
  look for embedded secrets is expensive, unbounded and outside read-only intent (R4 C2 trap (a));
  mode and size are the finding.
- **Fallback chain**: `findmnt -J` (bounded exec) for mount options if mountinfo parsing fails →
  UNKNOWN.
- **Evidence fields**: `file_metadata[]` `{path, mode, uid, gid, size, matches_running_kernel}`;
  `esp{mountpoint, fstype, options, world_readable}`; `initramfs_not_opened: true`.
- **Expected on the Lava host**: **fail**, severity `low`. Two initramfs images are **0644**
  (67 MB and 71 MB) while `grub.cfg`, `vmlinuz` and `System.map` are 0600, and `/boot/efi` is mounted
  `fmask=0022,dmask=0022` ⇒ the ESP is world-readable
  (`secrets.boot_artifacts_ls`, `kernel.boot_ls`, `storage.findmnt`).
- **Generic**: RHEL ships initramfs 0600 by default ⇒ the same check yields a different, correct
  answer (that asymmetry is the reason it is worth having); Debian/Ubuntu 0644 is common, hence
  `impact: low` with a reason that explains *why it matters here* (provisioning material on
  bare-metal provider images); container ⇒ no `/boot` ⇒ `applicable: false`;
  VM ⇒ same as the guest distro.
- **Traps**: opening the initramfs (never); reporting the ESP as a filesystem permission problem when
  it is a **mount option** (vfat has no owners — the mask is the control); flagging a stale
  `initrd.img.old` that does not match the running kernel at the same weight as the live one
  (record `matches_running_kernel`).
- **Fixtures**: `initramfs-world-readable-fails` (new), `initramfs-0600-passes` (new),
  `esp-dmask-world-readable` (new), `boot-unreadable-is-unknown` (new),
  `mountinfo-with-propagation-fields`.

---

## 3. Cross-cutting rules the engine enforces

1. **One finding per registered check, always** (L34, D3, F66/F68). `len(findings) == len(registry)`
   is a test invariant on every run, including a timed-out run, a panicking check and a run where a
   whole subsystem is missing. An unset verdict never defaults to PASS. Run-level errors
   (cannot write `--out`, invalid flags) live **outside** the findings array. Fixtures
   `registry-count-invariant`, `panicking-check`.
2. **Severity rule LD-2**, applied centrally by the engine, never per check:
   `severity = impact` when `status ∈ {fail, unknown}`; `severity = info` when `status = pass`;
   observational checks (`impact: info`) are always `info`. Rationale in DECISIONS D-04: an
   unverifiable control is an assurance gap of the same weight, and down-weighting unknowns would
   make an EACCES-heavy unprivileged run look healthier than a privileged one.
3. **Reason is mandatory and from the closed vocabulary** for `fail` and `unknown`
   (schema `if/then`; EVIDENCE_MODEL §7). Free text goes in `evidence.detail`, never in `reason`.
   The five failure classes stay five and are never collapsed (L35, fixture
   `four-failure-classes-one-check`).
4. **Contradiction handling**: when two probes disagree (oracle vs walker, config vs socket table,
   two sysfs paths), the engine records **both** observations with their sources and emits
   `status: unknown`, `reason: CONTESTED`. First-observation-wins is forbidden. Where one source is
   *definitionally* authoritative (e.g. the socket table over `sshd_config` for what is listening,
   L20/F30) that is a documented precedence rule stated in `resolution_rule`, not a silent pick.
5. **Evidence conventions**: every block carries the universal fields plus its
   `observation_type` shape; paths are absolute as opened; `errno` is symbolic; `exit_code` and
   `signal` are separate; `timed_out: true` forces `unknown`; `truncated: true` forbids `pass`;
   every enumeration carries its boundary (`unreadable_dirs`, `dirs_pruned`, `budget_exhausted`,
   `crossed_mounts`). Evidence records the observation, not the conclusion (D2).
6. **Secret redaction (build-gated)**: no file contents from any path classified as credential
   material; no hashes of secret values; `/etc/machine-id` never verbatim; no process environment;
   no key bytes, not even a 16-byte substring. Two build gates run over the real artifact:
   `no-secret-bytes-in-output`, `machine-id-not-emitted-raw` (EVIDENCE_MODEL §8, L23, L32).
7. **Determinism** (L47, D8): findings sorted by `(category, check_id)`; `encoding/json` v1 with
   `SetEscapeHTML(false)`; `collected_at` formatted explicitly as RFC 3339 (not via `time.Time`
   marshalling, whose width varies); `int64` for every count, size, mode, uid and exit code.
   Two runs differ only in timestamps and genuinely volatile values.
8. **Safety invariants in every check**: read-only; no `sudo`/`su`/`doas` ever; no network; no shell
   and no pipelines (L41); one exec runner with Setpgid + group-kill + WaitDelay + capped writers
   (L09–L12); one read primitive with `O_RDONLY|O_NONBLOCK|O_CLOEXEC`, `fstat`-on-fd, `IsRegular`
   required, caps from policy and never from `st_size` (L05, L13); `os.Root` for `/sys` and `/proc`
   with a documented degradation path (L15, F19); no device node is ever opened.
9. **Budget-cut behaviour.** Three nested budgets: `SCAN_DEADLINE` (60 s default) → per-check context
   (`min(perCheckBudget, remaining)`) → per-subprocess `WaitDelay`. Checks are classified:
   - **Cheap (< 10 ms each, pure sysfs/procfs reads)**: all of `BOOT_CHAIN`, `BMC_*` except the OOB
     read, `DISK_ENCRYPTION_AT_REST`, `ROOT_FILESYSTEM_REDUNDANCY`, `UNUSED_ATTACHED_BLOCK_DEVICES`,
     `SYSTEM_SECRET_STORE_PROTECTION`, `REMOTE_LISTENING_SURFACE` (the `/proc/net` path).
   - **Medium (one or a few bounded execs)**: the SSH family (one shared `sshd -G` run),
     `SSH_POLICY_IN_FORCE`, `HOST_FIREWALL_STATE`, `LOGIN_AND_ESCALATION_SURFACE`,
     `MEDIA_HEALTH_VISIBILITY`.
   - **Expensive (bounded walks)**: `PRIVATE_KEY_MATERIAL_EXPOSURE` (the only walk that can
     approach its 8 s cap), `CREDENTIAL_FILE_EXPOSURE`, `PROVISIONING_DATA_PROTECTION`.
   - **Uncancellable-read risk**: `BMC_RESPONDS_IN_BAND` only — its own goroutine + timer, abandoned
     on overrun (L40).
   Execution order is cheap → medium → expensive, so a deadline cut costs the fewest answers.
   **A cut looks like this in the output**: the not-yet-run checks still appear, `status: unknown`,
   `reason: BUDGET_EXHAUSTED`, `evidence.detail: "scan deadline exhausted before this check ran"`,
   `evidence.scan_deadline_ms` and `evidence.elapsed_ms` — plus a machine-level extra
   `scan.budget_cut: true` with the count. A partially completed walk emits its real evidence with
   `budget_exhausted: entries|depth|time` and `status: unknown`. The scan deadline bounds *scheduling
   and output*, never a stuck read: output is written without waiting on a hung goroutine (L14, F17).
10. **Capability gating before probing** (L37, L38): never gate on distro ID, hostname, vendor or
    port literals; always on an observed path, an observed capability, or an evidence class.
    Gates used here: `/run/systemd/system` (systemd booted), `/sys/firmware/efi` (EFI),
    `/sys/kernel/security` (securityfs), `/sys/class/ipmi` + DMI 38 (BMC), `/sys/block` (storage),
    execution context (L45).
11. **Panic isolation**: every check runs behind `recover()`; a panic becomes exactly one finding for
    that `check_id` with `status: unknown`, `reason: EXECUTION_ERROR` and the recovered value's type
    (never the panic value verbatim, which could carry data).

---

## 4. Vertical-slice recommendation

**Implement `SSH_ROOT_LOGIN_POLICY` end to end first.**

It is the only check that exercises every load-bearing seam in one go:
- **exec**: the bounded runner on `/usr/sbin/sshd -G` — Setpgid, group kill, `WaitDelay`, capped
  writers, the *real* child exit code (the recon's own rc 141 was a SIGPIPE artifact of a `head`
  pipe, R1-OR9 — the exact mistake L41 exists to prevent).
- **file read**: the Include-aware walker over `/etc/ssh/sshd_config` + `sshd_config.d/*.conf`
  through the capped read primitive, with `Include`-at-position and first-obtained-value-wins
  semantics and shadowed-occurrence reporting (L16, F27).
- **UNKNOWN path, and a real one**: on the Lava host this check's honest answer is
  `unknown/EACCES` because `permitrootlogin` is `without-password` while `/root/.ssh` is unreadable.
  The slice therefore proves the *hard* semantics (EACCES ≠ absent, under-claiming is a bug, reason +
  evidence required) on real host data rather than on a fixture.
- **CONTRADICTION path**: oracle vs walker disagreement is implementable and testable inside the same
  slice, exercising the CONTESTED rule end to end.
- **the whole output contract**: one finding, severity from LD-2, RFC 3339 timestamps, deterministic
  ordering, schema validation, and the `machine` block it sits next to.

It also de-risks the largest single unknown in the plan (LD-5's dependence on `sshd -G` behaving as
observed) at the earliest possible moment, and it settles OR-OPEN-3 (group-kill leaves no
descendants; `os.OpenRoot("/proc")` works on 6.8.0-139) on the first host run.

Runner-up considered and rejected: `BMC_DEVICE_NODE_ACCESS` — excellent evidence semantics
(mode + ACL + membership + policy gate) and it settles OR-OPEN-2, but it has **no exec path**, so it
would leave the riskiest primitive unexercised.

---

## 5. Coverage matrix

### 5.1 Contract items → check ids

| Contract | Covered by |
|---|---|
| B1/B1a host_id stability + provenance | §1.1 (+ two-run equality test) |
| B2/B2a owner + explicit unknown | §1.3 |
| B3/B3a/B3b/B3c vendor, model, CPU, memory | §1.4, §1.6, §1.7 |
| B4 OS | §1.5 |
| B5/B5a storage | §1.8 |
| B6/B7/AM-5/AM-7 unknown representation, extras | §1 global rules |
| C1 ≥ 2 checks per category, distinct results | 6/4/5/4/6 = 25 checks |
| C2 required categories | REMOTE_ACCESS, SECRETS_ON_DISK, BMC_INBAND_ACCESS |
| C3 custom category + intent | STORAGE_POSTURE, BOOT_CHAIN (LD-1) |
| C4/C4a remote access in force | `SSH_ROOT_LOGIN_POLICY`, `SSH_AUTH_METHODS_POLICY`, `SSH_POLICY_IN_FORCE`, `REMOTE_LISTENING_SURFACE`, `LOGIN_AND_ESCALATION_SURFACE`, `HOST_FIREWALL_STATE` |
| C5/C5a secrets present + protected, metadata only | `PRIVATE_KEY_MATERIAL_EXPOSURE`, `CREDENTIAL_FILE_EXPOSURE`, `PROVISIONING_DATA_PROTECTION`, `SYSTEM_SECRET_STORE_PROTECTION` |
| C6/C6a→LD-3 BMC interface, who is permitted | `BMC_INBAND_INTERFACE_PRESENT`, `BMC_RESPONDS_IN_BAND`, `BMC_DEVICE_NODE_ACCESS`, `BMC_CLIENT_TOOLING_INVENTORY`, `BMC_HOST_INTERFACE_EXPOSURE` |
| C7 `info` is a real answer | `BMC_INBAND_INTERFACE_PRESENT`, `BMC_RESPONDS_IN_BAND`, `BMC_CLIENT_TOOLING_INVENTORY`, `TPM_PRESENCE` (observational) + every `pass` (LD-2) |
| C8 establish, do not assume | every check's UNKNOWN branch + `default_source` requirement (L19) |
| C9 depth over volume | 25 checks, each with fallbacks, traps and fixtures |
| D1/D1a finding fields, stable ids | §2 blocks (UPPER_SNAKE_CASE, unique, stable) |
| D2 evidence quality | §3 rule 5 + per-check evidence fields |
| D3 no silent omission | §3 rules 1, 9, 11 |
| D4/D5 document shape, validation | §3 rule 7 + LD-6 (test-time full schema, runtime invariants) |
| D6→LD-2 severity | §3 rule 2 |
| D7 timestamps | §3 rule 7 |
| D8 determinism | §3 rule 7 |

### 5.2 Laws → checks (non-exhaustive; the load-bearing bindings)

| Law | Checks |
|---|---|
| L01, L02, L33 | §1.1, §1.4 (machine identity) |
| L03, L07, L35, L42 | every check's reason typing; `SYSTEM_SECRET_STORE_PROTECTION`, `KERNEL_LOCKDOWN_MODE` |
| L05, L13, L14, L15 | all sysfs/procfs readers; `stuck-read-does-not-block-output` |
| L09–L12, L41 | `SSH_*`, `HOST_FIREWALL_STATE`, `MEDIA_HEALTH_VISIBILITY`, `BMC_CLIENT_TOOLING_INVENTORY` |
| L16–L19, LD-5 | `SSH_ROOT_LOGIN_POLICY`, `SSH_AUTH_METHODS_POLICY`, `SSH_POLICY_IN_FORCE` |
| L20, L21 | `REMOTE_LISTENING_SURFACE`, `SSH_POLICY_IN_FORCE` |
| L22, L43 | `LOGIN_AND_ESCALATION_SURFACE`, `BMC_DEVICE_NODE_ACCESS`, `SYSTEM_SECRET_STORE_PROTECTION` |
| L23, L24, L25 | all four `SECRETS_ON_DISK` checks |
| L26, L27, LD-3 | all five `BMC_INBAND_ACCESS` checks |
| L28, L29, L30, L31 | §1.8, `DISK_ENCRYPTION_AT_REST`, `UNUSED_ATTACHED_BLOCK_DEVICES`, `MEDIA_HEALTH_VISIBILITY` |
| L32 | §1.1 + build gate |
| L34, L36 | §3 rules 1, and every check's under-claim fixture |
| L37, L38, L39, L45 | §3 rule 10; `BMC_CLIENT_TOOLING_INVENTORY`; §1.0 |
| L40 | `BMC_RESPONDS_IN_BAND` |
| L44 | `os.kernel_boot_default` extra (kernel drift is reported in the machine block; see OPEN-3) |
| L46 | all six `BOOT_CHAIN` checks |
| L47, L50, L51 | §3 rules 7, 8 (engine-level) |
| L52 | `SYSTEM_SECRET_STORE_PROTECTION`, `BMC_DEVICE_NODE_ACCESS`, `PRIVATE_KEY_MATERIAL_EXPOSURE` |

### 5.3 Expected status per check by profile

A = host-shaped (the Lava host), B = generic minimal (VM/lean Debian, no DMI/BMC/efivars),
C = restricted (container / EACCES-heavy). `p` = pass, `f` = fail, `u` = unknown,
`p*` = pass with `applicable: false` (proven not-applicable).

| check_id | impact | A | B | C |
|---|---|---|---|---|
| SSH_ROOT_LOGIN_POLICY | high | **u** (EACCES on /root/.ssh) | p or f | u (no sshd / UTILITY_MISSING) |
| SSH_AUTH_METHODS_POLICY | high | **p** | p or f | u |
| SSH_POLICY_IN_FORCE | medium | **p** | p / u (no systemd) | u (UNSUPPORTED) |
| REMOTE_LISTENING_SURFACE | medium | **p** | p or f | u (/proc/net masked) |
| LOGIN_AND_ESCALATION_SURFACE | medium | **u** (sudoers + shadow + /root EACCES) | u (same class) | u |
| HOST_FIREWALL_STATE | medium | **u** (ufw active, rules 0640) | f (no filter + listener) or u | u |
| PRIVATE_KEY_MATERIAL_EXPOSURE | high | **p** (scope printed) | p or f | u (BUDGET/EACCES) |
| CREDENTIAL_FILE_EXPOSURE | high | **p** | p or f | p or f (container scope) |
| PROVISIONING_DATA_PROTECTION | medium | **p** | p* (no cloud-init) | p* |
| SYSTEM_SECRET_STORE_PROTECTION | high | **p** | p | p / u |
| BMC_INBAND_INTERFACE_PRESENT | info | **p** (declared) | p (declared:false, proven) | u (host sysfs inherited, annotated) |
| BMC_RESPONDS_IN_BAND | info | **p** (IPMI 2.0, Supermicro) | p* | u |
| BMC_DEVICE_NODE_ACCESS | high | **p** (0600 root:root) | p* (ENOENT, proven) | u |
| BMC_CLIENT_TOOLING_INVENTORY | info | **p** (none found) | p | p |
| BMC_HOST_INTERFACE_EXPOSURE | medium | **p** (latent, DOWN) | p* | u |
| DISK_ENCRYPTION_AT_REST | high | **f** (no dm-crypt) | p (LUKS) or f | u (annotated) |
| ROOT_FILESYSTEM_REDUNDANCY | medium | **f** (single device) | f (single virtual disk, caveated) | u |
| UNUSED_ATTACHED_BLOCK_DEVICES | medium | **f** (nvme1n1) | p | u |
| MEDIA_HEALTH_VISIBILITY | medium | **u** (CAP_SYS_ADMIN, proof) | u (virtio, UNSUPPORTED) | u |
| SECURE_BOOT_ENABLED | high | **f** | u/`p*` (no efivars) or p | u (`applicable: false`) |
| UEFI_PLATFORM_SETUP_MODE | critical | **f** | u/`p*` or p | u |
| KERNEL_LOCKDOWN_MODE | medium | **f** ([none]) | f or u (not compiled in) | u (securityfs unmounted) |
| UNSIGNED_OR_OUT_OF_TREE_MODULES | medium | **f** (O+E, bnxt_en) | p or f | f/u — describes the **host** kernel, annotated |
| TPM_PRESENCE | info | **p** (2.0) | p (proven absent) | u |
| BOOT_ARTIFACT_READABILITY | low | **f** (initramfs 0644, ESP dmask 0022) | p (RHEL 0600) or f | p* (no /boot) |

Predicted Lava-host distribution: **9 pass · 8 fail · 8 unknown** —
1 critical, 5 high, 8 medium, 1 low fail/unknown-carried severities, 10 info.
Every one of the 8 unknowns has a named cause and an errno, and 4 of them are unknown *by
construction* for an unprivileged account (D-08).

---

## 6. OPEN items for the lead

- **OPEN-1 — SSH forwarding/limits placement.** `maxauthtries`, `logingracetime`, `x11forwarding`,
  `allowtcpforwarding`, `allowagentforwarding`, `gatewayports`, `permittunnel` currently ride in
  `SSH_AUTH_METHODS_POLICY`'s evidence as `observed_directives` with
  `verdict_contributing: false`. Alternative: a 7th REMOTE_ACCESS check `SSH_SESSION_CAPABILITIES`
  (`impact: info`). Kept folded to respect "3–6 per category"; splitting is a one-line registry change.
- **OPEN-2 — boot artifacts category.** `BOOT_ARTIFACT_READABILITY` sits in `BOOT_CHAIN` (decided),
  with a cross-reference from `SECRETS_ON_DISK`. R4's HOST_SPECIFIC_PLAN §C2 placed it under secrets;
  if the lead prefers that, move the check id, do not duplicate it.
- **OPEN-3 — kernel/patch drift.** F52/L44 give a provable drift finding on this host (running
  6.8.0-139 while `/boot` symlinks point at 7.0.0-31, and `/var/lib/apt/lists` is **empty** so
  "nothing upgradable" is meaningless — the T-U1 trap). It is currently only a machine-block extra
  (`os.kernel_boot_default`). A sixth category `UPDATE_DRIFT` (or a 7th BOOT_CHAIN check
  `BOOT_KERNEL_DRIFT`, impact medium) would make it a finding. Not proposed as scope creep, but it is
  the strongest fact currently going unreported.
- **OPEN-4 — `ROOT_FILESYSTEM_REDUNDANCY` impact** is `medium` with a `fail` on this host
  (justified in §2.4). Flip to `info` if availability is judged out of scope for a posture sensor.
- **OPEN-5 — two observation requests are settled by the first host run, not by recon**:
  OR-OPEN-2 (ACL xattr errno on `/dev/ipmi0`, `/etc/shadow`, `/var/log/journal` — affects
  `BMC_DEVICE_NODE_ACCESS` and `SYSTEM_SECRET_STORE_PROTECTION`) and OR-OPEN-3 (group-kill leaves no
  descendants; `os.OpenRoot("/proc")` on 6.8.0-139 — affects the runner and every `os.Root` reader).
  Both are exercised by the vertical slice plus `BMC_DEVICE_NODE_ACCESS`.
- **OPEN-6 — `sshd -G -C` (F25, CONTESTED)** is not relied upon anywhere; Match-conditional policy
  stays a bounded UNKNOWN (L17). If OR-OPEN-1 is ever answered, `SSH_ROOT_LOGIN_POLICY` and
  `SSH_AUTH_METHODS_POLICY` gain a per-connection branch — gated on the exec result, never on a
  version string.
