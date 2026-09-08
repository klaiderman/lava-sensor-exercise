# PRIOR_ART — reconciled REUSE / STEAL_PATTERN / BUILD / REJECT matrix

Sources: R1 `BVB_MATRIX.md` (capability-level) and R5 `IMPL_BVB.md` (implementation-level), reconciled against host evidence and the derived schema. Where R1 and R5 disagreed the resolution is stated explicitly with the CONTRADICTIONS id. Licence rule: permissive only (MIT/BSD/Apache-2.0/ISC) for REUSE and STEAL_PATTERN; copyleft is a separate blocker from any technical one.

## 1. Verdict matrix

| Option | Verdict | Facts | Reconciled reasoning |
|---|---|---|---|
| **Own stdlib sysfs/procfs readers behind an unexported fs seam** | **BUILD** | F3 F4 F14 F16 F18 F19 F56 F57 | The only option that satisfies bounded, mode-gated, errno-carrying reads; privileged data is unreachable for every library anyway. R1 and R5 agree. |
| `github.com/prometheus/procfs` (DMI) | **STEAL_PATTERN** (pointer-or-nil + `os.IsPermission` branch) | F64 | R1 said "REUSE candidate", R5 said BUILD; **resolved C-33**: a large import to save ~150 LOC that still lacks bounded/mode-gated reads and errno capture. |
| `jaypipes/ghw`, `shirou/gopsutil`, `zcalusic/sysinfo` | **REJECT** (dependency) / **STEAL_PATTERN** (per-domain packages, host-id ladder, udev route, explicit-unknown sentinel) | F63 | EACCES -> untyped "unknown", syslog scraping with silent substitution, ambient `GHW_CHROOT`/`HOST_SYS` production root overrides (attack surface), `HostID()` returns "" nil, `log.Fatal` unprivileged. R1 and R5 agree. |
| `u-root/pkg/smbios`, `digitalocean/go-smbios`, `dmidecode`/`lshw`/`inxi`/`facter`/`ohai` | **REJECT** | F4 | Correct code pointed at root-only data; GPL/Ruby/absent for the exec tools. |
| `lsblk`/`lscpu`/`blkid` (exec) | **REJECT as runtime** / **STEAL_PATTERN** (map of sysfs + udev DB) | F57 | Everything they give unprivileged comes from sysfs + `/run/udev/data`, which we read directly; blkid prints nothing and exits 0 as uid 1000. `nvme list` likewise redundant (F56). |
| **`sshd -G` (bounded exec)** | **REUSE — host-confirmed** | F24 F25 F26 | R1's headline reversal, now VERIFIED on the host (`network.sshd_g_effective`, 85 directives as uid 1000). Primary in-force oracle for global policy; ceiling: no Match evaluation (`-G -C` fatals, untested on host). **Resolves C-03** against R3/R4's parse-only framing. |
| `sshd -T` | **REJECT** | F26 | Loads host keys first; exits 1 unprivileged. Record any attempt as EXECUTION_ERROR. |
| **Own Include-aware sshd_config walker (narrow)** | **BUILD (fallback + provenance)** | F27 F29 F35 | No maintained Go server-side parser exists (client parsers misapply Host semantics). Was load-bearing in R3/R4/R5; now fallback when sshd is absent or `-G` fails, and the {path,line} provenance + cross-check source. |
| `/proc/net/tcp{,6}` + `/proc/net/unix` + `systemctl show/cat ssh.socket` | **BUILD** | F30 F31 | Listener primitives; `ss -ltnp` REJECTED as evidence (blank Process column = silent omission). |
| osquery tables (`ssh_configs`, `secureboot`, `disk_encryption`, ...) | **REJECT as dependency** / **STEAL_PATTERN** (efivars byte offset, world-readable-path preference; Apache-2.0 arm) | F65 F48 | C++ daemon (CGO, not linkable); silent-omission and zero-rows behaviours are anti-patterns to cite in NOTES. |
| Lynis, Wazuh SCA, FreeIPMI (GPL) | **REJECT as code** / **STEAL** (Lynis SKIPREASON taxonomy as reason-vocabulary shape; Wazuh as cautionary example) | F65 | Copyleft blocker + `sshd -T` false FAILs. |
| XCCDF / OVAL / SARIF result models | **STEAL_PATTERN** | F66 | Nine/six-value vocabularies collapsed into our three; the loss is carried by `reason`; SARIF's default-to-fail and run-level invocation status adopted. |
| Content secret scanners (`gitleaks`, `trufflehog`, Trivy rules) | **REJECT — scope decision** (safety, not licence) | F37 F38 | gitleaks is MIT (brief myth retracted) but serialises raw secrets; trufflehog AGPL + live API verification; content scanning structurally ingests key material. Header-only classification instead. |
| **Pure-Go POSIX ACL decoder (~50 LOC over stdlib `syscall.Getxattr`)** | **BUILD** | F41 | No maintained decoder (`joshlf/go-acl` dead, `pkg/xattr` raw bytes). Byte-verified by R1 LOCAL_REPRO; needs a byte-fixture unit test (R5 gap). Retires the getfacl-absent blocker. |
| `getfacl` (exec) | **REJECT** | F41 | UTILITY_MISSING on the target; the syscall is cheaper and exec-free. |
| **BMC identity via `/sys/devices/platform/ipmi_bmc.N/*` + `readdir /sys/firmware/dmi/entries` + `/proc/devices` (`ipmidev`) + per-path stat of the three device paths** | **BUILD** | F42 F43 F44 F45 F46 | No tool found uses the sysfs identity path; ipmitool clobbers errno; Go IPMI libraries open the root-only node; osquery has no table. Out-of-band deadline mandatory (L40). |
| `ipmitool`, FreeIPMI, `u-root/pkg/ipmi`, `bougou/go-ipmi`, `vmware/goipmi`, in-band Get Device ID via ioctl, Redfish queries | **REJECT** (querying) / **BUILD** (detecting the host interface) | F46 F47 F104 | Zero-valued unprivileged; strictly dominated by the sysfs path; Redfish bootstrap creates an account (write). Contract AM-6 conflict is C-26 (lead decides). |
| **efivars 5-byte read, taint bit-table decode, `/sys/module/*/taint`, cpu/vulnerabilities enumeration, `/sys/kernel/security/{lsm,lockdown}`** | **BUILD** (patterns stolen from osquery/kernel docs as data) | F48 F49 F50 F51 | Trivial, unprivileged; `mokutil` optional cross-check; `canonical/go-efilib` and `kernel-hardening-checker` REJECTED as over-scope (provisional, unevaluated). |
| **Bounded subprocess runner** (stdlib `os/exec` + `syscall`) | **BUILD** | F21 F22 F23 | Setpgid + group-kill Cancel + WaitDelay + capped writers + deferred Wait; no library encodes the combination. |
| `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3 | **REUSE — test-time + release gate** | F69 F70 | Apache-2.0, all drafts, Bowtie 100%, one transitive (`x/text`). **R1 vs R5 on where it runs resolved C-06**: test-only import (not linked) + the lead's gate validating the real `findings.json`; the binary enforces the same constraints as stdlib invariants and never suppresses output. Reversal: a richer real schema from Lava. |
| `xeipuuv/gojsonschema`, `kaptinlin/jsonschema`, `qri-io/jsonschema`, hand-rolled validator, `omissis/go-jsonschema` codegen (as strategy) | **REJECT** | F69 F70 | Draft ceiling / 20 hard errors; silent go 1.27 bump + YAML/i18n; dormant; `$ref`/`$dynamicRef` re-implementation trap; codegen fixes the schema at compile time (optional extra only). |
| `golang.org/x/sys` | **REJECT for this deliverable** (reversal: statx, openat2 flags, netlink, second GOOS) | F71 F102 F96 | **R1 REUSE vs R5 REJECT resolved C-05** for stdlib: every needed symbol exercised from `syscall`; openat2 hardening dropped in favour of os.Root (C-24). |
| `os.Root` (Go 1.24+) | **REUSE (stdlib)** | F19 F16 | In-root symlink following + escape refusal at zero dependency; degrade to plain bounded reads if OpenRoot fails on the 6.8 kernel; IsRegular gate still mandatory. |
| `encoding/json` v1 | **REUSE (stdlib)**; `encoding/json/v2` **REJECT** | F72 | v2 is experimental and non-deterministic for maps. |
| `spf13/cobra`, `urfave/cli`, `kong` | **REJECT** | F74 | Four modules incl. YAML for one subcommand; `flag` suffices. |
| `goldie`, `cupaloy`, `testing/synctest` | **REJECT** | F75 | `-update` idiom is 10 lines; synctest is for concurrency, not timestamps; inject `now`. |
| Declarative rule engine (Wazuh/kube-bench style YAML) | **REJECT — over-engineering** | F68 | At 3-6 checks per category a DSL adds a parser and a failure mode for nothing; metadata as Go struct literals. |
| `testing/fstest.MapFS` for sysfs fixtures | **REUSE (stdlib), prove symlink support by one test** | F75 F18 | Fallback: real fixture tree with `os.Symlink` under `testdata/`. |

## 2. Recommended dependency list (reconciled)

| Module | Version | Licence | Shipped in binary? | Why |
|---|---|---|---|---|
| Go standard library (`os`, `os/exec`, `syscall`, `encoding/json`, `flag`, `io/fs`, `testing/fstest`) | Go 1.26.x (os.Root needs >= 1.24; Root.ReadFile >= 1.25) | BSD-3 | yes | Everything the sensor needs at runtime (F19, F21-F23, F71, F72, F74). |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Apache-2.0 | **no — test-only import** (+ release gate tool) | Full 2020-12 conformance validation of golden and real output (F69, F70). Pulls `golang.org/x/text` only. |

**Net third-party runtime dependencies in the shipped binary: zero.** (R1 said one — `x/sys`; R5 said one — the validator. Both reconciled away: C-05, C-06.) `go mod vendor` is still cheap insurance for an offline reviewer build (R1-OR5 answered: prebuilt static binary + source + build instructions).

## 3. Conflicts between R1 and R5, resolved
| Topic | R1 | R5 | Resolution |
|---|---|---|---|
| `golang.org/x/sys` | REUSE, shipped | REJECT | **REJECT** (C-05): stdlib symbols exercised; openat2 dropped with os.Root. |
| Schema validation | test-only import | runtime embed, write nothing on failure | **Test-time + release gate + stdlib runtime invariants; never suppress output** (C-06). |
| `prometheus/procfs` | REUSE candidate | BUILD + steal naming | **STEAL_PATTERN** (C-33). |
| `sshd -G` vs own parser | `-G` oracle pending host answer; parser anyway | BUILD narrow parser (did not evaluate `-G`) | **`-G` primary (host-confirmed), parser fallback + provenance** (C-03). |
| `lstat`-first vs fd gate | lstat mandatory, O_NONBLOCK insufficient | O_NONBLOCK open + Fstat(fd) | **fd gate with O_NONBLOCK; lstat optional** (C-23). |
| openat2 | optional hardening | os.Root | **os.Root** (C-24). |

## 4. What would be stupid to rebuild vs what is safer to own
- Do not rebuild: JSON Schema 2020-12 validation (`$ref`/`$dynamicRef`), the OpenSSH effective-config resolver where the daemon itself will print it (`sshd -G`), Go's own `os.Root` containment.
- Own it: every host read primitive, the bounded runner, the sshd fallback walker, the ACL decoder, the BMC sysfs path, the evidence model. Each is under ~100 LOC and the correctness is in the UNKNOWN semantics no library provides (F63, F65).
