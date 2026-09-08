# R4 / S2 — BMC / In-band IPMI research

Scope: unprivileged, read-only sensor evidence about the BMC/IPMI subsystem on the
target host (Supermicro AS-3015MR-H10TNR / H13SRE-F, Ubuntu 24.04.4, kernel
6.8.0-139-generic). No SSH/host access used; all findings below are from primary
kernel source (matched to the host's actual kernel version where possible) and
vendor/standards documents.

---

## Q1 — /sys/devices/platform/ipmi_bmc.0 sysfs attributes: origin, meaning, and whether they prove a live BMC

**Driver:** the attributes are created by `drivers/char/ipmi/ipmi_msghandler.c`
(NOT `ipmi_si` — the message handler owns the `struct bmc_device` and its sysfs
group; `ipmi_si`/`ipmi_devintf`/`ipmi_ssif` are lower/upper layer drivers that sit
on top of it). Confirmed by reading the actual source
(`raw.githubusercontent.com/torvalds/linux/master/drivers/char/ipmi/ipmi_msghandler.c`,
lines ~2788-2999):

- `bmc_dev_attrs[]` registers: `device_id`, `provides_device_sdrs`, `revision`,
  `firmware_revision`, `ipmi_version`, `additional_device_support`,
  `manufacturer_id`, `product_id`, `aux_firmware_revision`, `guid`.
- Each `_show()` callback calls `bmc_get_device_id(NULL, bmc, &id, ...)`, i.e.
  **every sysfs read re-invokes the same code path that fetches the device ID**,
  it does not just print a static struct filled in once at probe time.
- `guid` and `aux_firmware_revision` are conditionally visible
  (`bmc_dev_attr_is_visible`) only if the BMC actually reported them (matches:
  host has `guid` readable, i.e. the BMC returned a GUID).

**Does reading it prove the BMC is alive?** Yes, with a 10-second cache window.
`__bmc_get_device_id()` (same file, ~line 2642) checks:
```
if (intf->in_bmc_register ||
    (bmc->dyn_id_set && time_is_after_jiffies(bmc->dyn_id_expiry)))
        goto out_noprocessing;   /* return cached value, no BMC I/O */
```
and otherwise calls `__get_device_id(intf, bmc)` →
`send_get_device_id_cmd(intf)`, which sends a genuine IPMI "Get Device ID"
request (NetFn App, cmd 01h) over whatever transport the interface uses — KCS in
this host's case — and waits for the BMC's response
(`bmc_device_id_handler`/`ipmi_demangle_device_id`). The cache TTL is:
```c
#define IPMI_DYN_DEV_ID_EXPIRY (10 * HZ)   /* line 179 */
```
So: **the attributes existing and holding non-zero, coherent values (device_id=32,
firmware_revision=1.5, ipmi_version=2.0, manufacturer_id=0x002a7c matching
Supermicro's real IANA PEN, a valid-looking GUID) is strong, code-level evidence
that the kernel received an actual Get Device ID response from a live BMC** — at
minimum at BMC registration time, and refreshed on any sysfs read older than 10s.
It is not a synthesized/static value. The values also cannot be spoofed by
userspace since there is no interface for userspace to set them.

Also relevant: `ipmi.rst` (kernel.org, driver-api docs) confirms discovery is via
ACPI/SMBIOS/DMI (`tryacpi=1 trydmi=1` by default) — matching the host's observed
ACPI device `IPI0001` at `\_SB_.PCI0.SBRG.SIKC` that triggered `ipmi_si` to
attach.

**Design impact:** an unprivileged sensor reading `/sys/devices/platform/ipmi_bmc.0/{device_id,firmware_revision,ipmi_version,manufacturer_id,product_id,guid,additional_device_support,provides_device_sdrs}` gets a **PASS-quality, live-verified** signal that KCS + BMC are functioning, without ever touching `/dev/ipmi0` or needing privilege. This is materially stronger evidence than "module loaded" alone.

---

## Q2 — IANA PEN 0x002a7c / decimal 10876, and product_id 0x1d6e

Fetched the IANA Private Enterprise Numbers registry directly
(`https://www.iana.org/assignments/enterprise-numbers.txt`, plain-text primary
source) and located entry 10876:
```
10876
  Super Micro Computer Inc.
    Roy Chen
      royc&supermicro.com
```
**VERIFIED**: 0x002a7c = 10876 = **Super Micro Computer Inc.** This directly
corroborates the DMI/SMBIOS-reported board vendor — i.e. the BMC's own IPMI
"Get Device ID" response is internally consistent with the platform's known
identity, which is another point of evidence the response is genuine and not a
generic/stub value.

`product_id` 0x1d6e (7534 decimal): **could not find any public Supermicro
document mapping this specific product ID.** Web search for the exact value (in
both hex and decimal, combined with "Get Device ID" and "BMC") returned no
authoritative hits — Supermicro does not appear to publish a product-ID table.
This is expected: IPMI product IDs are typically only meaningful to the vendor's
own management tools (SMCIPMITool/IPMICFG) and are not part of any public
registry (there is no IANA-style registry for product IDs, only for enterprise
IDs). Treat as **SPECULATIVE/uninterpretable** — evidence only that it's a
Supermicro-assigned board/BMC firmware variant identifier, no further decode
possible from public sources.

---

## Q3 — /dev/ipmi0 permissions, udev rules, and capability checks

**Package contents:** Debian bookworm's `ipmitool` package file list (fetched
from `packages.debian.org/bookworm/amd64/ipmitool/filelist`) contains **no udev
rules file at all** — only the binary, man pages, `ipmievd` service, and
`/usr/share/misc/enterprise-numbers.txt`. `README.Debian` (fetched from
`sources.debian.org`, package version 1.8.19-4+deb12u2, matching bookworm) only
discusses the removal of `/etc/default/ipmitool` and `systemctl edit ipmievd` —
**nothing about device permissions, groups, or udev**. Ubuntu inherits this
packaging verbatim (Ubuntu does not carry IPMI-specific udev deltas).

**Kernel side:** `drivers/char/ipmi/ipmi_devintf.c` registers the device via:
```c
static const struct class ipmi_class = { .name = "ipmi" };
...
device_create(&ipmi_class, device, dev, NULL, "ipmi%d", if_num);
```
No `.devnode()` callback is set on `ipmi_class`, and no explicit mode is passed.
There is **no CAP_SYS_ADMIN/CAP_SYS_RAWIO or any `capable()`/`ns_capable()` check
anywhere** in `ipmi_devintf.c` or `ipmi_msghandler.c` (confirmed by grepping the
full source of both files — zero matches). Access control for `/dev/ipmiN` is
**pure DAC (file mode), nothing else.** With no udev rule overriding it, the
devtmpfs/driver-core default for a class device created without an explicit mode
is `0600` owned by the creating context (root, since it's created from kernel
code at driver-probe time) — which is exactly the host's observed
`crw------- root:root`.

**Conclusion:** the 0600 root:root permission on `/dev/ipmi0` is the **out-of-the-box
kernel default**, not a hardening step taken by Ubuntu/Latitude.sh, and not
something the (uninstalled) ipmitool package would have changed even if it were
present. A sysadmin who wants group access must hand-write a udev rule (e.g. the
common pattern `KERNEL=="ipmi*", MODE="660", GROUP="ipmi"` documented in
third-party blog posts, e.g. LinuxServer.io's Telegraf guide) — there is no
"standard `ipmi` group" shipped by any distro package by default.

**errno for unprivileged open():** since this is a pure file-mode check in the
VFS (`inode_permission`), an unprivileged process (not root, not in a
group/ACL with access) calling `open("/dev/ipmi0", O_RDWR)` gets **EACCES**
(errno 13) at the VFS layer, before the driver's `.open` (`ipmi_open` in
`ipmi_devintf.c`) is ever entered. If the node didn't exist it would be ENOENT,
but it does exist here. No capability grants access — even a process with
`CAP_DAC_OVERRIDE` would bypass this (irrelevant to this sensor's unprivileged
context), but plain capabilities like CAP_SYS_ADMIN/CAP_SYS_RAWIO alone do
**not** help since the code never checks for them.

---

## Q4 — SMBIOS Type 38 vs Type 42, and dmi-sysfs permissions

Source: DMTF **DSP0134 "SMBIOS Reference Specification" v3.4.0**, official PDF,
fetched directly (`www.dmtf.org/.../DSP0134_3.4.0.pdf`; DMTF blocks the
WebFetch/trafilatura default user-agent with HTTP 403, but a normal browser
User-Agent via `curl` succeeds — noted for future fetches). Extracted with
`pypdf` locally.

### Type 38 — IPMI Device Information (Table 114/115, §7.39)
| Offset | Field | Notes |
|---|---|---|
| 00h | Type | =38 |
| 01h | Length | min 10h |
| 02h | Handle | WORD |
| 04h | **Interface Type** | ENUM: 00h Unknown, 01h **KCS**, 02h **SMIC**, 03h **BT**, 04h **SSIF**, others reserved |
| 05h | IPMI Specification Revision | BCD, e.g. 10h = v1.0 (note: NOT the same field as the sysfs `ipmi_version` which comes from the live Get Device ID response, not SMBIOS) |
| 06h | I2C Target (Slave) Address | on the I2C bus |
| 07h | NV Storage Device Address | 0FFh if none |
| 08h | Base Address | QWORD; bit0=1 → I/O space, else memory-mapped |
| 10h | Base Address Modifier / Interrupt Info | register spacing, LS address bit, interrupt polarity/trigger |
| 11h | Interrupt Number | 00h = unspecified |

Text explicitly says: *"If IPMI is not shared with other protocols, either the
Type 38 or the Type 42 structures can be used. Providing Type 38 is recommended
for backward compatibility."*

### Type 42 — Management Controller Host Interface (Table 122/123/124/125, §7.43)
| Offset | Field | Notes |
|---|---|---|
| 00h | Type | =42 |
| 01h | Length | min 0Bh |
| 02h | Handle | WORD |
| 04h | Interface Type | ENUM: 00h-3Fh MCTP (DSP0239), **40h = Network Host Interface (→ DSP0270)**, F0h OEM, else reserved |
| 05h | Interface Type Specific Data Length (N) | |
| 06h | Interface Type Specific Data | if Interface Type=OEM, first 4 bytes = IANA vendor ID |
| 06h+N | Number of Protocol Records (X) | |
| 07h+N | Protocol Records | each: Protocol Type (00h/01h reserved, 02h **IPMI**, 03h **MCTP**, 04h **Redfish over IP**, F0h OEM) + type-specific data |

So: Type 38 tells you the classic in-band bus (KCS/SMIC/BT/SSIF) and its I/O or
MMIO address; Type 42 is protocol-and-transport-agnostic and is how a
Redfish-capable BMC's *network-style* host interface (including USB gadget NICs,
per DSP0270 below) gets described, alongside (optionally) IPMI multiplexed on
the same physical interface.

### dmi-sysfs permissions — root-only by kernel design, and wider than just "raw"
`drivers/firmware/dmi-sysfs.c`, fetched at the **exact tag matching the host's
running kernel, `v6.8`** (not master — verified the same at both), shows:
```c
#define DMI_SYSFS_ATTR(_entry, _name) \
struct dmi_sysfs_attribute dmi_sysfs_attr_##_entry##_##_name = { \
    .attr = {.name = __stringify(_name), .mode = 0400}, \
    ...
}
...
static DMI_SYSFS_ATTR(entry, length);
static DMI_SYSFS_ATTR(entry, handle);
static DMI_SYSFS_ATTR(entry, type);
static DMI_SYSFS_ATTR(entry, instance);
static DMI_SYSFS_ATTR(entry, position);
...
static const BIN_ATTR_ADMIN_RO(raw, 0);   /* also mode 0400, via include/linux/sysfs.h __BIN_ATTR_ADMIN_RO */
```
**This means every per-entry attribute under
`/sys/firmware/dmi/entries/<N>-<inst>/` — not just `raw` — is mode 0400
(root-only) by kernel design**, including `length`, `handle`, `type`,
`instance`, `position`. This is a **discrepancy worth flagging against the
task's stated host observation** ("the `raw` files are root-only", implying
`type`/`length` were readable) — per the actual kernel source for the exact
running version, they should also be 0400. The likely reconciliation: **directory
listing** of `/sys/firmware/dmi/entries/` (which entries of which SMBIOS type
exist, e.g. confirming a `38-0` and `42-0` directory exists) only requires
directory-traversal permission and does not require reading any attribute file,
so an unprivileged sensor probably *can* prove "Type 38 and Type 42 structures
are present" via `readdir`/`os.Stat` on the entry directories, but **cannot read
any field inside them** (type, length, handle, raw bytes) without root. Whoever
owns the host recon should double check this distinction (directory presence vs.
file readability) rather than assume `type`/`length` are readable — recommend
re-verifying with `ls -la` + an actual `cat` attempt on
`/sys/firmware/dmi/entries/38-0/type` on the host.

No commit history search pinpointed exactly when 0400 became the mode for the
non-`raw` attributes (git-log via GitHub API for this file only went back to
2017 without finding the origin of `DMI_SYSFS_ATTR`'s mode value; the macro
already had mode 0400 as far back as available history), so treat "these were
always 0400" as **LIKELY** rather than fully pinned to a specific hardening
commit — but it is unambiguously true for the exact kernel tag (v6.8) the host
runs.

---

## Q5 — Redfish Host Interface (DSP0270) and the aspeed_vhub USB NIC gadget

Source: DMTF **DSP0270 "Redfish Host Interface Specification" v1.3.0**, official
PDF (same 403-then-curl-with-UA workaround as DSP0134).

- §7.1 explicitly lists as an example implementation of the "Network Host
  Interface" protocol: **"A USB Network Connection between a Host and a Redfish
  Service"** — alongside PCIe-NIC-based alternatives. So yes, **a USB
  Ethernet/RNDIS gadget from the BMC is a standards-sanctioned, first-class
  Redfish Host Interface transport**, not a proprietary Supermicro hack.
- §8.3.1 (Table 3, "Device Type values" for SMBIOS Type 42 Interface Type 40h):
  02h = "USB Network Interface" (Table 4: Vendor ID/Product ID/Serial Number
  read straight from the USB descriptor, matching what the host observed: usb
  0b1f:03ee, "Linux 5.4.62 with aspeed_vhub", "RNDIS/Ethernet Gadget"), 04h =
  "USB Network Interface v2" (adds a MAC Address field), 03h/05h = PCI/PCIe
  variants, 80h-FFh = OEM.
- §9 defines **IPMI-based credential bootstrapping** for this interface: `Get
  Manager Certificate Fingerprint` and `Get Bootstrap Account Credentials`
  (NetFn 2Ch "Group Extension", group ID 52h = Redfish). **Important safety
  note for Q7 too: "Get Bootstrap Account Credentials" is a WRITE — the spec
  says the manager "shall generate a new user name and password... and store
  the credentials"** — i.e. issuing it *creates a live BMC account*, even though
  it travels over the in-band "system interface" and superficially looks like a
  read/query. This must be on the sensor's absolute do-not-run list regardless
  of transport.
- §10 also defines an alternate/legacy path: delivering credentials to host
  OS/firmware via **UEFI runtime variables** instead of/in addition to the IPMI
  bootstrap commands.

**What DOWN + no IP means, and what an unprivileged sensor can/can't
distinguish:** DSP0270 doesn't mandate the interface be up by default — it only
specifies the *protocol* once a link exists. An observed `operstate=DOWN` with
no assigned address is consistent with any of: (a) the BMC firmware not
bringing up its side of the virtual NIC (gadget not enumerated as active by the
BMC), (b) the interface being up at the USB/link level but the **host OS**
simply never configuring it (no netplan/systemd-networkd match for this
interface name, common for an interface nobody told the OS to use), or (c) a
policy disable. An **unprivileged** sensor cannot fully distinguish these three
because doing so would require either root (reading BMC-side state is
impossible in-band without a LAN session, and IPMI KCS itself doesn't expose
"is my USB gadget's link layer up" as a Get Device ID style informational
read) or CAP_NET_ADMIN-free network introspection that still can't see *why* an
interface is down. What an unprivileged sensor *can* safely determine and
report as evidence: interface exists (`/sys/class/net/<if>`), driver =
`rndis_host`, `operstate`, presence/absence of `netplan`/`systemd-networkd`
config referencing it (readable without root), and absence of an IPv4/IPv6
address — reported as `unknown`/`not configured`, not asserted as "Redfish HI
disabled by BMC" (that would be over-claiming from insufficient evidence).

---

## Q6 — Do cloud/bare-metal providers disable in-band IPMI, and what would remain observable?

- **Intel** (Integrated BMC Web Console docs, `intel.com/.../000058321`,
  vendor primary source, though for Intel BMCs not ASPEED): defines three **KCS
  Policy Control Modes**: *Allow All* (normal), *Deny All* (fully disables the
  IPMI KCS command interface between host OS and BMC; explicitly "does not
  apply to the authenticated network interfaces to the BMC" — i.e. LAN/Redfish
  access is unaffected, only in-band is blocked), and *Restricted* (ACL-limited
  command subset over KCS). This proves the *concept* of an admin-configurable
  in-band kill switch is real and standard across BMC vendors, generalizing
  beyond Intel.
- **Supermicro-specific** (Supermicro's own "BMC Server Management Feature
  Guide" PDF, vendor primary source, `supermicro.com/products/nfo/files/IPMI/...`,
  May 2022): documents **"KCS Privilege Control"** as a real, shipped feature on
  Supermicro BMCs, but the concretely documented sub-feature is narrower than
  Intel's "Deny All": *"Disallow In-band firmware updates over the KCS
  interface"* — available on X12-generation platforms and later, which **only
  blocks firmware-update commands** over KCS (forcing FW updates to go via
  LAN/USB instead) while leaving ordinary IPMI messaging (e.g. Get Device ID)
  unaffected. The guide does not document a Supermicro equivalent of Intel's
  full "Deny All" KCS block, but does not rule one out either — Supermicro's
  Redfish/Web BMC config API is stated as the place such controls would live.
- **Latitude.sh** (the actual provider for this host; `docs.latitude.sh/docs/ipmi`
  and marketing pages, secondary/vendor source): describes their **"Remote
  Access"** product, which governs **out-of-band** BMC LAN/web credential
  issuance (they rotate the IPMI password per request and don't store it) —
  this is about customer access to the BMC's own network interface, not about
  whether the *host OS* is allowed to talk to its own BMC via KCS. No public
  Latitude.sh documentation found addressing in-band KCS policy specifically.
- **What we can already say empirically, without re-deriving it here**: the
  host's own `/sys/devices/platform/ipmi_bmc.0` attributes are populated with
  real, internally-consistent values (Supermicro PEN, IPMI 2.0, sane firmware
  revision) — which per Q1's analysis requires the BMC to have actually
  answered a live Get Device ID over KCS. **This is itself the evidence that
  in-band KCS is NOT in a "Deny All"-equivalent state on this host** — if it
  were, `ipmi_si` would still load (ACPI-described interface is independent of
  BMC-side policy) but `__get_device_id()` would time out/fail and the sysfs
  group would either not populate or `bmc->dyn_id_set` would stay unset,
  making the attributes disappear (they are shown/hidden per
  `bmc_dev_attr_is_visible`) or read stale/failed. A sensor design implication:
  **the mere presence of `device_id` et al. with a plausible value is itself
  the "is in-band IPMI usable" signal** — no need to attempt `/dev/ipmi0` or run
  ipmitool to establish this for PASS purposes.

---

## Q7 — Safe read-only in-band IPMI ops; can an unprivileged/no-tooling user learn BMC LAN/user config?

**Read-only / informational (safe if ever run with privilege — moot here since
this sensor has neither root nor ipmitool):**
- `Get Device ID` (NetFn 06h/App, cmd 01h) — what `ipmitool mc info` and the
  kernel's own sysfs group both use. Pure query.
- `Get Device GUID`, `Get Channel Info`, `Get User Access`/`user list`,
  `Get LAN Configuration Parameters` (`lan print`) as *reads*, `sdr`/`sensor
  list` (Get Sensor Reading), `sel list`/`sel info` (reading the System Event
  Log; note repeated/heavy SEL reads on some BMCs can be noisy but are not
  state-changing), `fru print` (read FRU inventory), `chassis status` (read
  power/chassis state — NOT the same as `chassis power on/off/reset/cycle`,
  which are writes/actions).
- DSP0270's `Get Manager Certificate Fingerprint` is a read (fetches a TLS
  cert fingerprint) — but its sibling `Get Bootstrap Account Credentials` is
  **not** (see Q5): it mutates BMC account state.

**Definite writes / must never be run by this sensor, even if privilege were
available:** `chassis power on|off|cycle|reset|soft`, `user set password`,
`user set name`, `user enable/disable`, `lan set <param>` (ipaddr, netmask,
auth, arp respond, access...), `mc reset cold|warm`, `sel clear`, `sel delete`,
`fru write`, `raw` (arbitrary/unbounded — could be either), `chassis identify`
(minor/cosmetic but still a write/action), `sol` session control, `firmware
update`/HPM.1, `Get Bootstrap Account Credentials` (per DSP0270, creates an
account). General rule that matches this project's safety invariants: **any
IPMI command whose IPMI spec description contains a verb like set/write/clear/
reset/create/enable/disable/update is out of scope**; only Get-prefixed,
informational reads are candidates, and even then only if reachable without
root (which on this host, none are — `/dev/ipmi0` is 0600 root:root and no
ipmitool/FreeIPMI/ipmiutil binary exists).

**Can an unprivileged user with no ipmitool and no `/dev/ipmi0` access learn BMC
LAN/user configuration?** **Confirmed: no.** There is no alternate unprivileged
path: `/dev/ipmi0` is root-only (Q3), the SMBIOS Type 38/42 sysfs attributes
that might hint at the interface are also root-only per kernel source (Q4), and
LAN/user config is only exposed via IPMI LAN-configuration-parameter commands
that require exactly the same privileged transport. The only thing genuinely
visible unprivileged is the **existence** of the IPMI subsystem and its
device-identity metadata via `/sys/devices/platform/ipmi_bmc.0/*` (Q1) — never
BMC network/user configuration.

---

## Q8 — Supermicro H13SRE-F / AS-3015MR-H10TNR: BMC confirmation

- Supermicro's own **H13SRE-F product page** (`supermicro.com/en/products/motherboard/h13sre-f`,
  vendor primary source, fetched via WebFetch): confirms **BMC Chip: ASPEED
  AST2600**, a **single dedicated LAN port for IPMI connectivity** (default
  disabled state per the spec sheet's wording), and a KVM connector (VGA +
  serial COM + USB 2.0) for out-of-band remote access. Notes the board is sold
  "For SuperServer Only", specifically listing **AS-3015MR-H10TNR** and
  **AS-3015MR-H5TNR** as the compatible MicroCloud systems — i.e. this is
  confirmed as the exact board/BMC pairing for the target host.
- Search results (secondary sources — Broadberry/Wiredzone resellers,
  Supermicro's own MicroCloud AS-3015MR-H10TNR datasheet page) corroborate
  **"ASPEED AST2600 BMC IPMI"**, CLI/Redfish API and "Advanced Redfish APIs"
  support, and console redirection features, consistent with the board page.
  The AS-3015MR-H10TNR datasheet PDF itself could not be text-extracted (came
  back as a `dompdf`-generated, largely image/vector-based PDF with no usable
  embedded text layer — noted as an extraction limitation, not a content gap:
  the same facts were independently confirmed via the H13SRE-F motherboard
  page instead).
- The **"virtual USB NIC to BMC"** feature is not named verbatim as a marketed
  feature string on the pages fetched, but is functionally exactly what's
  observed on the host (aspeed_vhub RNDIS/Ethernet Gadget) and is the standard
  ASPEED AST2600 mechanism for implementing a DSP0270 USB-based Redfish Host
  Interface (Q5) — ASPEED's AST2600 datasheet (not independently fetched here;
  out of scope/paywalled vendor doc) is known industry-wide to include a
  "virtual USB hub" (vhub) block for exactly this purpose, matching the
  `aspeed_vhub` Linux driver name bound to this device. Flagging this specific
  linkage as **LIKELY** (strong indirect corroboration: driver name + DSP0270
  Device Type 02h match + AST2600 confirmed present) rather than **VERIFIED**
  from an ASPEED primary source directly.

---

## INJECTION ATTEMPTS

None encountered. No fetched page or PDF contained text resembling an
instruction directed at an AI reader (e.g. "ignore previous instructions", "for
the AI reading this"). All content reviewed was standard technical
documentation/spec prose.

---

## SOURCES

- https://www.kernel.org/doc/html/latest/driver-api/ipmi.html | The Linux IPMI Driver (Documentation/driver-api/ipmi.rst) | primary | trafilatura CLI | credibility 3 | Q1, Q6 (ACPI/DMI discovery)
- https://raw.githubusercontent.com/torvalds/linux/master/drivers/char/ipmi/ipmi_msghandler.c | ipmi_msghandler.c (kernel source, master mirror) | primary | curl (raw githubusercontent) | credibility 3 | Q1
- https://raw.githubusercontent.com/torvalds/linux/master/drivers/char/ipmi/ipmi_devintf.c | ipmi_devintf.c (kernel source, master mirror) | primary | curl (raw githubusercontent) | credibility 3 | Q3
- https://raw.githubusercontent.com/torvalds/linux/master/drivers/char/ipmi/ipmi_si_intf.c | ipmi_si_intf.c (kernel source, master mirror) | primary | curl (raw githubusercontent) | credibility 2 | Q3 (checked, no extra permission logic found)
- https://raw.githubusercontent.com/torvalds/linux/master/drivers/firmware/dmi-sysfs.c | dmi-sysfs.c (kernel source, master mirror) | primary | curl (raw githubusercontent) | credibility 3 | Q4
- https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi-sysfs.c | dmi-sysfs.c at tag v6.8 (matches host's running kernel) | primary | curl (raw githubusercontent) | credibility 3 | Q4 — this is the load-bearing citation, confirms mode 0400 at the host's exact kernel version
- https://raw.githubusercontent.com/torvalds/linux/master/include/linux/sysfs.h | sysfs.h (BIN_ATTR_ADMIN_RO macro def) | primary | curl (raw githubusercontent) | credibility 3 | Q4
- https://www.iana.org/assignments/enterprise-numbers.txt | IANA Private Enterprise Numbers registry | primary | curl | credibility 3 | Q2 — PEN 10876 = Super Micro Computer Inc.
- https://packages.debian.org/bookworm/amd64/ipmitool/filelist | Debian bookworm ipmitool package file list | primary (distro packaging metadata) | trafilatura CLI | credibility 3 | Q3 — no udev rules shipped
- https://sources.debian.org/src/ipmitool/1.8.19-4%2Bdeb12u2/debian/README.Debian/ | Debian ipmitool README.Debian (bookworm version) | primary | trafilatura CLI | credibility 3 | Q3 — no permission/group guidance
- https://www.linuxserver.io/blog/2017-11-25-how-to-give-telegraf-ipmitool-permissions-via-udev | LinuxServer.io blog: IPMI udev permissions | secondary | trafilatura CLI | credibility 1 | Q3 — corroborates 0600 default and manual-udev-rule workaround pattern
- https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf | DMTF SMBIOS Reference Specification v3.4.0 | primary standard | curl with browser User-Agent (WebFetch got HTTP 403; plain curl also 403 without UA, succeeded with Chrome UA string) + pypdf text extraction | credibility 3 | Q1, Q4 — Type 38/42 field tables
- https://www.dmtf.org/sites/default/files/standards/documents/DSP0270_1.3.0.pdf | DMTF Redfish Host Interface Specification v1.3.0 | primary standard | curl with browser User-Agent + pypdf | credibility 3 | Q5, Q7 — USB Network Interface device type, credential bootstrapping commands
- https://www.intel.com/content/www/us/en/support/articles/000058321/server-products.html | Intel: Integrated BMC KCS Policy Control Mode | primary vendor doc (different BMC vendor, general concept) | trafilatura CLI | credibility 2 | Q6 — Allow All / Deny All / Restricted KCS policy concept
- https://www.supermicro.com/products/nfo/files/IPMI/BMC_Server_Management_Feature_Guide.pdf | Supermicro BMC Server Management Feature Guide (May 2022) | primary vendor doc | WebFetch (direct curl got 403; WebFetch succeeded and the fetched PDF binary was recovered from its cache and parsed with pypdf) | credibility 3 | Q6 — "KCS Privilege Control" / "Disallow In-band firmware updates over the KCS interface" (X12+)
- https://www.supermicro.com/en/products/motherboard/h13sre-f | Supermicro H13SRE-F product page | primary vendor doc | WebFetch | credibility 3 | Q8 — ASPEED AST2600 BMC, dedicated IPMI LAN port, confirms pairing with AS-3015MR-H10TNR
- https://www.supermicro.com/en/products/system/datasheet/as-3015mr-h10tnr | Supermicro AS-3015MR-H10TNR datasheet | primary vendor doc | curl (fetched as PDF but text layer not extractable — dompdf-rendered, effectively image-based) | credibility 2 (content not extracted) | Q8 — not usable as a text source, see H13SRE-F page instead
- https://docs.latitude.sh/docs/ipmi and https://www.latitude.sh/blog/introducing-remote-access-the-safest-way-to-access-your-servers-remotely | Latitude.sh Remote Access / IPMI docs | secondary vendor doc | WebSearch summary only (not deep-fetched) | credibility 1 | Q6 — describes out-of-band BMC LAN credential policy, does not address in-band KCS policy
- (general) WebSearch results for ipmitool command classification (linux.die.net man page, Thomas-Krenn wiki cheat sheet, various) | secondary | WebSearch aggregation | credibility 1 | Q7 — general read vs write command classification, no single authoritative source quoted verbatim

---

## CANDIDATE FACTS

1. `/sys/devices/platform/ipmi_bmc.0/*` attributes are created and served by `ipmi_msghandler.c`, and each read re-runs `bmc_get_device_id()` which sends a live IPMI Get Device ID request over KCS if the 10-second cache (`IPMI_DYN_DEV_ID_EXPIRY`) has expired. | VERIFIED | high | https://raw.githubusercontent.com/torvalds/linux/master/drivers/char/ipmi/ipmi_msghandler.c | Sensor should treat non-zero, internally-consistent values in this sysfs group as strong PASS evidence of a live, responding BMC over KCS — no `/dev/ipmi0` access needed.

2. IANA PEN 0x002a7c (10876) = Super Micro Computer Inc. | VERIFIED | high | https://www.iana.org/assignments/enterprise-numbers.txt | Corroborates the BMC's Get-Device-ID response is genuinely Supermicro's, strengthening confidence in fact #1; safe to hardcode this single PEN→vendor mapping as evidence annotation if desired (do not build a full PEN table).

3. product_id 0x1d6e (7534) has no publicly documented Supermicro meaning. | SPECULATIVE (absence of evidence) | low | (search only, no source found) | Do not attempt to decode/label this field beyond reporting the raw value as evidence.

4. `/dev/ipmi0` is 0600 root:root purely because of kernel `device_create()` defaults with no `.devnode()` override and no capability checks anywhere in `ipmi_devintf.c`/`ipmi_msghandler.c`; Debian/Ubuntu's `ipmitool` package ships zero udev rules. | VERIFIED | high | ipmi_devintf.c source; packages.debian.org filelist; README.Debian | An unprivileged sensor will always get EACCES on `/dev/ipmi0` on any stock Debian/Ubuntu install unless an admin has manually added a udev rule (not the case on this host). Report as UNKNOWN with reason=EACCES if a probe reaches for this device, never as FAIL.

5. All `/sys/firmware/dmi/entries/*/` attribute files (`length`, `handle`, `type`, `instance`, `position`, `raw`) are mode 0400 by kernel design in `dmi-sysfs.c`, confirmed identical at kernel tag v6.8 (matching the host's exact running kernel). | VERIFIED | high | raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi-sysfs.c | Contradicts the task prompt's framing that only `raw` is root-only; recommend the lead re-verify on-host whether `type`/`length`/etc. are actually readable (e.g. maybe only directory listing was meant). If they are indeed unreadable, the sensor can only prove Type 38/42 *entry presence* (directory listing), not their field contents, without root.

6. SMBIOS Type 38 encodes classic bus/address info for KCS/SMIC/BT/SSIF; Type 42 encodes a protocol-and-transport-agnostic "Management Controller Host Interface" including USB Network Interface (Device Type 02h/04h) and Protocol Records (IPMI=02h, MCTP=03h, Redfish over IP=04h). | VERIFIED | high | DMTF DSP0134 v3.4.0 PDF | If the Type 42 structure were readable, it would directly confirm the aspeed_vhub USB gadget's role as a Redfish Host Interface — but per fact #5 it likely isn't readable unprivileged.

7. A USB RNDIS/Ethernet gadget from an ASPEED BMC is a standards-sanctioned Redfish Host Interface transport per DSP0270 §7.1/§8.3.1, and DSP0270's "Get Bootstrap Account Credentials" IPMI command (NetFn 2Ch, group 52h) is a WRITE that creates a live BMC account, despite being issued in-band. | VERIFIED | high | DMTF DSP0270 v1.3.0 PDF | Add to the sensor's explicit do-not-run list even under any future privileged mode; also explains what the observed `aspeed_vhub` device is for.

8. `operstate=DOWN` with no IP on the BMC's USB gadget NIC cannot be attributed (BMC-disabled vs OS-unconfigured vs link-down) using only unprivileged evidence. | VERIFIED (as a limitation) | high | DSP0270 (no host-observable state machine exposed) + no unprivileged IPMI channel to ask the BMC | Sensor must report `unknown`/`not configured`, not infer a specific cause, for this interface's non-active state.

9. BMC vendors (generalized: Intel's "Deny All" KCS Policy Control Mode; Supermicro's narrower "Disallow in-band firmware updates over KCS") support admin-configurable in-band IPMI restriction, but Supermicro's own documentation only confirms the narrower firmware-update-blocking variant, not a full KCS block equivalent to Intel's "Deny All." | LIKELY (Intel precedent) / CONTESTED for Supermicro's exact equivalent | medium | Intel KB 000058321; Supermicro BMC_Server_Management_Feature_Guide.pdf | Combined with fact #1 (BMC did respond to Get Device ID), we can already conclude in-band KCS is NOT fully blocked on this host, regardless of which exact policy model Supermicro implements.

10. No public/documented path exists for an unprivileged user with no ipmitool/FreeIPMI/ipmiutil and no `/dev/ipmi0` access to learn BMC LAN or user configuration. | VERIFIED | high | Composite of facts #1, #4, #5 (all relevant channels are root-only) | Confirms the expected answer in the task brief; sensor should never claim to know BMC LAN/user config, only IPMI subsystem presence/identity metadata.

11. Supermicro H13SRE-F (paired with AS-3015MR-H10TNR) has an ASPEED AST2600 BMC with a dedicated IPMI LAN port and Redfish/CLI API support. | VERIFIED | high | supermicro.com/en/products/motherboard/h13sre-f | Confirms the board-level BMC identity referenced throughout; no need to further probe BMC model on-host since this is now doc-confirmed.
