# Gap-filler findings (Crawl4AI-based) — OR-OPEN-4 / OR-OPEN-5

Worker: `gap-filler-crawl4ai`. Extraction engine: Crawl4AI 0.9.3 (PDF + browser/Playwright strategies) per
assignment; Trafilatura was available as fallback but not needed — Crawl4AI succeeded on every source once the
correct fetch path was used (see PROVENANCE.md for the two engineering detours: PDF anti-bot block, Windows
`file://` URL bug).

All facts are `status: VERIFIED | LIKELY | SPECULATIVE | UNKNOWN`. UNKNOWN = looked, not found in the sources
we could reach in the time box, not "doesn't exist."

---

## Gap 1 — Micron 7450 PRO SED / Opal SKU distinction (OR-OPEN-5, R3-F58)

### Fact 1 — SED and non-SED are separate SKUs under the SAME base part number [VERIFIED]
Micron's own 7450 SSD Part Catalog (internal doc, but served unauthenticated from `assets.micron.com`) lists,
for "U.3 15mm PRO", capacity 960 GB, two rows sharing the identical base MPN `MTFDKCC960TFR`, distinguished only
by the ordering suffix after the dash:

> "960 Non-SED MTFDKCC960TFR-1BC1ZABYY" / "SED TCG Opal 2.0 MTFDKCC960TFR-1BC15ABYY"

The Technical Product Specification's part-numbering diagram confirms the suffix character that carries this
distinction ("Extended Firmware Features"):

> "D = OCP 1.0a + SED Opal 2.01 ... Z = Non-SED ... 5 = SED Opal 2.01"

### Fact 2 — The base MPN alone (no suffix) cannot distinguish SED from non-SED [VERIFIED]
Because both rows above share the exact string `MTFDKCC960TFR`, the base MPN is not diagnostic by itself — the
security-feature code lives only in the trailing suffix (`-1BC1ZABYY` vs `-1BC15ABYY`), which is a
marking/ordering code, not something exposed by the drive's own identify data.

### Fact 3 — The host's captured model string is the base MPN, without the suffix [VERIFIED, from HOST_SNAPSHOT.json]
`state/HOST_SNAPSHOT.json` records `"model": "Micron_7450_MTFDKCC960TFR"` for both NVMe namespaces (fw
`E2MU200`) — i.e. exactly the base MPN from Fact 1, with no visible suffix. Combining Facts 1–3:

**Conclusion: SED/Opal capability is NOT determinable from the model string `MTFDKCC960TFR` alone. It is
architecturally ambiguous — Micron genuinely ships both a non-SED and a TCG Opal 2.01 SED variant under this
exact base model number, and the NVMe-reported model field does not carry the disambiguating suffix.** This
confirms (does not merely re-state) the existing UNKNOWN in R3-F58 — it is a real vendor-side ambiguity, not a
probing gap on our side. (The only way to resolve it on the live host would be a TCG Opal `LEVEL0_DISCOVERY` /
Security Protocol NVMe admin command query, or reading a physical label — both out of scope for a read-only,
unprivileged sensor, and the latter isn't even remotely accessible.)

### Fact 4 — Host drive matches the "7450 PRO, U.3 15mm, 960GB" catalog line [VERIFIED]
The catalog's "U.3 15mm PRO" section is the only place `MTFDKCC960TFR` appears, confirming the earlier
brief-only assumption that form factor is U.3/2.5in and confirming PRO (not MAX) endurance tier for this host
drive.

### Sources used (Gap 1)
| # | URL | Type | Extractor |
|---|-----|------|-----------|
| 1 | assets.micron.com .../7450-nvme-ssd-product-brief.pdf | PDF | crawl4ai-pdf |
| 2 | assets.micron.com .../7450-product-catalog.pdf | PDF | crawl4ai-pdf |
| 3 | micron.com .../7450-nvme-ssd-tech-prod-spec.pdf | PDF | crawl4ai-pdf |
| 4 | micron.com .../part-numbering-guide/numssd.pdf | PDF | crawl4ai-pdf |

Note: source #2 (part catalog) carries an in-document "Micron Confidential" watermark despite being reachable
at an unauthenticated public URL discovered via ordinary web search; we treat its content as evidentiary for
this research question only (facts, not the document itself, are what's recorded here) and did not attempt to
access anything requiring authentication. Source #4 covers Micron's older 3xx/4xx/420/5xx SATA SSD series, not
the 7450 directly — used only as corroborating context that Micron's "digit/letter = SED" suffix convention is
long-standing, not evidence about the 7450 specifically (Facts 1–2 come from sources #1–3).

---

## Gap 2 — Latitude.sh bare-metal provider policy (OR-OPEN-4 + AM context)

### (a) In-band IPMI / `/dev/ipmi0` tenant policy [UNKNOWN — not documented]
Latitude.sh's only public documentation of "IPMI access" describes an **out-of-band, dashboard-driven Remote
Access feature** — not anything about the in-band `/dev/ipmi0` character device inside the guest OS:

> "IPMI IP addresses are always private. We require that you create a VPN session before getting the IPMI
> credentials... Every time you request your IPMI credentials, we change the IPMI password... we do not store
> IPMI passwords anywhere." (latitude.sh blog, "Introducing Remote Access", 2019, reaffirmed by the 2023
> "Remote Access without VPN" changelog)

This is BMC-web/KVM access gated behind their control plane + a customer VPN/session, which is a different
surface than the host-OS-visible `/dev/ipmi0` (KCS via `ipmi_si`) our host snapshot already shows as root-only
0600. **No source found that discusses whether Latitude intentionally leaves `/dev/ipmi0` present/root-only by
policy, or whether it's simply stock Ubuntu+kernel default behavior.** Status: UNKNOWN, not contradicted.

### (b) Default `ubuntu` user + sudo [LIKELY for "sudo granted"; UNKNOWN for "passwordless"]
Documented directly:

> "Root access is disabled by default so you first need to log in with the provided username and then sudo to
> root." (docs, "Logging into your server")

and the user-data doc's template-variable table gives `ubuntu` as the worked example for `{{ USER_DISTRO }}`.
This VERIFIES that Latitude's standard Linux deployment model is "non-root default user + sudo to root," matching
our host (`ubuntu`, groups `ubuntu sudo`). It does **not** state whether the sudoers entry is `NOPASSWD:ALL`
(a `90-cloud-init-users`-style rule) — that specific detail is UNKNOWN/not published; our host's sudoers is
unreadable to us anyway (unprivileged, by design), so this remains an assumption either way, now slightly
better supported (LIKELY, not SPECULATIVE) by the "log in as `ubuntu`, sudo to root" documented workflow, which
would be awkward for operators if a password were required on every use for a hands-off bare-metal fleet.

### (c) Kernel cmdline hardening / instant-deploy image notes [checked, NOT FOUND]
Checked docs/servers/instant-deployment, docs/servers/deploying-a-server, docs/servers/custom-images, and the
"Deploy servers in 15 seconds" changelog. All describe instant deploy purely as a **speed** feature (pre-staged
images, <10s activation, no custom disk layout/RAID support), with **no mention of kernel command-line
parameters, module blacklisting, or any security-hardening posture**:

> "Instant deployments are the fastest way to create servers on the Latitude.sh platform. Some operating
> systems can be deployed in less than 10 seconds... This feature does not support custom disk layouts."

**Conclusion: `module_blacklist=af_alg,algif_*` (or similar) is not attributable to a documented Latitude.sh
policy.** It is far more likely to be an artifact of the stock Ubuntu 24.04 cloud/server image's own kernel
cmdline defaults (Ubuntu's cloud-image kernels commonly blacklist unused crypto af_alg family modules) rather
than something Latitude adds. Status: UNKNOWN→now better characterized as "no vendor documentation found;
probably upstream Ubuntu default, not Latitude-specific" (SPECULATIVE attribution to Ubuntu, absence of Latitude
docs is VERIFIED).

### (d) Media sanitization / server hand-back procedure [BLOCKED — gated behind Trust Center]
The only self-service statement found:

> "Deleting a server permanently erases all data on its disks and cannot be undone." (docs, "Deleting a
> server")

This describes customer-initiated logical deletion, not a documented vendor sanitization *standard* (e.g. NIST
800-88 purge/clear, disk shredding, or attestation) applied when a physical server changes tenants. The
"Security at Latitude.sh" legal page is a generic ISMS policy statement and explicitly defers detailed security
control documentation to a gated Trust Center:

> "A comprehensive set of security policies are available on our Trust Center." (linking to `trust.latitude.sh`)

`trust.latitude.sh` was not fetched — it is very likely to require a login/NDA request (typical for
Vanta/Drata-style trust-center platforms) and pursuing it was out of scope for this time-boxed, no-login-wall
worker. **Status: BLOCKED (access-gated), not attempted further** — record this as BLOCKED, not UNSUPPORTED.

### Sources used (Gap 2)
| # | URL | Type | Extractor |
|---|-----|------|-----------|
| 5 | latitude.sh/blog/introducing-remote-access-... | HTML (JS) | crawl4ai-html (Playwright) |
| 6 | latitude.sh/changelog/remote-access-without-vpn-... | HTML (JS) | crawl4ai-html |
| 7 | latitude.sh/docs/servers/deleting-a-server | HTML (JS) | crawl4ai-html |
| 8 | latitude.sh/legal/security | HTML (JS) | crawl4ai-html |
| 9 | latitude.sh/docs/servers/user-data | HTML (JS) | crawl4ai-html |
| 10 | latitude.sh/docs/servers/logging-into-your-server | HTML (JS) | crawl4ai-html |
| 11 | latitude.sh/docs/servers/instant-deployment | HTML (JS) | crawl4ai-html |
| 12 | latitude.sh/docs/servers/deploying-a-server (docs.latitude.sh redirect, 301) | HTML (JS) | crawl4ai-html |
| 13 | latitude.sh/docs/servers/custom-images | HTML (JS) | crawl4ai-html |
| 14 | latitude.sh/changelog/deploy-servers-in-15-seconds-... | HTML (JS) | crawl4ai-html |
| 15 | docs.latitude.sh/docs/ssh (redirect to latitude.sh/docs/servers/ssh-keys) | HTML (JS) | crawl4ai-html |
| — | trust.latitude.sh | — | NOT FETCHED — BLOCKED (assumed access-gated), out of time-box |

Not needed: Trafilatura fallback (Crawl4AI's browser strategy handled every JS-rendered `latitude.sh`/
`docs.latitude.sh` page without issue — all were server-rendered enough that `networkidle` + markdown
generation worked on the first attempt).
