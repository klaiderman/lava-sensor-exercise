# Lava Public Context

## Identity check

CONFIRMED (VERIFIED_PUBLIC_FACT, R2-F1): `lavahq.io` and `lavalabs.io` are the same
entity. `https://lavalabs.io/` returns an HTTP 301 redirect to `https://lavahq.io/`,
and the GitHub organization `lava-security-research` lists its website as
`https://lavahq.io` and its contact address as `research@lavalabs.io`. Both domains
may be treated as one company for the purposes of this brief.

**Same-named-company risk is real and was actively triggered.** A plain WebSearch for
"lavahq.io careers jobs" returned marketing copy for a *different* company also
called "Lava" -- an AI-payments/monetization platform (products "Build" and
"Gateway", careers portal at `lava.breezy.hr`, a reported $5.8M raised) that shares
no confirmed link to lavahq.io (R2-F12). Separately, "Lava Network" (blockchain RPC
infrastructure, ~$27M raised, founders Yair Cleper and Gil Binder) is a third,
well-documented, unrelated company (R2-F13, R2-F19). "Lava International" (Indian
phone manufacturer), "Lavastorm Analytics", "Lavaan" (R package), "LAVA VC", "LAVA
Technology Services", and "LAVA Laboratory for Visionary Architecture" round out the
name-collision field. None of these entities' facts appear anywhere else in this
brief as if they were lavahq.io facts -- each was checked against the confirmed
identity anchor (R2-F1: the lavalabs.io redirect + GitHub org website field) before
being kept or discarded.

**What lavahq.io actually is, confirmed:** a pre-launch ("Coming soon") security
company positioned as "Security for Enterprise Data Centers and Neoclouds," ISO
27001 certified, publishing a security-research blog and a named risk framework
(FORGE) rather than a publicly documented sensor product (R2-F2, R2-F3, R2-F6).

**What the internal brief claims that public materials do NOT confirm:** the bounded,
sitemap-complete crawl of all 17 reachable lavahq.io pages contains no occurrence of
"tens of thousands," "central plane," or "no way in, only a way out" (R2-F4). This is
neither a contradiction nor a confirmation -- it is silence. The brief's framing may
be internal/unreleased product language, forward-looking roadmap, or paraphrase from
a channel outside this track's public-web scope. Treat the brief's literal wording as
un-sourced from the public web; treat its *thematic* content (data-center posture,
bare-metal, "layers hardest to manage, secure, and control") as strongly consistent
with everything Lava does say publicly.

## VERIFIED_PUBLIC_FACT

- lavahq.io = lavalabs.io = GitHub org `lava-security-research`, confirmed via
  redirect + org metadata. (R2-F1, sources: S1, S18, S20)
- Homepage: "Coming soon" / "Security for Enterprise Data Centers and Neoclouds" /
  ISO 27001 Certified. (R2-F2, sources: S1)
- About page: "Lava is built by infrastructure engineers and security experts...
  We focus on the layers that are hardest to manage, secure, and control." (R2-F3,
  sources: S2)
- Flagship research: 36,872 internet-exposed IPMI/BMC hosts found on UDP/623;
  24,650 (66.9%) leaked password-derived RAKP hashes pre-login via CVE-2013-4786;
  independently corroborated by CSOonline (2026-07-28). (R2-F5, sources: S3, S4, S7,
  S21, S22, S23)
- FORGE framework: five pillars -- Fleet Integrity, Operations & Management Planes,
  Resource Isolation, Grid, Evidence & Exposure Management -- authored by Michael
  Katchinskiy (Head of Security Research) and Yakir Kadkoda (CTO/co-founder),
  reviewed by named experts from Google, Dell, Nebius, Roblox, IBM, Intel, Visa.
  (R2-F6, sources: S11, S19)
- Three-part firmware-integrity series (chain of trust, SPDM/CoRIM attestation,
  firmware rootkits) and three-part runtime-integrity series (kernel rootkits, eBPF
  backdoors, LD_PRELOAD implants, lockdown/hardening mitigations). (R2-F7, R2-F8,
  sources: S12-S17)
- Neocloud/shared-responsibility writing explicitly names storage-media
  sanitization, hardware/device lifecycle reuse, and "what happens to a bare-metal
  machine before it moves from one customer to another" as customer-relevant
  concerns. (R2-F9, sources: S6, S8, S9, S10)
- Only public GitHub repo (`forge-framework`) is Markdown+images only -- no code, no
  language/stack signal. (R2-F10, sources: S18, S19)
- No careers/jobs page found in the bounded, sitemap-complete crawl. (R2-F11,
  sources: S2, S28)

## LIKELY_PRODUCT_IMPLICATION

- Likely reader of a findings.json-shaped artifact: CISOs, neocloud/security
  operations leadership, and infrastructure engineers -- reasoning chain: FORGE was
  "built with CISOs, neocloud experts, researchers, and infrastructure leaders"
  (R2-F14) and every research post closes with an explicit call to data-center/GPU/
  bare-metal operators, not developers. (R2-F14, sources: S1, S7, S11)
- That reader values concrete, boundary-explicit evidence over qualitative claims:
  Lava's own writing cites specific CVE IDs, quantifies findings numerically, names
  vendors/timelines, and explicitly states what was *not* done (no auth attempted).
  (R2-F15, sources: S7)
- FORGE's "Evidence & Exposure Management" pillar is defined around "provider
  transparency and patch velocity" -- a firmware/kernel staleness-and-patch-velocity
  check would land as on-thesis for Lava's own stated framework, not merely
  generically useful. (R2-F16, sources: S19)
- A BMC/IPMI exposure-and-hardening check would resonate strongest with Lava's own
  publicized identity, since it is literally Lava's flagship research result.
  (R2-F5, sources: S3, S7)

## SPECULATION

- Whether lavahq.io has raised institutional funding is unknown; no financing
  event was found anywhere in public search results specifically attributable to
  it (as opposed to the unrelated, well-documented "Lava Network" blockchain
  company). What would confirm/deny: a funding-specific press release, Crunchbase/
  Tracxn entry naming Michael Katchinskiy or Yakir Kadkoda, or a future non-stealth
  product launch page. (R2-F19)
- Whether Lava is actively hiring for a Go/agent-runtime/BMC-Redfish-skilled role is
  unknown; the About page's "always looking for top-tier talent" line is present but
  no job listing or external ATS link was reachable within the crawl bounds. What
  would confirm/deny: discovery of a careers subpage or ATS link outside the 17-page
  crawl, or a LinkedIn/job-board posting explicitly attributed to lavahq.io (not yet
  searched beyond the bounds of this track's time budget). (R2-F11)

## Contradictions found

- **Marketing vs. hiring/docs:** insufficient evidence either way. No job postings
  or technical hiring documentation attributable to lavahq.io were found within the
  crawl or search bounds of this track, so the marketing claim "we're scaling fast"
  cannot be checked against day-to-day hiring reality. This is a gap, not a
  contradiction -- recorded honestly rather than resolved by guessing. (R2-F11)
- **Identity confusion risk:** real and triggered mid-research. A generic careers
  search surfaced a same-named-but-distinct AI-payments company (R2-F12); a
  funding search surfaced a same-named-but-distinct blockchain company (R2-F13,
  R2-F19). Both were caught against the R2-F1 identity anchor (the lavalabs.io
  redirect + GitHub org metadata) before being written into any fact, and neither
  appears elsewhere in this brief as if it were a lavahq.io fact.
