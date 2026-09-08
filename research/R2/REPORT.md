# R2 -- Lava Public Context Report

Track R2, `r2-lava-context`. Public-surface research on lavahq.io only. See
`LAVA_CONTEXT.md` for the identity check and tagged fact buckets, `facts.jsonl` /
`sources.jsonl` for the raw evidence, `PROVENANCE.md` for method and timing, and
`CUSTOM_CATEGORY_CANDIDATES.md` for the ranked recommendation this report feeds.

## Q1 -- What is Lava? Product, positioning, target customers

lavahq.io (confirmed identical to lavalabs.io and to the GitHub org
`lava-security-research`, R2-F1) is a pre-launch security company: the homepage is
literally marked "Coming soon" and reads "Security for Enterprise Data Centers and
Neoclouds," ISO 27001 certified (R2-F2). The About page frames the team as
"infrastructure engineers and security experts... focus[ed] on the layers that are
hardest to manage, secure, and control" (R2-F3). Public content is dominated by a
security-research blog (11 posts) and a named risk-taxonomy framework, FORGE, rather
than product documentation (R2-F6).

The internal brief's specific claim -- sensors on "tens of thousands" of machines in
"isolated customer data centers, reporting to a central plane," with "no way in,
only a way out" -- is **not confirmed anywhere in the public materials reached by
this track's bounded, sitemap-complete crawl** (17 of 18 sitemap URLs; R2-F4). This
is silence, not contradiction: nothing on the public site describes a deployed sensor
fleet at all, consistent with the "Coming soon" status. What *is* publicly confirmed
is thematically identical territory -- bare-metal infrastructure, firmware/BMC trust,
data-center posture -- just not the specific fleet/central-plane/one-way-out
language. Treat the brief's exact wording as unverified from the public web and its
theme as strongly corroborated.

Target customers, per Lava's own writing, are enterprise data-center operators and
neocloud/GPU-cloud providers and their infrastructure/security leadership (R2-F14):
FORGE was "built with CISOs, neocloud experts, researchers, and infrastructure
leaders," and every research post closes with an invitation to talk aimed at
organizations that "operate data centers or AI, GPU, or bare-metal infrastructure."

## Q2 -- Public GitHub/repos, blog, talks, jobs, founders, funding/news

**GitHub:** one public org (`lava-security-research`, 2 followers) with one public
repo, `forge-framework` (20 stars, CC BY-NC-SA 4.0, Markdown + images only -- no
source code, no language/runtime signal) (R2-F10). This means Lava's public GitHub
presence tells us their risk taxonomy, not their engineering stack; it provides no
evidence for or against Go, agent frameworks, or any other implementation choice.

**Blog / research:** 11 posts spanning BMC/IPMI exposure research, neocloud security
posture, the Shared Responsibility Model, and two three-part series on firmware
integrity and runtime integrity (R2-F5, R2-F7, R2-F8, R2-F9).

**Talks:** none found within this track's time budget; not searched exhaustively
beyond WebSearch/crawl -- treat as an open item, not "confirmed absent."

**Jobs/hiring:** no careers page or external ATS link found in the bounded,
sitemap-complete crawl; the only hiring-adjacent text is the About page's "we're
scaling fast... always looking for top-tier talent" (R2-F11). This is a genuine gap
in what a hiring-stack signal (Go? agents? BMC/Redfish? storage?) could tell us --
recorded honestly rather than filled with a guess or, worse, with a different
company's job postings (see the identity-confusion contradiction below).

**Founders/engineers named publicly:** Michael Katchinskiy, Head of Security
Research; Yakir Kadkoda, CTO/co-founder -- both credited as FORGE's authors, with
named reviewers from Google, Dell, Nebius, Roblox, IBM, Intel, and Visa (R2-F6,
R2-F18). Recorded at the professional-role level only, per this track's
personal-data-collection limit.

**Funding/news:** no funding round, investor, or valuation specifically
attributable to lavahq.io was found; every "Lava funding" search result resolves to
the unrelated blockchain company "Lava Network" (R2-F13, R2-F19). Absence of
evidence is not evidence of absence for a stealth-mode company -- recorded as
genuinely unknown.

## Q3 -- The infrastructure/storage angle

Storage posture is explicitly part of Lava's stated problem space, though it is
consistently framed as one dependency among several rather than Lava's primary
angle (BMC/firmware is clearly primary; see Q1, Q5). Evidence:

- The Shared-Responsibility-Model comparison table lists "storage media
  sanitization" as a named AI-infrastructure layer alongside firmware trust and
  out-of-band management networks (R2-F9).
- The neocloud-security post asks directly: "How is shared storage isolated?"
  and states "Storage creates another dependency. A customer may receive a
  filesystem containing its datasets and checkpoints, while the actual storage
  platform underneath it is shared across a much larger environment" (R2-F9,
  source S8).
- "Hardware and device lifecycle" is explicitly defined to include "storage
  devices... reuse, decommissioning, and disposal," and the neocloud posts ask
  directly "what happens to a bare-metal machine before it moves from one
  customer to another?" (R2-F9).

No public evidence was found for RAID health, multipath, or NVMe-firmware-specific
concerns by name; the storage angle that *is* public is about **isolation and
sanitization of shared/reused storage between tenants**, not disk-level health
telemetry. Evidence and inference are kept separate per the task's instruction:
the "storage media sanitization" and "device lifecycle reuse" language is
VERIFIED_PUBLIC_FACT; the leap to "therefore Lava would want a specific NVMe-health
check" is a LIKELY_PRODUCT_IMPLICATION, not a verified claim (see
`LAVA_CONTEXT.md` and `CUSTOM_CATEGORY_CANDIDATES.md`).

## Q4 -- Likely reader of a findings.json artifact and evidence style they'd value

Likely reader: CISOs, neocloud/security-operations leadership, and infrastructure
engineers -- reasoning chain in R2-F14 (sources S1, S7, S11). This is a
LIKELY_PRODUCT_IMPLICATION built from two verified facts (FORGE's stated
co-author/reviewer audience, and every post's closing call-to-action), not a
verbatim public statement about findings.json specifically.

Evidence style that reader would value, inferred from Lava's own writing habits
(R2-F15, source S7): specific CVE IDs where applicable; numeric quantification
("36,872 hosts," "24,650 (66.9%)"); named vendors and disclosure timelines; and an
explicit statement of ethical/scope boundaries ("We did not submit the matching
passwords to the affected BMCs or use them to authenticate"). This maps directly
onto this project's own evidence-semantics rule (path read, value found, command
run, exit code/errno -- never a restatement of the title) and onto FORGE's
"Evidence & Exposure Management" pillar, defined around "provider transparency and
patch velocity" (R2-F16).

## Q5 -- Ranked custom health-check categories

See `CUSTOM_CATEGORY_CANDIDATES.md` for the full ranked list with fact-ID citations
and "why Lava would care" statements. Summary of the ranking logic: categories are
ranked by (a) how directly they trace to a VERIFIED_PUBLIC_FACT about Lava's own
published research/framework, and (b) how much differentiated, non-trivial evidence
they would actually produce on the real target host per `state/HOST_SNAPSHOT.json`
(a category that is 100% "not applicable" on this specific host is ranked lower even
if thematically on-point). This is a ranked recommendation with evidence; the lead
decides the final category, per this track's mandate.

## Anomalies encountered

No prompt-injection attempts, hidden instructions, or adversarial content were found
in any crawled page or fetched source during this track's research. All 17 crawled
pages and all WebFetch/WebSearch results returned ordinary marketing/technical/press
content with no embedded directives to this agent.

## What was left shallow, and why (time-box)

Per this track's edge-case guidance, the identity check and Questions 1 and 5 were
prioritized and are the most thoroughly evidenced sections above. Given the roughly
40-minute active-work budget, the following were given comparatively less depth and
are recorded as open rather than guessed:

- Talks/conference appearances by Lava engineers: not searched beyond the queries
  already run; open.
- A LinkedIn company page for lavahq.io itself was not fetched in full (LinkedIn
  full-profile content is login-walled per this track's constraints); only a
  same-named individual's public profile title surfaced incidentally and was not
  pursued further.
- The full Crawl4AI JS/PDF escalation path was not exercised because no page
  returned under 500 characters of useful Trafilatura text except the two
  short marketing/stat pages (homepage, bmcradar, about-lava) which were
  short by design (landing/stat-tile pages, not JS-gated content) -- escalating
  would not have produced more signal. See `PROVENANCE.md`.
