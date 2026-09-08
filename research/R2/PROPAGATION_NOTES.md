# PROPAGATION_NOTES -- Track R2

For each load-bearing fact: what breaks downstream if it turns out to be wrong or
weakened, and what should be re-checked.

- **R2-F1 (identity: lavahq.io = lavalabs.io = GitHub org lava-security-research).**
  If this is wrong, *every other fact in this brief* is potentially about the
  wrong company and must be re-verified from scratch. Re-check trigger: if
  `lavalabs.io` stops redirecting to `lavahq.io`, or if the GitHub org's listed
  website field changes. This is the single highest-leverage fact in the brief;
  it gates all others.

- **R2-F4 (brief's exact "tens of thousands / central plane / no way in" language
  is absent from the public crawl).** If a future crawl of lavahq.io (post-launch)
  *does* contain this language, R2-F4 should be re-marked from "absent in this
  snapshot" to "confirmed public" and Q1's framing in `R2_ANSWERS.md` /
  `LAVA_CONTEXT.md` should be updated from "silence" to "confirmed." Re-check
  trigger: any future re-crawl of lavahq.io, especially after the site exits
  "Coming soon" status.

- **R2-F5 (BMC/IPMI exposure research, the basis for custom-category rank #3 and a
  contributing basis for #1).** If CSOonline's corroboration is later found to be
  inaccurate or retracted, R2-F5 drops from a two-source-corroborated claim to a
  single-primary-source claim (still `LIKELY`, not `VERIFIED`) and
  `CUSTOM_CATEGORY_CANDIDATES.md` candidate #3's "flagship research" framing should
  be softened accordingly, though the underlying BMC/IPMI category recommendation
  would not change (it is independently supported by FORGE's own pillar
  definition, R2-F6).

- **R2-F6 (FORGE's five pillars).** This fact underlies candidates #1, #4, and #5
  directly, and #2 indirectly (Fleet Integrity's scope). If the FORGE README is
  revised to redefine or rename these pillars, the entire ranked-candidate list's
  "why Lava would care" reasoning should be re-derived from the updated pillar
  definitions, not patched piecemeal.

- **R2-F9 (storage-media-sanitization / device-lifecycle-reuse language).** This is
  the sole support for the "would not anticipate" storage-reuse candidate. If this
  language is removed or reworded in a future site revision, that candidate loses
  its public-evidence anchor and should be either dropped or re-justified purely
  from FORGE's "Resource Isolation" pillar (weaker support, since that pillar is
  about live multi-tenant isolation, not idle-device reuse).

- **R2-F12 / R2-F13 (identity-collision exclusions).** If either excluded company
  (the AI-payments "Lava," "Lava Network") is later found to actually be the same
  entity as lavahq.io under some corporate-structure fact not yet public (e.g., an
  acquisition), every fact currently excluded under R2-F12/R2-F13 would need to be
  re-evaluated for inclusion. No evidence found in this run suggests this, but the
  brief explicitly flags it as the kind of thing that could change the picture if
  discovered later.

- **R2-F14 / R2-F15 (reader persona and evidence-style inference).** These are
  LIKELY_PRODUCT_IMPLICATION, not VERIFIED -- they are the interpretive bridge
  between Lava's public writing and "how findings.json should read." If the lead
  weighs Q4 heavily in a decision, note that this is inference, not a direct public
  statement about findings.json consumption; re-derive from `R2_ANSWERS.md` Q4's
  full reasoning chain before treating it as settled.
