# OBSERVATION_REQUESTS -- Track R2

Per `prompts/R2/prompt.md` item 12: this track never guesses a host fact it
lacks, and never probes the host itself. This track turned out not to need any
new host observation beyond what `state/HOST_SNAPSHOT.json` already provides --
every host cross-reference used in `CUSTOM_CATEGORY_CANDIDATES.md` (BMC interface
state, Secure Boot/Setup Mode, kernel taint, sysctl hardening values, BIOS date,
kernel drift, the unused `nvme1n1` device) was already present in the host
snapshot supplied in this track's own context. No blocking or non-blocking
observation request is filed.

If, after the lead reviews `CUSTOM_CATEGORY_CANDIDATES.md`, a chosen category needs
a host fact not already in `state/HOST_SNAPSHOT.json` (for example: whether
`nvme1n1`'s discard/TRIM state or any residual signature is readable via a
specific sysfs path not yet probed), that is a question for the sensor's own
implementation-time capability probing, not for this public-research track --
this track's scope ends at recommending the category with public evidence, per
its mandate ("you recommend, you do not decide").
