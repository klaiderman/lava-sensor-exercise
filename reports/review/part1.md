# REVIEW_FINDINGS — independent review of `sensor/` (code-reviewer, Fable 5.1, 2026-09-09 ~05:10Z)

Reviewed: the working tree as of 05:01Z (test binaries cross-compiled then; `go vet` clean; probe/scan/checks/cmd
test binaries all PASS under WSL as uid 1000) plus `reports/real_host/findings.json` (26 checks, 10/11/5, exit 0),
which was produced by the pre-fix binary. During the review the author landed UNCOMMITTED edits to
`remote_access.go` (05:04), `scan/check.go` (05:04), `storage.go` (05:03), `secrets.go` (05:06) and a new
`fixbatch1_test.go` (05:08). Those edits were read, not tested; each finding says whether the live tree already
addresses it. Six adversarial fixtures of my own were run under WSL (uid 1000) from a scratch copy of the module
(`reports/review/sensorcopy`, never `sensor/`); results are in the Adversarial fixtures section.

## Findings (ranked)

### C1 - CRITICAL - SSH_POLICY_IN_FORCE reports FAIL on the real host from a sub-second precision artefact
- `sensor/internal/checks/remote_access.go` (05:01 tree, lines 291-303): `delta := started.Sub(newest); if newest.After(started) -> Fail`.
  `started` comes from `systemctl show -p ActiveEnterTimestamp` (whole seconds); `newest` is an lstat mtime (nanoseconds).
- Real host: newest_config_mtime = 2026-09-08T17:37:29Z, service_active_enter = 2026-09-08T17:37:29Z, delta_seconds = 0,
  detail "modified 0s after ActiveEnterTimestamp ... the running daemon is enforcing something other than what is on disk".
  The evidence carries no ordering; the verdict asserts one. Registry 5.3 predicted pass. Sensor bug, not a host fact.
- Violates L41 (an ordering derived from two instruments of different resolution) and the evidence-supports-verdict rule:
  a false fail (medium) on a healthy machine.
- Live tree: ADDRESSED - `serviceStartTime()` uses `*Monotonic + /proc/uptime` (100 ms resolution); a same-resolution delta
  yields unknown / TIMESTAMP_RESOLUTION (new constant in scan/check.go). Not re-run here. Nit: TIMESTAMP_RESOLUTION widens
  the closed reason vocabulary (L07/L35) - record it in EVIDENCE_MODEL section 7.
- Regression test: Chtimes(sshd_config, T+0.4s) with stub ActiveEnterTimestamp = T (whole second) must not be fail.
- Consequence: `reports/real_host/findings.json` contains a false fail and must be regenerated.

### C2 - CRITICAL - PROVISIONING_DATA_PROTECTION fails every default cloud-init host
- `secrets.go` (05:01 tree) `inspect()` lines 401-433: any other-readable artifact is Adverse; the fail branch fired on
  `/run/cloud-init/instance-data.json` (0644 by cloud-init design - the redacted copy; the sensor itself recorded
  redaction_observed: true), the package-shipped `/etc/cloud/cloud.cfg.d/*.cfg` (0644 by design; no injection key names were
  found - no `injection_key_names_in_*` field was emitted), even `README`, and the 0755 `/var/lib/cloud/instances/<id>` dir.
- Registry 2.2 FAIL condition is "artifact that can carry injected credentials ... non-empty user-data, seed data, or a drop-in
  containing an ssh_authorized_keys/password/chpasswd key name"; it predicted pass on this host and lists instance-data.json
  0644 self-redacting as acceptable. L24 (the software's own documented permission rule) violated.
- ADV-2 reproduced: default Ubuntu layout -> fail POLICY naming README. False fail (medium) on every Ubuntu cloud image.
- Live tree: ADDRESSED - payload vs public-by-design classes; drop-ins promoted only on key names. Not re-run here.
- Regression test: ADV-2 (`TestADV_Provisioning_DefaultCloudInitLayoutIsNotAFail`) verbatim.

### H1 - HIGH - PRIVATE_KEY_MATERIAL_EXPOSURE passes while a scan root (/root) was unreadable
- `probe/walk.go:46` `Complete()` = BudgetExhausted=="none" && Errno=="" - it ignores UnreadableDirs. `secrets.go:163` relies
  on it, so the /root walk (entries_scanned: 1, unreadable_dirs: ["/root"]) counts as complete and the detail says "every
  enumeration completed". Real host: pass with /root and /etc/ssl/private unreadable.
- Registry 2.2 UNKNOWN condition: "a scan root is unreadable (EACCES - e.g. /root: present, contents unknown, never clean)";
  DESIGN_LAWS fixture unreadable-home-not-clean; L25. In the same category and for the same /root, CREDENTIAL_FILE_EXPOSURE
  reports unknown/EACCES - the two checks contradict each other on one fact.
- ADV-3 reproduced: a world-readable /root/.ssh/id_ed25519 behind a 0000 /root -> pass, "every enumeration completed".
- The registry's own 5.3 row says "p (scope printed)", contradicting its 2.2 rule; the sensor followed the weaker one.
- Patch (secrets.go, privateKeyMaterialExposure.Run): `if !res.Complete() || len(res.UnreadableDirs) > 0 { incomplete = true }`
  and report reason EACCES (not BUDGET_EXHAUSTED) when the cause is a denied directory; keep the walk table as the scope.
  Or add the condition to WalkResult.Complete() itself after auditing its other callers.
- Live tree: NOT addressed (live secrets.go:164 unchanged).
- Regression test: ADV-3 verbatim.
